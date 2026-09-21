import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { once } from 'node:events';
import { request } from 'node:http';
import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { FilesystemBlobStore, FilesystemMetadataStore } from '../../storage-filesystem/src/index.js';
import { createArtifactServer, createContentServer, createControlServer } from '../../server/src/index.js';
import { createToken } from '../../server/src/auth.js';
import { canonicalContentUrl, createHostBinding, parseHostHeader } from '../../server/src/content-host.js';
import { artifactDigest, canonicalJson, validateManifest } from '../../spec/src/index.js';
import { publicContentUrl, remotePublish, remotePublishResult } from '../../cli/src/remote.js';
import { TOOLS } from '../../mcp/src/schemas.js';

// Origin-topology regressions. These assert HTTP reachability and Host binding,
// not browser enforcement: no markup is executed and no browser is required.
// Header expectations are written out literally rather than imported, so a change
// to the production profile helper cannot silently rewrite the expectation too.
const CSP = "sandbox; default-src 'none'; script-src 'none'; style-src 'unsafe-inline'; img-src data:; connect-src 'none'; font-src 'none'; media-src 'none'; object-src 'none'; frame-src 'none'; worker-src 'none'; form-action 'none'; frame-ancestors 'none'; base-uri 'none'";
const PROFILE_HEADERS = {
  'content-security-policy': CSP,
  'x-content-type-options': 'nosniff',
  'referrer-policy': 'no-referrer',
  'x-robots-tag': 'noindex, nofollow, noarchive',
  'cache-control': 'no-store',
  'x-frame-options': 'DENY',
  'x-dns-prefetch-control': 'off',
  'x-owa-security-profile': 'sandboxed-web-v1'
};
const FIXED_TIME = '2020-01-01T00:00:00.000Z';
const NOW = 1_700_000_000;
const SECRET = 'origin-isolation-secret-value-0123456789';
const UPLOAD_SECRET = 'origin-isolation-upload-secret-0123456789';
const BASE_DOMAIN = 'sites.exampleusercontent.invalid';
const CONTENT = Object.freeze({ baseDomain: BASE_DOMAIN, scheme: 'https' });

const digest = bytes => `sha256:${createHash('sha256').update(bytes).digest('hex')}`;

function makeArtifact(sources, { spa = false } = {}) {
  const blobs = new Map();
  const manifest = {
    specVersion: 'owa.dev/v1',
    artifactType: 'application/vnd.openwebartifact.site.v1+json',
    entrypoint: sources[0].path,
    files: sources.map(source => {
      const bytes = Buffer.from(source.text, 'utf8'), hash = digest(bytes);
      blobs.set(hash, bytes);
      return { path: source.path, digest: hash, size: bytes.length, mediaType: source.mediaType };
    }),
    access: { visibility: 'public' },
    lifecycle: { expiresAt: null },
    ...(spa ? { routing: { spaFallback: sources[0].path } } : {})
  };
  validateManifest(manifest);
  return { manifest, blobs, canonical: canonicalJson(manifest), artifactDigest: artifactDigest(manifest) };
}

const siteArtifact = (marker, options) => makeArtifact([
  { path: '/index.html', text: `<h1>${marker}</h1>`, mediaType: 'text/html' },
  { path: '/app.js', text: `console.log("${marker}");`, mediaType: 'text/javascript' },
  { path: '/data.bin', text: `${marker}-bytes`, mediaType: 'application/octet-stream' }
], options);

/** Raw HTTP with an explicit path string: never fetch/URL, which would normalize traversal. */
function raw(port, path, { method = 'GET', headers = {}, body, host } = {}) {
  const payload = body === undefined ? undefined : Buffer.from(body);
  return new Promise((resolve, reject) => {
    const req = request({
      hostname: '127.0.0.1', port, path, method, agent: false,
      headers: {
        ...(host === null ? {} : { host: host ?? `demo.${BASE_DOMAIN}` }),
        connection: 'close',
        ...(payload ? { 'content-length': String(payload.length) } : {}),
        ...headers
      }
    }, res => {
      const chunks = [];
      res.on('data', chunk => chunks.push(chunk));
      res.on('error', reject);
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks) }));
    });
    req.setTimeout(5000, () => req.destroy(new Error(`timeout ${method} ${path}`)));
    req.on('error', reject);
    req.end(payload);
  });
}

const parseBody = res => JSON.parse(res.body.toString('utf8'));

function token(capabilities, sites = ['demo'], exp = NOW + 600) {
  return createToken({ secret: SECRET, jti: 'origin-test', exp, sites, capabilities, now: () => NOW });
}
const bearer = (...args) => ({ authorization: `Bearer ${token(...args)}` });

/**
 * Start a real control listener and a real content listener on separate ports
 * over shared storage, so every assertion below is about actual origin topology
 * rather than helper-function behavior.
 */
async function withOrigins(run, { content = CONTENT, seedSites = ['demo', 'other'] } = {}) {
  const root = await mkdtemp(join(tmpdir(), 'owa-origins-'));
  const blobs = new FilesystemBlobStore(root);
  const metadata = new FilesystemMetadataStore(root);
  const listeners = [];
  const start = server => new Promise(resolve => {
    server.listen(0, '127.0.0.1', () => { listeners.push(server); resolve(server.address().port); });
  });
  try {
    const artifacts = {};
    for (const slug of seedSites) {
      const artifact = siteArtifact(slug);
      artifacts[slug] = artifact;
      for (const [hash, bytes] of artifact.blobs) await blobs.put(hash, bytes);
      const releaseId = `r_${createHash('sha256').update(slug).digest('hex').slice(0, 20)}`;
      const site = { id: `s_${digest(Buffer.from(slug)).slice(7, 27)}`, slug, activeReleaseId: releaseId, createdAt: FIXED_TIME };
      await metadata.saveSite(site);
      await metadata.saveRelease(site.id, { id: releaseId, artifactDigest: artifact.artifactDigest, createdAt: FIXED_TIME, manifest: artifact.manifest });
    }
    const controlPort = await start(createControlServer({
      blobs, metadata, uploadSecret: UPLOAD_SECRET, content, auth: { secret: SECRET, now: () => NOW }
    }));
    const contentPort = content === null ? null : await start(createContentServer({ blobs, metadata, content }));
    return await run({ root, blobs, metadata, controlPort, contentPort, artifacts });
  } finally {
    for (const server of listeners) {
      if (server.listening) await new Promise(resolve => server.close(() => resolve()));
    }
    await rm(root, { recursive: true, force: true });
  }
}

// --------------------------------------------------------------- control ---

test('control listener preserves the existing authenticated control surface', async t => {
  await withOrigins(async env => {
    const artifact = siteArtifact('demo');
    const body = JSON.stringify({ manifest: artifact.manifest, artifactDigest: artifact.artifactDigest });
    const post = (path, headers) => raw(env.controlPort, path, {
      method: 'POST', body, headers: { 'content-type': 'application/json', ...headers }
    });

    await t.test('2. accepts a correctly authenticated plan request', async () => {
      const res = await post('/v1/sites/demo/publish/plan', bearer(['plan', 'upload']));
      assert.equal(res.status, 200);
      assert.equal(parseBody(res).slug, 'demo');
    });

    await t.test('3. rejects a missing bearer with the existing exact 401 behavior', async () => {
      const res = await post('/v1/sites/demo/publish/plan');
      assert.equal(res.status, 401);
      assert.deepEqual(parseBody(res), { error: 'Authentication required', code: 'OWA_AUTH_MISSING' });
    });

    await t.test('4. preserves WWW-Authenticate and auth error semantics', async () => {
      const missing = await post('/v1/sites/demo/publish/plan');
      assert.equal(missing.headers['www-authenticate'], 'Bearer realm="owa"');
      assert.equal(missing.headers['cache-control'], 'no-store');
      const wrongSite = await post('/v1/sites/demo/publish/plan', bearer(['plan'], ['elsewhere']));
      assert.equal(wrongSite.status, 403);
      assert.equal(parseBody(wrongSite).code, 'OWA_AUTH_SITE');
      assert.equal(wrongSite.headers['www-authenticate'], undefined, '403 must not issue a challenge');
      const wrongCap = await post('/v1/sites/demo/publish/commit', bearer(['commit']));
      assert.equal(wrongCap.status, 403, 'commit still defaults to requiring activate');
      assert.equal(parseBody(wrongCap).code, 'OWA_AUTH_CAPABILITY');
      const staleToken = createToken({ secret: SECRET, jti: 'origin-test', exp: NOW - 1, sites: ['demo'], capabilities: ['plan'], now: () => NOW - 60 });
      const expired = await post('/v1/sites/demo/publish/plan', { authorization: `Bearer ${staleToken}` });
      assert.equal(parseBody(expired).code, 'OWA_AUTH_EXPIRED');
    });

    await t.test('control responses keep the full security profile and set no cookies', async () => {
      for (const res of [await post('/v1/sites/demo/publish/plan', bearer(['plan', 'upload'])), await post('/v1/sites/demo/publish/plan')]) {
        for (const [name, value] of Object.entries(PROFILE_HEADERS)) assert.equal(res.headers[name], value);
        assert.equal(res.headers['set-cookie'], undefined);
      }
    });

    await t.test('release listing still requires the read capability', async () => {
      const denied = await raw(env.controlPort, '/v1/sites/demo/releases', { headers: bearer(['plan']) });
      assert.equal(denied.status, 403);
      const allowed = await raw(env.controlPort, '/v1/sites/demo/releases', { headers: bearer(['read']) });
      assert.equal(allowed.status, 200);
      assert.equal(parseBody(allowed).site.slug, 'demo');
    });
  });
});

test('1. default control server still fails closed without auth configuration', async () => {
  const root = await mkdtemp(join(tmpdir(), 'owa-origins-failclosed-'));
  try {
    const stores = { blobs: new FilesystemBlobStore(root), metadata: new FilesystemMetadataStore(root) };
    for (const factory of [createControlServer, createArtifactServer]) {
      assert.throws(() => factory({ ...stores }), error => error.code === 'OWA_AUTH_CONFIG');
      assert.throws(() => factory({ ...stores, auth: { secret: 'too-short' } }), error => error.code === 'OWA_AUTH_CONFIG');
      // A content origin must not become an implicit way to skip control auth.
      assert.throws(() => factory({ ...stores, content: CONTENT }), error => error.code === 'OWA_AUTH_CONFIG');
    }
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

// --------------------------------------------------------------- content ---

test('content listener serves only public artifact GET/HEAD for the Host-bound site', async t => {
  await withOrigins(async env => {
    await t.test('5/6. GET and HEAD succeed with no bearer at all', async () => {
      const get = await raw(env.contentPort, '/');
      assert.equal(get.status, 200);
      assert.equal(get.body.toString('utf8'), '<h1>demo</h1>');
      const head = await raw(env.contentPort, '/', { method: 'HEAD' });
      assert.equal(head.status, 200);
      assert.equal(head.body.length, 0);
      assert.equal(head.headers['www-authenticate'], undefined, 'public content never challenges');
    });

    await t.test('7. GET/HEAD carry identical sandboxed-web-v1 headers', async () => {
      const get = await raw(env.contentPort, '/');
      const head = await raw(env.contentPort, '/', { method: 'HEAD' });
      for (const res of [get, head]) {
        for (const [name, value] of Object.entries(PROFILE_HEADERS)) assert.equal(res.headers[name], value);
        assert.equal(res.headers['content-type'], 'text/html');
        assert.equal(res.headers['content-disposition'], 'inline');
        assert.equal(res.headers.etag, `"${env.artifacts.demo.manifest.files[0].digest}"`);
      }
      assert.equal(get.headers['content-length'], head.headers['content-length'], 'GET/HEAD parity');
    });

    await t.test('25. MIME behavior is unchanged: unknown types download, known types inline', async () => {
      const binary = await raw(env.contentPort, '/data.bin');
      assert.equal(binary.headers['content-type'], 'application/octet-stream');
      assert.equal(binary.headers['content-disposition'], 'attachment');
      const script = await raw(env.contentPort, '/app.js');
      assert.equal(script.headers['content-type'], 'text/javascript');
      assert.equal(script.headers['content-disposition'], 'inline');
    });

    await t.test('35. an OWA bearer is neither required nor consumed by the content origin', async () => {
      const withBearer = await raw(env.contentPort, '/', { headers: bearer(['read']) });
      const without = await raw(env.contentPort, '/');
      assert.equal(withBearer.status, 200);
      assert.equal(without.status, 200);
      assert.deepEqual(withBearer.body, without.body, 'a bearer changes nothing on the content origin');
    });

    await t.test('content responses set no cookies of any kind', async () => {
      for (const path of ['/', '/app.js', '/missing']) {
        assert.equal((await raw(env.contentPort, path)).headers['set-cookie'], undefined);
      }
    });
  });
});

test('8-13. no control route is reachable or SPA-masked on the content listener', async t => {
  // SPA fallback would otherwise be the subtle way a control path returns 200.
  await withOrigins(async env => {
    const controlRoutes = [
      ['POST', '/v1/sites/demo/publish/plan'],
      ['POST', '/v1/sites/demo/publish/commit'],
      ['POST', '/v1/sites/demo/activate/r_11111111111111111111'],
      ['GET', '/v1/sites/demo/releases'],
      ['PUT', `/v1/uploads/sha256:${'a'.repeat(64)}?expires=${NOW + 600}&sig=${'b'.repeat(64)}&site=demo`],
      ['GET', '/health']
    ];
    for (const [method, path] of controlRoutes) {
      for (const headers of [{}, bearer(['plan', 'upload', 'commit', 'activate', 'read'])]) {
        const res = await raw(env.contentPort, path, { method, headers });
        await t.test(`${method} ${path.split('?')[0]} is not served as content`, () => {
          assert.equal(res.status, 404, 'control route must not be dispatched or SPA-filled');
          assert.deepEqual(parseBody(res), { error: 'not found' });
          assert.notEqual(res.headers['content-type'], 'text/html');
        });
      }
    }
  });

  await t.test('13. a control path is still 404 when the site defines an SPA fallback', async () => {
    const spa = siteArtifact('demo', { spa: true });
    const root = await mkdtemp(join(tmpdir(), 'owa-origins-spa-'));
    let server;
    try {
      const blobs = new FilesystemBlobStore(root), metadata = new FilesystemMetadataStore(root);
      for (const [hash, bytes] of spa.blobs) await blobs.put(hash, bytes);
      const releaseId = `r_${'2'.repeat(20)}`;
      const site = { id: `s_${digest(Buffer.from('demo')).slice(7, 27)}`, slug: 'demo', activeReleaseId: releaseId, createdAt: FIXED_TIME };
      await metadata.saveSite(site);
      await metadata.saveRelease(site.id, { id: releaseId, artifactDigest: spa.artifactDigest, createdAt: FIXED_TIME, manifest: spa.manifest });
      server = createContentServer({ blobs, metadata, content: CONTENT });
      server.listen(0, '127.0.0.1');
      await once(server, 'listening');
      const port = server.address().port;
      // An ordinary unknown path DOES get the SPA fallback; a control path must not.
      assert.equal((await raw(port, '/deep/link')).status, 200, 'SPA fallback still works for content');
      for (const path of ['/v1/sites/demo/releases', '/v1/uploads/x', '/health', '/v1']) {
        const res = await raw(port, path);
        assert.equal(res.status, 404, `${path} must not be masked by SPA fallback`);
      }
    } finally {
      if (server?.listening) await new Promise(resolve => server.close(() => resolve()));
      await rm(root, { recursive: true, force: true });
    }
  });
});

// ---------------------------------------------------------- host binding ---

test('14-21. Host is the only content site selector and is validated strictly', async t => {
  await withOrigins(async env => {
    await t.test('14. a bound Host resolves its own site', async () => {
      assert.equal((await raw(env.contentPort, '/', { host: `demo.${BASE_DOMAIN}` })).body.toString(), '<h1>demo</h1>');
      assert.equal((await raw(env.contentPort, '/', { host: `other.${BASE_DOMAIN}` })).body.toString(), '<h1>other</h1>');
    });

    await t.test('14. an explicit port in Host is normalized away', async () => {
      const res = await raw(env.contentPort, '/', { host: `demo.${BASE_DOMAIN}:8443` });
      assert.equal(res.status, 200);
      assert.equal(res.body.toString(), '<h1>demo</h1>');
    });

    await t.test('14. uppercase Host is DNS-normalized rather than treated as a new site', async () => {
      const res = await raw(env.contentPort, '/', { host: `DEMO.${BASE_DOMAIN.toUpperCase()}` });
      assert.equal(res.status, 200);
      assert.equal(res.body.toString(), '<h1>demo</h1>');
    });

    await t.test('15. an unknown or unbound Host is rejected without disclosing existence', async () => {
      for (const host of ['unbound.invalid', `nosuchsite.${BASE_DOMAIN}`, BASE_DOMAIN, `deep.nested.${BASE_DOMAIN}`, '127.0.0.1']) {
        const res = await raw(env.contentPort, '/', { host });
        assert.equal(res.status, 404, `host ${host} must not resolve`);
        assert.equal(parseBody(res).error, 'site or active release not found');
      }
    });

    await t.test('16. a malformed Host is rejected with a fixed 400 that never echoes it', async () => {
      for (const host of [`demo.${BASE_DOMAIN}/../other.${BASE_DOMAIN}`, `demo.${BASE_DOMAIN}?x=1`,
        `user@other.${BASE_DOMAIN}`, `demo.${BASE_DOMAIN}.`, `demo..${BASE_DOMAIN}`,
        `demo.${BASE_DOMAIN}:0`, `demo.${BASE_DOMAIN}:99999`, `demo.${BASE_DOMAIN}:08443`, `demo.${BASE_DOMAIN}:x`]) {
        const res = await raw(env.contentPort, '/', { host });
        assert.equal(res.status, 400, `host ${host} must be malformed`);
        assert.deepEqual(parseBody(res), { error: 'Malformed Host header', code: 'OWA_CONTENT_HOST_MALFORMED' });
        assert.ok(!res.body.toString().includes('other'), 'the received Host is never reflected');
      }
    });

    await t.test('17. a Host for site A cannot reach site B', async () => {
      const res = await raw(env.contentPort, '/', { host: `demo.${BASE_DOMAIN}` });
      assert.equal(res.body.toString(), '<h1>demo</h1>');
      assert.notEqual(res.body.toString(), '<h1>other</h1>');
    });

    await t.test('18. ?site= cannot override or widen the Host binding', async () => {
      for (const target of ['/?site=other', '/?site=demo', '/index.html?site=other', '/?site=%6f%74%68%65%72']) {
        const res = await raw(env.contentPort, target, { host: `demo.${BASE_DOMAIN}` });
        assert.equal(res.status, 200);
        assert.equal(res.body.toString(), '<h1>demo</h1>', `${target} must stay on the Host-bound site`);
      }
    });

    await t.test('19. ?site= alone selects nothing when the Host is not bound', async () => {
      for (const host of ['localhost', '127.0.0.1', 'other.invalid']) {
        const res = await raw(env.contentPort, '/?site=demo', { host });
        assert.equal(res.status, 404, 'the query selector must be inert on the content origin');
      }
    });

    await t.test('20. duplicate or comma-joined Host values are never accepted', async () => {
      for (const host of [`demo.${BASE_DOMAIN}, other.${BASE_DOMAIN}`, `demo.${BASE_DOMAIN},other.${BASE_DOMAIN}`]) {
        assert.equal((await raw(env.contentPort, '/', { host })).status, 400);
      }
      // A configuration that pins one host twice, or collides with the wildcard,
      // is rejected at construction rather than resolved ambiguously at runtime.
      assert.throws(() => createHostBinding({ hosts: { 'a.invalid': 'one', 'A.invalid': 'two' } }), error => error.code === 'OWA_AUTH_CONFIG');
      assert.throws(() => createHostBinding({ baseDomain: BASE_DOMAIN, hosts: { [`demo.${BASE_DOMAIN}`]: 'other' } }), error => error.code === 'OWA_AUTH_CONFIG');
    });

    await t.test('21. forwarded host headers never override the direct Host', async () => {
      for (const headers of [
        { 'x-forwarded-host': `other.${BASE_DOMAIN}` },
        { forwarded: `host=other.${BASE_DOMAIN}` },
        { 'x-forwarded-server': `other.${BASE_DOMAIN}` },
        { 'x-original-host': `other.${BASE_DOMAIN}` }
      ]) {
        const res = await raw(env.contentPort, '/', { host: `demo.${BASE_DOMAIN}`, headers });
        assert.equal(res.status, 200);
        assert.equal(res.body.toString(), '<h1>demo</h1>', 'only the direct Host may select a site');
      }
      // A forwarded header must not rescue an unbound direct Host either.
      const spoof = await raw(env.contentPort, '/', { host: 'unbound.invalid', headers: { 'x-forwarded-host': `demo.${BASE_DOMAIN}` } });
      assert.equal(spoof.status, 404);
    });

    await t.test('a missing Host header cannot select a site', async () => {
      const res = await raw(env.contentPort, '/', { host: null });
      assert.ok(res.status === 400 || res.status === 404, `expected rejection, got ${res.status}`);
    });
  });
});

test('Host parsing rejects confusable authority spellings before any lookup', () => {
  for (const value of ['', ' ', 'a b.invalid', 'a\tb.invalid', 'a .invalid', 'a\\b.invalid',
    'user:pass@a.invalid', '[::1]', '[::1]:80', 'a.invalid:80:80', 'a.invalid#f', 'a.invalid/p',
    '-lead.invalid', 'trail-.invalid', '.leading.invalid', 'a..invalid', 'a.invalid.', 'xn--café.invalid',
    'a'.repeat(64) + '.invalid']) {
    assert.equal(parseHostHeader(value), null, `must reject ${JSON.stringify(value)}`);
  }
  assert.deepEqual(parseHostHeader('demo.sites.invalid'), { host: 'demo.sites.invalid', port: null });
  assert.deepEqual(parseHostHeader('DEMO.Sites.Invalid:8443'), { host: 'demo.sites.invalid', port: 8443 });
  // An IPv4 literal is well-formed but binds to nothing; resolve() reports it as
  // an unknown host so probes cannot tell malformed syntax from an absent site.
  assert.deepEqual(parseHostHeader('192.168.0.1'), { host: '192.168.0.1', port: null });
  assert.throws(() => createHostBinding({ baseDomain: BASE_DOMAIN }).resolve('192.168.0.1'),
    error => error.code === 'OWA_CONTENT_HOST_UNKNOWN');
});

test('the documented base-domain spellings are all accepted', () => {
  // `localhost` is a single label and is what the local development setup in
  // docs/origins.md uses; rejecting it would break the documented quickstart.
  for (const baseDomain of ['localhost', 'sites.example.invalid', 'sites.exampleusercontent.com', 'a-b.c-d.invalid']) {
    const binding = createHostBinding({ baseDomain });
    assert.equal(binding.resolve(`demo.${baseDomain}`), 'demo');
    assert.equal(canonicalContentUrl(binding, 'demo', { scheme: 'http', port: 7332 }), `http://demo.${baseDomain}:7332/`);
  }
  for (const baseDomain of ['', '.', 'a..b', '-bad.invalid', 'bad-.invalid', 'a.invalid.', 'caf\u00e9.invalid', 'a'.repeat(64)]) {
    assert.throws(() => createHostBinding({ baseDomain }), error => error.code === 'OWA_AUTH_CONFIG', `must reject ${JSON.stringify(baseDomain)}`);
  }
});

test('a site cannot escape into another metadata namespace through the Host', async () => {
  let lookups = 0;
  const binding = createHostBinding({ baseDomain: BASE_DOMAIN });
  // Traversal, encoding and separator tricks must fail in the binding itself,
  // before any metadata key is derived from the request.
  for (const host of [`../other.${BASE_DOMAIN}`, `..${BASE_DOMAIN}`, `a%2f..${BASE_DOMAIN}`,
    `demo%2eother.${BASE_DOMAIN}`, `demo/other.${BASE_DOMAIN}`, `demo\\other.${BASE_DOMAIN}`]) {
    assert.throws(() => { lookups++; binding.resolve(host); }, error => error.name === 'ContentHostError');
  }
  assert.equal(lookups, 6);
});

// ------------------------------------------------------------ path safety ---

test('22-24. artifact path hardening is unchanged on the content origin', async t => {
  await withOrigins(async env => {
    await t.test('22/23. raw and encoded traversal remain rejected', async () => {
      for (const path of ['/../secret', '/..%2fsecret', '/%2e%2e/secret', '/a/../../secret',
        '/%2e%2e%2fsecret', '/..\\secret', '/%5c..%5csecret']) {
        const res = await raw(env.contentPort, path);
        assert.equal(res.status, 404, `${path} must not resolve`);
        assert.equal(parseBody(res).error, 'file not found');
      }
    });

    await t.test('24. malformed percent encodings remain rejected', async () => {
      for (const path of ['/%', '/%zz', '/%2', '/index%.html', '/%e0%a4%a.html']) {
        assert.equal((await raw(env.contentPort, path)).status, 404, `${path} must not resolve`);
      }
    });

    await t.test('a NUL byte in the path is rejected', async () => {
      assert.equal((await raw(env.contentPort, '/index%00.html')).status, 404);
    });

    await t.test('decode-once semantics are preserved: %252e is not decoded twice', async () => {
      assert.equal((await raw(env.contentPort, '/%252e%252e/secret')).status, 404);
    });
  });
});

// ------------------------------------------------------- canonical URL ---

test('26-28,36. the canonical public URL is server-authoritative', async t => {
  const artifact = siteArtifact('demo');
  const commitBody = slug => JSON.stringify({ manifest: siteArtifact(slug).manifest, artifactDigest: siteArtifact(slug).artifactDigest });

  await t.test('26. commit returns contentUrl when a content origin is configured', async () => {
    await withOrigins(async env => {
      const res = await raw(env.controlPort, '/v1/sites/demo/publish/commit', {
        method: 'POST', body: commitBody('demo'),
        headers: { 'content-type': 'application/json', ...bearer(['commit', 'activate']) }
      });
      assert.equal(res.status, 201);
      assert.equal(parseBody(res).contentUrl, `https://demo.${BASE_DOMAIN}/`);
    }, { seedSites: ['demo'] });
  });

  await t.test('26. the field is omitted entirely, never fabricated, without configuration', async () => {
    await withOrigins(async env => {
      const res = await raw(env.controlPort, '/v1/sites/demo/publish/commit', {
        method: 'POST', body: commitBody('demo'),
        headers: { 'content-type': 'application/json', ...bearer(['commit', 'activate']) }
      });
      assert.equal(res.status, 201);
      assert.equal(Object.hasOwn(parseBody(res), 'contentUrl'), false, 'no URL is better than a wrong URL');
    }, { content: null, seedSites: ['demo'] });
  });

  await t.test('27/28. the URL derives only from configuration and the authorized slug', async () => {
    await withOrigins(async env => {
      // Client-supplied URL-ish fields in the commit body must be ignored entirely.
      const packed = siteArtifact('demo');
      const res = await raw(env.controlPort, '/v1/sites/demo/publish/commit', {
        method: 'POST',
        body: JSON.stringify({
          manifest: packed.manifest, artifactDigest: packed.artifactDigest,
          contentUrl: 'https://attacker.invalid/', url: 'https://attacker.invalid/',
          content: { baseDomain: 'attacker.invalid' }
        }),
        headers: { 'content-type': 'application/json', host: 'attacker.invalid', ...bearer(['commit', 'activate']) }
      });
      assert.equal(res.status, 201);
      const body = parseBody(res);
      assert.equal(body.contentUrl, `https://demo.${BASE_DOMAIN}/`);
      assert.ok(!JSON.stringify(body).includes('attacker.invalid'), 'no client input reaches the canonical URL');
    }, { seedSites: ['demo'] });
  });

  await t.test('36. no bearer or credential can appear in a canonical URL', async () => {
    const binding = createHostBinding({ baseDomain: BASE_DOMAIN });
    const url = canonicalContentUrl(binding, 'demo', { scheme: 'https' });
    assert.equal(url, `https://demo.${BASE_DOMAIN}/`);
    const parsed = new URL(url);
    assert.equal(parsed.username, '');
    assert.equal(parsed.password, '');
    assert.equal(parsed.search, '');
    // An invalid slug or unconfigured binding yields null rather than a guess.
    assert.equal(canonicalContentUrl(binding, '../evil', {}), null);
    assert.equal(canonicalContentUrl(null, 'demo', {}), null);
    assert.equal(canonicalContentUrl(binding, 'demo', { scheme: 'javascript' }), null);
  });

  await t.test('explicit host mappings produce a canonical URL; ambiguous ones produce none', () => {
    const pinned = createHostBinding({ hosts: { 'demo.example.invalid': 'demo' } });
    assert.equal(canonicalContentUrl(pinned, 'demo', { scheme: 'https' }), 'https://demo.example.invalid/');
    const ambiguous = createHostBinding({ hosts: { 'a.example.invalid': 'demo', 'b.example.invalid': 'demo' } });
    assert.equal(canonicalContentUrl(ambiguous, 'demo', { scheme: 'https' }), null);
  });

  await t.test('a non-default port is rendered, a default port is not', () => {
    const binding = createHostBinding({ baseDomain: BASE_DOMAIN });
    assert.equal(canonicalContentUrl(binding, 'demo', { scheme: 'http', port: 8080 }), `http://demo.${BASE_DOMAIN}:8080/`);
    assert.equal(canonicalContentUrl(binding, 'demo', { scheme: 'http', port: 80 }), `http://demo.${BASE_DOMAIN}/`);
    assert.equal(canonicalContentUrl(binding, 'demo', { scheme: 'https', port: 443 }), `https://demo.${BASE_DOMAIN}/`);
  });

  assert.equal(artifact.artifactDigest, siteArtifact('demo').artifactDigest, 'fixture determinism');
});

// -------------------------------------------------- artifact invariance ---

test('29-31. content-origin configuration cannot affect artifact or release identity', async () => {
  const captured = [];
  for (const content of [null, CONTENT, { baseDomain: 'other.invalid', scheme: 'http', port: 8080 }]) {
    await withOrigins(async env => {
      const packed = siteArtifact('demo');
      const res = await raw(env.controlPort, '/v1/sites/demo/publish/commit', {
        method: 'POST', body: JSON.stringify({ manifest: packed.manifest, artifactDigest: packed.artifactDigest }),
        headers: { 'content-type': 'application/json', ...bearer(['commit', 'activate']) }
      });
      assert.equal(res.status, 201);
      const body = parseBody(res);
      const site = await env.metadata.getSite('demo');
      const release = await env.metadata.getRelease(site.id, body.releaseId);
      captured.push({
        artifactDigest: body.artifactDigest,
        canonical: canonicalJson(release.manifest),
        storedDigest: artifactDigest(release.manifest),
        manifestKeys: Object.keys(release.manifest).sort().join(','),
        releaseShape: Object.keys(release).sort().join(',')
      });
    }, { content, seedSites: ['demo'] });
  }
  const [first, ...rest] = captured;
  for (const entry of rest) {
    assert.equal(entry.artifactDigest, first.artifactDigest, '30. digest is independent of content origin');
    assert.equal(entry.canonical, first.canonical, '29. canonical manifest bytes are byte-identical');
    assert.equal(entry.storedDigest, first.storedDigest);
    assert.equal(entry.releaseShape, first.releaseShape, '31. release record shape is unchanged');
  }
  assert.equal(first.storedDigest, first.artifactDigest);
  assert.ok(!first.manifestKeys.includes('contentUrl'), 'no URL/origin field enters the manifest');
  assert.ok(!first.canonical.includes(BASE_DOMAIN), 'no content domain is persisted in canonical bytes');
  assert.ok(!first.releaseShape.includes('contentUrl'), 'no URL/origin field enters the release record');
});

// ------------------------------------------------------------- topology ---

test('control and content are genuinely different origins over shared storage', async () => {
  await withOrigins(async env => {
    assert.notEqual(env.controlPort, env.contentPort, 'separate listeners, separate origins');
    // The same path is control on one origin and absent on the other.
    const onControl = await raw(env.controlPort, '/v1/sites/demo/releases', { headers: bearer(['read']) });
    const onContent = await raw(env.contentPort, '/v1/sites/demo/releases', { headers: bearer(['read']) });
    assert.equal(onControl.status, 200);
    assert.equal(onContent.status, 404);
    // Content is public on one origin and absent on the other.
    const contentHere = await raw(env.contentPort, '/');
    assert.equal(contentHere.status, 200);
    const contentThere = await raw(env.controlPort, '/', { host: `demo.${BASE_DOMAIN}` });
    assert.equal(contentThere.status, 404, 'the control origin serves no artifact bytes');
  });
});

test('43. the legacy shared-origin server keeps its documented prototype behavior', async () => {
  // Backwards compatibility: createArtifactServer is unchanged, including the
  // `?site=`/`.localhost` selectors that the content origin deliberately drops.
  const root = await mkdtemp(join(tmpdir(), 'owa-origins-legacy-'));
  let server;
  try {
    const blobs = new FilesystemBlobStore(root), metadata = new FilesystemMetadataStore(root);
    const artifact = siteArtifact('legacy');
    for (const [hash, bytes] of artifact.blobs) await blobs.put(hash, bytes);
    const releaseId = `r_${'3'.repeat(20)}`;
    const site = { id: `s_${digest(Buffer.from('legacy')).slice(7, 27)}`, slug: 'legacy', activeReleaseId: releaseId, createdAt: FIXED_TIME };
    await metadata.saveSite(site);
    await metadata.saveRelease(site.id, { id: releaseId, artifactDigest: artifact.artifactDigest, createdAt: FIXED_TIME, manifest: artifact.manifest });
    server = createArtifactServer({ blobs, metadata, uploadSecret: UPLOAD_SECRET, auth: { mode: 'dev' } });
    server.listen(0, '127.0.0.1');
    await once(server, 'listening');
    const port = server.address().port;
    assert.equal((await raw(port, '/?site=legacy', { host: 'localhost' })).status, 200);
    assert.equal((await raw(port, '/', { host: 'legacy.localhost' })).status, 200);
    assert.equal((await raw(port, '/health', { host: 'localhost' })).status, 200);
  } finally {
    if (server?.listening) await new Promise(resolve => server.close(() => resolve()));
    await rm(root, { recursive: true, force: true });
  }
});

// ---------------------------------------------------------------- clients ---

/** Publish a real directory through the hardened CLI against a real control listener. */
async function withCliPublish(run, { content = CONTENT } = {}) {
  const root = await mkdtemp(join(tmpdir(), 'owa-origins-cli-'));
  const previousToken = process.env.OWA_TOKEN;
  let server;
  try {
    const directory = join(root, 'site');
    await mkdir(directory, { recursive: true });
    await writeFile(join(directory, 'index.html'), '<h1>cli</h1>');
    const blobs = new FilesystemBlobStore(join(root, 'store'));
    const metadata = new FilesystemMetadataStore(join(root, 'store'));
    server = createControlServer({
      blobs, metadata, uploadSecret: UPLOAD_SECRET, content,
      auth: { secret: SECRET, now: () => NOW }
    });
    server.listen(0, '127.0.0.1');
    await once(server, 'listening');
    const origin = `http://127.0.0.1:${server.address().port}`;
    process.env.OWA_TOKEN = token(['plan', 'upload', 'commit', 'activate', 'read']);
    return await run({ directory, origin, blobs, metadata });
  } finally {
    if (previousToken === undefined) delete process.env.OWA_TOKEN; else process.env.OWA_TOKEN = previousToken;
    if (server?.listening) await new Promise(resolve => server.close(() => resolve()));
    await rm(root, { recursive: true, force: true });
  }
}

test('32. the CLI surfaces the server-provided canonical URL and never rebuilds one', async t => {
  await t.test('the configured canonical URL reaches the CLI result and output', async () => {
    await withCliPublish(async env => {
      const result = await remotePublishResult(env.directory, 'demo', env.origin);
      assert.equal(result.contentUrl, `https://demo.${BASE_DOMAIN}/`);
      // The printed URL is the server's, never the control origin the CLI dialed.
      const text = await remotePublish(env.directory, 'demo', env.origin);
      assert.match(text, /Public URL: https:\/\/demo\.sites\.exampleusercontent\.invalid\//);
      assert.ok(!text.includes(env.origin), 'the control origin is not advertised as public');
      assert.ok(!text.includes('?site='), 'the CLI never synthesizes a query selector');
    });
  });

  await t.test('with no content origin configured the CLI reports no URL at all', async () => {
    await withCliPublish(async env => {
      const result = await remotePublishResult(env.directory, 'demo', env.origin);
      assert.equal(Object.hasOwn(result, 'contentUrl'), false);
      const text = await remotePublish(env.directory, 'demo', env.origin);
      assert.ok(!text.includes('Public URL'), 'no URL is better than a reconstructed guess');
    }, { content: null });
  });

  await t.test('28/36. a hostile or credential-bearing URL from a server is discarded', () => {
    for (const value of ['https://user:pass@evil.invalid/', 'https://evil.invalid/#f', 'https://evil.invalid/?site=x',
      'javascript:alert(1)', 'data:text/html,x', '//evil.invalid/', 'not a url', '', null, undefined, 42, {}]) {
      assert.equal(publicContentUrl(value), null, `must reject ${JSON.stringify(value)}`);
    }
    assert.equal(publicContentUrl('https://demo.example.invalid/'), 'https://demo.example.invalid/');
  });
});

test('37. S3/R2 presigned upload grants are unchanged by content-origin configuration', async () => {
  // A storage adapter that mints its own grants must keep doing so verbatim: no
  // OWA bearer marker, no control-origin URL, and no dependence on content config.
  const grants = [];
  const storageBlobs = {
    async has() { return false; },
    async get() { throw new Error('unused'); },
    async put() {},
    async createUpload(digestValue, options) {
      const grant = { digest: digestValue, method: 'PUT', url: `https://bucket.r2.invalid/${digestValue}?X-Amz-Signature=${'f'.repeat(64)}`, expiresIn: options.expires };
      grants.push(grant);
      return grant;
    }
  };
  const captured = [];
  for (const content of [null, CONTENT]) {
    const root = await mkdtemp(join(tmpdir(), 'owa-origins-s3-'));
    let server;
    try {
      const metadata = new FilesystemMetadataStore(root);
      server = createControlServer({ blobs: storageBlobs, metadata, uploadSecret: UPLOAD_SECRET, content, auth: { secret: SECRET, now: () => NOW } });
      server.listen(0, '127.0.0.1');
      await once(server, 'listening');
      const packed = siteArtifact('demo');
      const res = await raw(server.address().port, '/v1/sites/demo/publish/plan', {
        method: 'POST', body: JSON.stringify({ manifest: packed.manifest, artifactDigest: packed.artifactDigest }),
        headers: { 'content-type': 'application/json', ...bearer(['plan', 'upload']) }
      });
      assert.equal(res.status, 200);
      captured.push(parseBody(res).uploads);
    } finally {
      if (server?.listening) await new Promise(resolve => server.close(() => resolve()));
      await rm(root, { recursive: true, force: true });
    }
  }
  assert.deepEqual(captured[0], captured[1], 'content configuration must not alter storage grants');
  for (const upload of captured.flat()) {
    assert.equal(upload.method, 'PUT');
    assert.ok(upload.url.startsWith('https://bucket.r2.invalid/'), 'the storage grant URL is passed through');
    assert.equal(Object.hasOwn(upload, 'authorization'), false, 'no OWA bearer marker on a storage grant');
    assert.ok(!upload.url.includes(BASE_DOMAIN), 'the content origin never leaks into a storage grant');
  }
});

test('33/34. the MCP adapter consumes the server URL and synthesizes no ?site=', async () => {
  // The adapter's runtime needs its isolated SDK dependencies, so these are
  // source- and schema-level assertions that hold without installing them.
  const source = await readFile(new URL('../../mcp/src/adapter.js', import.meta.url), 'utf8');
  // Assert on executable code: prose about the retired prototype URL is allowed.
  const adapter = source.replace(/\/\*[\s\S]*?\*\//g, '').replace(/^\s*\/\/.*$/gm, '');
  assert.ok(!/\?site=/.test(adapter), '34. no prototype query URL may be synthesized');
  assert.ok(!/config\.server\s*\}\s*\/\?/.test(adapter), '34. no control origin is advertised as public');
  assert.ok(/contentUrl/.test(adapter), '33. the server-provided canonical URL is consumed');

  const publish = TOOLS.find(tool => tool.name === 'publish');
  const success = publish.outputSchema.oneOf[0];
  assert.equal(success.properties.url.type, 'string');
  assert.ok(!success.required.includes('url'), 'url must be optional so it can be omitted entirely');
  for (const field of ['site', 'artifactDigest', 'releaseId', 'activeReleaseId', 'uploaded', 'reused']) {
    assert.ok(success.required.includes(field), `${field} remains required`);
  }
  // The published discovery snapshot must match the runtime surface exactly.
  const snapshot = JSON.parse(await readFile(new URL('../../mcp/tool-schemas.json', import.meta.url), 'utf8'));
  assert.deepEqual(snapshot, { tools: TOOLS });
});
