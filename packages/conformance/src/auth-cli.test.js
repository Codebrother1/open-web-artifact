import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { createServer } from 'node:http';
import { once } from 'node:events';
import { mkdtemp, mkdir, readFile, readdir, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createToken } from '../../server/src/auth.js';
import { createArtifactServer } from '../../server/src/index.js';
import { FilesystemBlobStore, FilesystemMetadataStore } from '../../storage-filesystem/src/index.js';
import { CliError, cliErrorMessage, remoteReleases } from '../../cli/src/remote.js';

// Synthetic credentials are constructed at runtime and kept only in memory.
// Never assert raw output/token equality: failed assertions must not print them.
const secret = Buffer.from(Array.from({ length: 32 }, (_, i) => i + 41));
const uploadSecret = Buffer.from(Array.from({ length: 32 }, (_, i) => i + 89));
const NOW = 1700000000;
const CAPS = ['plan', 'upload', 'commit', 'activate', 'read'];
const mint = (capabilities = CAPS, sites = ['demo']) => createToken({
  secret, now: () => NOW, jti: 'synthetic-cli-test', exp: NOW + 300, sites, capabilities
});
const CLI = fileURLToPath(new URL('../../cli/src/index.js', import.meta.url));
const RELEASE = `r_${'a'.repeat(20)}`;
const DIGEST = `sha256:${'b'.repeat(64)}`;
const TIMESTAMP = '2023-11-14T22:13:20.000Z';
const signature = () => Buffer.from(Array.from({ length: 32 }, (_, i) => i + 5)).toString('hex');

async function fixture(t) {
  const root = await mkdtemp(join(tmpdir(), 'owa-auth-cli-'));
  const site = join(root, 'site'), data = join(root, 'data');
  await mkdir(site); await mkdir(data);
  await writeFile(join(site, 'index.html'), '<h1>Synthetic auth CLI fixture</h1>');
  t.after(() => rm(root, { recursive: true, force: true }));
  return { root, site, data };
}
async function listen(t, server) {
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  t.after(() => new Promise(resolve => { server.close(resolve); server.closeAllConnections(); }));
  return `http://127.0.0.1:${server.address().port}`;
}
async function run(args, token, cwd) {
  const child = spawn(process.execPath, [CLI, ...args], {
    cwd, env: { ...process.env, OWA_TOKEN: token ?? '' }, stdio: ['ignore', 'pipe', 'pipe']
  });
  let stdout = '', stderr = '';
  child.stdout.on('data', chunk => { stdout += chunk; });
  child.stderr.on('data', chunk => { stderr += chunk; });
  const timeout = setTimeout(() => child.kill('SIGKILL'), 10000);
  try {
    const [code, signal] = await once(child, 'close');
    return { code, signal, stdout, stderr };
  } finally { clearTimeout(timeout); }
}
function safeResult(result, token, { ok = true, code, forbidden = [] } = {}) {
  assert.ok(result.signal === null, 'CLI exited normally');
  assert.ok(result.code === (ok ? 0 : 1), 'CLI exit code');
  const output = result.stdout + result.stderr;
  assert.ok(!token || !output.includes(token), 'credential is never printed');
  for (const value of forbidden) assert.ok(!output.includes(value), 'sensitive response data is never printed');
  assert.ok(!output.includes('X-Amz-Signature=') && !output.includes('?expires='), 'no full presigned URL');
  assert.ok(!output.includes('    at ') && !output.includes('[cause]'), 'no stack or nested cause');
  if (!ok) assert.ok(result.stdout === '', 'failure does not produce partial success output');
  if (code) assert.ok(result.stderr.includes(code), 'fixed error code is reported');
}
function json(res, status, value) {
  res.writeHead(status, { 'content-type': 'application/json' }); res.end(JSON.stringify(value));
}
async function readJson(req) {
  let text = ''; for await (const chunk of req) text += chunk;
  return JSON.parse(text || '{}');
}
function observe(req, token) {
  return {
    method: req.method,
    path: new URL(req.url, 'http://localhost').pathname,
    authorized: req.headers.authorization === `Bearer ${token}`,
    hasAuthorization: Object.hasOwn(req.headers, 'authorization'),
    contentType: req.headers['content-type'],
    leakedOutsideHeader: req.url.includes(token) || Object.entries(req.headers)
      .some(([name, value]) => name !== 'authorization' && String(value).includes(token))
  };
}
function bearerGrant(origin, digest) {
  return { digest, method: 'PUT', authorization: 'bearer',
    url: `${origin}/v1/uploads/${encodeURIComponent(digest)}?expires=${NOW + 300}&sig=${signature()}&site=demo` };
}
async function mockControl(t, token, { grant, planResponse, commitResponse, releasesResponse, activateResponse, uploadStatus = 204, uploadBody = '' } = {}) {
  const seen = [], bodies = [];
  let origin;
  const server = createServer(async (req, res) => {
    seen.push(observe(req, token));
    try {
      if (req.url.endsWith('/publish/plan')) {
        const body = await readJson(req); bodies.push({ operation: 'plan', body });
        const digest = body.manifest.files[0].digest;
        const uploads = grant ? [await grant(origin, digest)] : [];
        return json(res, 200, planResponse ? planResponse(body, uploads) : {
          slug: 'demo', artifactDigest: body.artifactDigest, uploads, reused: uploads.length ? 0 : 1
        });
      }
      if (req.url.endsWith('/publish/commit')) {
        const body = await readJson(req); bodies.push({ operation: 'commit', body });
        return json(res, 201, commitResponse ? commitResponse(body) : {
          slug: 'demo', releaseId: RELEASE, artifactDigest: body.artifactDigest,
          activeReleaseId: body.activate === false ? null : RELEASE
        });
      }
      if (req.url.endsWith('/releases')) return json(res, 200, releasesResponse ?? {
        site: { slug: 'demo', activeReleaseId: RELEASE },
        releases: [{ id: RELEASE, artifactDigest: DIGEST, createdAt: TIMESTAMP }]
      });
      if (req.url.includes('/activate/')) return json(res, 200, activateResponse ?? { slug: 'demo', activeReleaseId: RELEASE });
      for await (const chunk of req) void chunk;
      res.writeHead(uploadStatus); res.end(uploadBody);
    } catch { json(res, 500, { error: 'Synthetic fixture failure' }); }
  });
  origin = await listen(t, server);
  return { origin, seen, bodies };
}

// Real server + filesystem integration: actual auth contract, no mock auth bypass.
test('CLI authenticates plan, local FS upload, commit, read and activate with header-only env token', async t => {
  const { site, data, root } = await fixture(t);
  const token = mint();
  const blobs = new FilesystemBlobStore(data), metadata = new FilesystemMetadataStore(data);
  const server = createArtifactServer({ blobs, metadata, uploadSecret, auth: { secret, now: () => NOW } });
  const seen = [];
  server.on('request', req => { seen.push(observe(req, token)); });
  const origin = await listen(t, server);
  const published = await run(['publish', site, '--site', 'demo', '--server', origin], token, root);
  safeResult(published, token);
  const record = await metadata.getSite('demo');
  assert.ok(/^r_[0-9a-f]{20}$/.test(record.activeReleaseId), 'publish activates by default');
  safeResult(await run(['releases', '--site', 'demo', '--server', origin], token, root), token);
  safeResult(await run(['activate', record.activeReleaseId, '--site', 'demo', '--server', origin], token, root), token);
  assert.ok(seen.length === 5, 'plan, upload, commit, releases and activate');
  assert.ok(seen.every(req => req.authorized && !req.leakedOutsideHeader), 'all control and marked FS calls have the credential only in Authorization');
  const upload = seen.find(req => req.method === 'PUT');
  assert.ok(upload.path.startsWith('/v1/uploads/sha256%3A'), 'exact encoded local digest route');
  assert.ok(upload.contentType === undefined, 'control JSON headers are not copied into upload');
  async function noPersistedToken(dir) {
    for (const entry of await readdir(dir, { withFileTypes: true })) {
      const path = join(dir, entry.name);
      if (entry.isDirectory()) await noPersistedToken(path);
      else assert.ok(!(await readFile(path)).includes(Buffer.from(token)), 'credential is not persisted');
    }
  }
  await noPersistedToken(root);
});

test('CLI --no-activate permits commit-only capability and default publish still requires activate', async t => {
  const { site, data, root } = await fixture(t);
  const token = mint(['plan', 'upload', 'commit']);
  const blobs = new FilesystemBlobStore(data), metadata = new FilesystemMetadataStore(data);
  const origin = await listen(t, createArtifactServer({ blobs, metadata, uploadSecret, auth: { secret, now: () => NOW } }));
  const args = ['publish', site, '--site', 'demo', '--server', origin];
  safeResult(await run([...args, '--no-activate'], token, root), token);
  assert.ok((await metadata.getSite('demo')).activeReleaseId === null, 'commit did not activate');
  assert.ok((await metadata.listReleases((await metadata.getSite('demo')).id)).length === 1);
  safeResult(await run(args, token, root), token, { ok: false, code: 'OWA_AUTH_CAPABILITY' });
  assert.ok((await metadata.getSite('demo')).activeReleaseId === null, 'denied default commit cannot activate');
  safeResult(await run(['releases', '--site', 'demo', '--server', origin], token, root), token, { ok: false, code: 'OWA_AUTH_CAPABILITY' });
  const release = (await metadata.listReleases((await metadata.getSite('demo')).id))[0];
  safeResult(await run(['activate', release.id, '--site', 'demo', '--server', origin], token, root), token, { ok: false, code: 'OWA_AUTH_CAPABILITY' });
});

test('CLI plan with missing blobs requires upload as well as plan; missing/site-scoped credentials are rejected', async t => {
  const { site, data, root } = await fixture(t);
  const blobs = new FilesystemBlobStore(data), metadata = new FilesystemMetadataStore(data);
  const origin = await listen(t, createArtifactServer({ blobs, metadata, uploadSecret, auth: { secret, now: () => NOW } }));
  for (const [token, code] of [[mint(['plan']), 'OWA_AUTH_CAPABILITY'], [undefined, 'OWA_AUTH_MISSING'], [mint(CAPS, ['other']), 'OWA_AUTH_SITE']]) {
    safeResult(await run(['publish', site, '--site', 'demo', '--server', origin], token, root), token, { ok: false, code });
  }
  assert.ok(await metadata.getSite('demo') === null, 'denials do not create a site');
});

test('CLI commit sends activate:false only for --no-activate; default field remains absent', async t => {
  const { site, root } = await fixture(t), token = mint();
  const mock = await mockControl(t, token);
  const args = ['publish', site, '--site', 'demo', '--server', mock.origin];
  safeResult(await run([...args, '--no-activate'], token, root), token);
  safeResult(await run(args, token, root), token);
  const commits = mock.bodies.filter(value => value.operation === 'commit');
  assert.ok(commits[0].body.activate === false && !Object.hasOwn(commits[1].body, 'activate'));
  assert.ok(mock.seen.every(value => value.authorized && !value.leakedOutsideHeader));
  assert.ok(mock.bodies.every(value => !JSON.stringify(value.body).includes(token)), 'credential is not in JSON');
});

for (const external of [false, true]) {
  test(`CLI does not send OWA authorization on ${external ? 'external-origin' : 'same-origin'} S3/R2-style upload`, async t => {
    const { site, root } = await fixture(t), token = mint();
    const objectRequests = [];
    let objectOrigin;
    if (external) objectOrigin = await listen(t, createServer(async (req, res) => {
      objectRequests.push(observe(req, token)); for await (const chunk of req) void chunk;
      res.writeHead(204); res.end();
    }));
    const mock = await mockControl(t, token, { grant: (origin, digest) => ({ digest, method: 'PUT',
      url: `${objectOrigin ?? origin}/bucket/object?X-Amz-Signature=${signature()}` }) });
    safeResult(await run(['publish', site, '--site', 'demo', '--server', mock.origin], token, root), token);
    const uploads = external ? objectRequests : mock.seen.filter(req => req.method === 'PUT');
    assert.ok(uploads.length === 1 && !uploads[0].hasAuthorization && uploads[0].contentType === undefined, 'ordinary upload has no copied control headers');
    assert.ok(!uploads[0].leakedOutsideHeader, 'credential is absent from URL and all other headers');
    assert.ok(mock.seen.filter(req => req.method !== 'PUT').every(req => req.authorized));
  });
}

test('CLI does not infer bearer auth for an unmarked same-origin filesystem-looking URL', async t => {
  const { site, root } = await fixture(t), token = mint();
  const mock = await mockControl(t, token, { grant: (origin, digest) => {
    const value = bearerGrant(origin, digest); delete value.authorization; return value;
  } });
  safeResult(await run(['publish', site, '--site', 'demo', '--server', mock.origin], token, root), token);
  const upload = mock.seen.find(req => req.method === 'PUT');
  assert.ok(upload && !upload.hasAuthorization, 'authorization requires an explicit marker');
});

const invalidGrants = [
  ['unknown authorization marker', value => ({ ...value, authorization: 'basic' })],
  ['null authorization marker', value => ({ ...value, authorization: null })],
  ['arbitrary headers', value => ({ ...value, headers: { 'x-provider-key': 'untrusted' } })],
  ['empty arbitrary headers', value => ({ ...value, headers: {} })],
  ['non-PUT method', value => ({ ...value, method: 'POST' })],
  ['null method', value => ({ ...value, method: null })],
  ['lowercase method', value => ({ ...value, method: 'put' })],
  ['cross-site query', value => ({ ...value, url: value.url.replace('site=demo', 'site=other') })],
  ['duplicate site query', value => ({ ...value, url: `${value.url}&site=demo` })],
  ['missing site query', value => ({ ...value, url: value.url.replace('&site=demo', '') })],
  ['extra query field', value => ({ ...value, url: `${value.url}&other=value` })],
  ['duplicate signature query', value => ({ ...value, url: `${value.url}&sig=${signature()}` })],
  ['missing signature', value => ({ ...value, url: value.url.replace(`&sig=${signature()}`, '') })],
  ['invalid expiration', value => ({ ...value, url: value.url.replace(`expires=${NOW + 300}`, 'expires=NaN') })],
  ['arbitrary path', value => ({ ...value, url: value.url.replace('/v1/uploads/', '/bucket/') })],
  ['path digest mismatch', value => ({ ...value, url: value.url.replace(encodeURIComponent(value.digest), encodeURIComponent(DIGEST)) })],
  ['unknown instruction digest', value => ({ ...value, digest: DIGEST })],
  ['malformed instruction digest', value => ({ ...value, digest: 'sha256:bad\n' })],
  ['URL username', value => ({ ...value, url: value.url.replace('http://', 'http://operator@') })],
  ['URL password', value => ({ ...value, url: value.url.replace('http://', 'http://operator:password@') })],
  ['empty URL userinfo', value => ({ ...value, url: value.url.replace('http://', 'http://@') })],
  ['URL fragment', value => ({ ...value, url: `${value.url}#fragment` })],
  ['empty URL fragment', value => ({ ...value, url: `${value.url}#` })],
  ['path traversal normalization', value => ({ ...value, url: value.url.replace('/v1/uploads/', '/discard/../v1/uploads/') })],
  ['encoded path traversal normalization', value => ({ ...value, url: value.url.replace('/v1/uploads/', '/%2e%2e/v1/uploads/') })],
  ['backslash normalization', value => ({ ...value, url: value.url.replace('/v1/uploads/', '/v1\\uploads/') })],
  ['URL whitespace', value => ({ ...value, url: `${value.url}\n` })],
  ['relative upload URL', value => ({ ...value, url: new URL(value.url).pathname })],
  ['non-HTTP upload URL', value => ({ ...value, url: 'file:///untrusted' })]
];
for (const [label, transform] of invalidGrants) {
  test(`CLI rejects ${label} before any upload or commit`, async t => {
    const { site, root } = await fixture(t), token = mint();
    const mock = await mockControl(t, token, { grant: (origin, digest) => transform(bearerGrant(origin, digest)) });
    safeResult(await run(['publish', site, '--site', 'demo', '--server', mock.origin], token, root), token, { ok: false, code: 'OWA_CLI_GRANT' });
    assert.ok(mock.seen.length === 1 && mock.seen[0].authorized, 'only the authenticated plan was sent');
  });
}

test('CLI rejects an external bearer-marked upload without sending any request to that origin', async t => {
  const { site, root } = await fixture(t), token = mint();
  let externalHits = 0;
  const external = await listen(t, createServer((req, res) => { externalHits++; res.end(); }));
  const mock = await mockControl(t, token, { grant: (_origin, digest) => bearerGrant(external, digest) });
  safeResult(await run(['publish', site, '--site', 'demo', '--server', mock.origin], token, root), token, { ok: false, code: 'OWA_CLI_GRANT' });
  assert.ok(externalHits === 0 && mock.seen.length === 1, 'no cross-origin credential exfiltration or commit');
});

for (const upload of [false, true]) {
  for (const sameOrigin of [false, true]) {
    test(`CLI blocks ${upload ? 'upload' : 'control'} redirect to ${sameOrigin ? 'same' : 'other'} origin`, async t => {
      const { site, root } = await fixture(t), token = mint();
      let targetHits = 0, origin;
      const external = await listen(t, createServer((req, res) => { targetHits++; res.end(); }));
      const server = createServer(async (req, res) => {
        if (req.url.startsWith('/redirect-target')) { targetHits++; res.end(); return; }
        if (upload && req.url.endsWith('/publish/plan')) {
          const body = await readJson(req);
          return json(res, 200, { slug: 'demo', artifactDigest: body.artifactDigest, reused: 0,
            uploads: [bearerGrant(origin, body.manifest.files[0].digest)] });
        }
        for await (const chunk of req) void chunk;
        res.writeHead(307, { location: `${sameOrigin ? origin : external}/redirect-target?X-Amz-Signature=${signature()}` }); res.end();
      });
      origin = await listen(t, server);
      const args = upload ? ['publish', site, '--site', 'demo', '--server', origin] : ['releases', '--site', 'demo', '--server', origin];
      safeResult(await run(args, token, root), token, { ok: false, code: 'OWA_CLI_NETWORK' });
      assert.ok(targetHits === 0, 'redirect destination is not requested');
    });
  }
}

test('CLI HTTP failures report only numeric status and whitelisted auth code, never provider error', async t => {
  const { root } = await fixture(t), token = mint();
  const sensitive = `provider-secret-${signature()}`;
  let recognized = true;
  const origin = await listen(t, createServer((req, res) => {
    json(res, 403, { code: recognized ? 'OWA_AUTH_CAPABILITY' : sensitive,
      error: `${token} ${sensitive} https://storage.invalid/object?X-Amz-Signature=${signature()}` });
  }));
  for (const known of [true, false]) {
    recognized = known;
    const result = await run(['releases', '--site', 'demo', '--server', origin], token, root);
    safeResult(result, token, { ok: false, code: known ? 'OWA_AUTH_CAPABILITY' : 'OWA_CLI_HTTP', forbidden: [sensitive] });
    assert.ok(result.stderr.includes('HTTP 403'), 'numeric HTTP status retained');
  }
});

test('CLI upload errors discard the provider body and report numeric status only', async t => {
  const { site, root } = await fixture(t), token = mint();
  const sensitive = `provider-secret-${signature()}`;
  const mock = await mockControl(t, token, { grant: bearerGrant, uploadStatus: 503,
    uploadBody: `${sensitive} ${token} https://storage.invalid/object?X-Amz-Signature=${signature()}` });
  const result = await run(['publish', site, '--site', 'demo', '--server', mock.origin], token, root);
  safeResult(result, token, { ok: false, code: 'OWA_CLI_UPLOAD', forbidden: [sensitive] });
  assert.ok(result.stderr.includes('HTTP 503') && mock.seen.length === 2);
});

test('CLI fixed error formatter ignores raw messages, code spoofing, causes and stack', () => {
  const token = mint();
  const cause = new Error(`provider ${token}`);
  const raw = new Error(`https://storage.invalid/object?X-Amz-Signature=${signature()} ${token}`, { cause });
  raw.code = 'OWA_AUTH_MISSING'; raw.status = 401;
  assert.ok(cliErrorMessage(raw) === 'artifact: OWA_CLI_FAILED: Operation failed');
  const safe = new CliError('OWA_CLI_NETWORK'); safe.message = raw.message; safe.cause = cause;
  assert.ok(cliErrorMessage(safe) === 'artifact: OWA_CLI_NETWORK: Network request failed');
});

test('CLI sanitizes nested fetch causes before they reach the formatter', async () => {
  const previousFetch = globalThis.fetch, previousToken = process.env.OWA_TOKEN;
  const token = mint(); process.env.OWA_TOKEN = token;
  globalThis.fetch = async () => { throw new Error(`provider ${token}`, { cause: new Error(`nested ${token}`) }); };
  try {
    let caught;
    try { await remoteReleases('demo', 'https://control.invalid'); } catch (error) { caught = error; }
    assert.ok(caught instanceof CliError && caught.code === 'OWA_CLI_NETWORK');
    assert.ok(!Object.hasOwn(caught, 'cause') && !caught.stack.includes(token), 'nested network data is dropped');
  } finally {
    globalThis.fetch = previousFetch;
    if (previousToken === undefined) delete process.env.OWA_TOKEN; else process.env.OWA_TOKEN = previousToken;
  }
});

const invalidBases = [
  origin => `${origin}/path`, origin => `${origin}/discard/..`, origin => `${origin}?query=value`,
  origin => `${origin}?`, origin => `${origin}#fragment`, origin => `${origin}#`,
  origin => origin.replace('http://', 'http://operator:password@'), origin => origin.replace('http://', 'http://@'),
  origin => `${origin}\n`, () => 'file:///tmp', () => 'http://192.0.2.1', () => 'http://example.invalid',
  () => 'http://localhost.example.invalid', () => 'http://[::ffff:192.0.2.1]', () => 'http://[::]'
];
for (let i = 0; i < invalidBases.length; i++) {
  test(`CLI rejects unsafe control-plane base URL case ${i + 1} before network activity`, async t => {
    const { root } = await fixture(t), token = mint();
    let hits = 0;
    const origin = await listen(t, createServer((req, res) => { hits++; res.end(); }));
    safeResult(await run(['releases', '--site', 'demo', '--server', invalidBases[i](origin)], token, root), token, { ok: false, code: 'OWA_CLI_CONFIG' });
    assert.ok(hits === 0);
  });
}

test('CLI accepts HTTPS origins and exactly localhost, IPv4 127/8 and IPv6 ::1 for bearer HTTP', async () => {
  const previousFetch = globalThis.fetch, previousToken = process.env.OWA_TOKEN;
  const token = mint(); process.env.OWA_TOKEN = token;
  let hits = 0;
  globalThis.fetch = async (url, options) => {
    hits++;
    assert.ok(options.headers.authorization === `Bearer ${token}`);
    assert.ok(options.redirect === 'error' && options.credentials === 'omit');
    return new Response(JSON.stringify({ site: { slug: 'demo', activeReleaseId: null }, releases: [] }), { status: 200 });
  };
  try {
    for (const base of ['http://localhost:7331', 'http://127.0.0.1', 'http://127.2.3.4:7331/', 'http://[::1]:7331', 'https://control.example.invalid']) {
      assert.ok(await remoteReleases('demo', base) === '');
    }
    assert.ok(hits === 5, 'all supported origin forms reach the mocked transport');
  } finally {
    globalThis.fetch = previousFetch;
    if (previousToken === undefined) delete process.env.OWA_TOKEN; else process.env.OWA_TOKEN = previousToken;
  }
});

test('CLI rejects invalid site and release inputs before remote requests', async t => {
  const { root } = await fixture(t), token = mint();
  const mock = await mockControl(t, token);
  for (const slug of ['Demo', 'a'.repeat(64), 'demo\n', 'demo/other', '_demo', 'démo']) {
    safeResult(await run(['releases', '--site', slug, '--server', mock.origin], token, root), token, { ok: false, code: 'OWA_CLI_INPUT' });
  }
  for (const release of ['r_bad', `r_${'A'.repeat(20)}`, `${RELEASE}\n`, '../release']) {
    safeResult(await run(['activate', release, '--site', 'demo', '--server', mock.origin], token, root), token, { ok: false, code: 'OWA_CLI_INPUT' });
  }
  assert.ok(mock.seen.length === 0);
});

for (const field of ['id', 'artifactDigest', 'createdAt']) {
  test(`CLI rejects sensitive release-list ${field} before printing any row`, async t => {
    const { root } = await fixture(t), token = mint();
    const good = { id: RELEASE, artifactDigest: DIGEST, createdAt: TIMESTAMP };
    const mock = await mockControl(t, token, { releasesResponse: {
      site: { slug: 'demo', activeReleaseId: RELEASE }, releases: [good, { ...good, [field]: token }]
    } });
    safeResult(await run(['releases', '--site', 'demo', '--server', mock.origin], token, root), token, { ok: false, code: 'OWA_CLI_RESPONSE' });
  });
}

test('CLI rejects impossible timestamps rather than printing malformed successful response', async t => {
  const { root } = await fixture(t), token = mint();
  const mock = await mockControl(t, token, { releasesResponse: { site: { slug: 'demo', activeReleaseId: RELEASE },
    releases: [{ id: RELEASE, artifactDigest: DIGEST, createdAt: '2023-02-30T22:13:20.000Z' }] } });
  safeResult(await run(['releases', '--site', 'demo', '--server', mock.origin], token, root), token, { ok: false, code: 'OWA_CLI_RESPONSE' });
});

for (const field of ['releaseId', 'artifactDigest', 'activeReleaseId']) {
  test(`CLI rejects sensitive commit ${field} before success output`, async t => {
    const { site, root } = await fixture(t), token = mint();
    const mock = await mockControl(t, token, { commitResponse: body => ({ slug: 'demo', releaseId: RELEASE,
      artifactDigest: body.artifactDigest, activeReleaseId: RELEASE, [field]: token }) });
    safeResult(await run(['publish', site, '--site', 'demo', '--server', mock.origin], token, root), token, { ok: false, code: 'OWA_CLI_RESPONSE' });
  });
}

test('CLI rejects sensitive activation response before success output', async t => {
  const { root } = await fixture(t), token = mint();
  const mock = await mockControl(t, token, { activateResponse: { slug: 'demo', activeReleaseId: token } });
  safeResult(await run(['activate', RELEASE, '--site', 'demo', '--server', mock.origin], token, root), token, { ok: false, code: 'OWA_CLI_RESPONSE' });
});

test('CLI rejects sensitive plan counts before printing or committing', async t => {
  const { site, root } = await fixture(t), token = mint();
  const mock = await mockControl(t, token, { planResponse: body => ({ slug: 'demo', artifactDigest: body.artifactDigest, uploads: [], reused: token }) });
  safeResult(await run(['publish', site, '--site', 'demo', '--server', mock.origin], token, root), token, { ok: false, code: 'OWA_CLI_RESPONSE' });
  assert.ok(mock.seen.length === 1);
});

test('CLI top-level failures are sanitized even when local paths contain sensitive text', async t => {
  const { root } = await fixture(t), token = mint();
  safeResult(await run(['publish', join(root, token), '--site', 'demo'], token, root), token, { ok: false, code: 'OWA_CLI_FAILED' });
});

test('CLI local filesystem operator workflow remains available without HTTP auth', async t => {
  const { site, data, root } = await fixture(t);
  safeResult(await run(['publish', site, '--site', 'demo', '--data', data], undefined, root), undefined);
  const metadata = new FilesystemMetadataStore(data), record = await metadata.getSite('demo');
  assert.ok(record.activeReleaseId !== null);
  safeResult(await run(['releases', '--site', 'demo', '--data', data], undefined, root), undefined);
  safeResult(await run(['activate', record.activeReleaseId, '--site', 'demo', '--data', data], undefined, root), undefined);
});

test('CLI help describes env-only auth, operator minting and --no-activate without exposing credentials', async t => {
  const { root } = await fixture(t), token = mint();
  const result = await run(['--help'], token, root);
  safeResult(result, token);
  assert.ok(result.stdout.includes('OWA_TOKEN') && result.stdout.includes('createToken') && result.stdout.includes('--no-activate'));
});
