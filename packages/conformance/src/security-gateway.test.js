import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { once } from 'node:events';
import { request } from 'node:http';
import { mkdtemp, readFile, readdir, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { FilesystemBlobStore, FilesystemMetadataStore } from '../../storage-filesystem/src/index.js';
import { createArtifactServer } from '../../server/src/index.js';
import { resolveRequestPath } from '../../core/src/index.js';
import { artifactDigest, canonicalJson, validateManifest } from '../../spec/src/index.js';

// These are HTTP-policy/byte-integrity regressions, NOT browser-enforcement tests.
// No fixture markup or JavaScript is executed, and no browser dependency is used.
// Expectations deliberately do not import the production security-header helper.
const CSP = "sandbox; default-src 'none'; script-src 'none'; style-src 'unsafe-inline'; img-src data:; connect-src 'none'; font-src 'none'; media-src 'none'; object-src 'none'; frame-src 'none'; worker-src 'none'; form-action 'none'; frame-ancestors 'none'; base-uri 'none'";
const COMMON_HEADERS = {
  'content-security-policy': CSP,
  'x-content-type-options': 'nosniff',
  'referrer-policy': 'no-referrer',
  'x-robots-tag': 'noindex, nofollow, noarchive',
  'cache-control': 'no-store',
  'x-frame-options': 'DENY',
  'x-dns-prefetch-control': 'off',
  'x-owa-security-profile': 'sandboxed-web-v1'
};
const fixtureUrl = new URL('../../../docs/security-fixtures/sandboxed-web-v1.json', import.meta.url);
const requestCorpusUrl = new URL('../../../docs/conformance/v0.2/request.json', import.meta.url);
const fixture = JSON.parse(await readFile(fixtureUrl, 'utf8'));
const requestCorpusBytes = await readFile(requestCorpusUrl);
const requestCorpus = JSON.parse(requestCorpusBytes.toString('utf8'));
const FIXED_TIME = '2020-01-01T00:00:00.000Z';

function digest(bytes) {
  return `sha256:${createHash('sha256').update(bytes).digest('hex')}`;
}

function sampleBytes(sample) {
  return Object.hasOwn(sample, 'text') ? Buffer.from(sample.text, 'utf8') : Buffer.from(sample.base64, 'base64');
}

function makeArtifact(sources, { visibility = 'public', spa = false, expiresAt = null } = {}) {
  const blobs = new Map();
  const manifest = {
    specVersion: 'owa.dev/v1',
    artifactType: 'application/vnd.openwebartifact.site.v1+json',
    entrypoint: sources[0].path,
    files: sources.map(source => {
      const bytes = sampleBytes(source), hash = digest(bytes);
      blobs.set(hash, bytes);
      return { path: source.path, digest: hash, size: bytes.length, mediaType: source.mediaType };
    }),
    access: { visibility },
    lifecycle: { expiresAt },
    ...(spa ? { routing: { spaFallback: sources[0].path } } : {})
  };
  validateManifest(manifest);
  const canonical = canonicalJson(manifest);
  const hash = digest(Buffer.from(canonical));
  assert.equal(artifactDigest(manifest), hash, 'independent digest of canonical manifest');
  return { manifest, blobs, canonical, artifactDigest: hash };
}

function typeArtifact() {
  return makeArtifact(fixture.typeCases.map(probe => ({
    ...fixture.samples[probe.sample], path: probe.path, mediaType: probe.mediaType
  })));
}

// Use http.request's path option, never fetch or a URL constructor for the target.
// Fetch/WHATWG URL normalization would erase the very traversal bytes under test.
// Only the TCP destination is loopback; .invalid strings remain inert fixture bytes.
function rawRequest(env, path, { method = 'GET', headers = {}, body } = {}) {
  const payload = body === undefined ? undefined : Buffer.from(body);
  return new Promise((resolve, reject) => {
    const req = request({
      hostname: '127.0.0.1', port: env.port, path, method, agent: false,
      headers: {
        host: 'security.localhost', origin: 'https://untrusted.invalid', connection: 'close',
        ...(payload ? { 'content-length': String(payload.length) } : {}), ...headers
      }
    }, res => {
      const chunks = [];
      res.on('data', chunk => chunks.push(chunk));
      res.on('error', reject);
      res.on('aborted', () => reject(new Error(`Response aborted for ${method} ${path}`)));
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks) }));
    });
    req.setTimeout(5000, () => req.destroy(new Error(`Local HTTP timeout: ${method} ${path}`)));
    req.on('error', reject);
    req.end(payload);
  });
}

async function jsonRequest(env, path, value) {
  return rawRequest(env, path, {
    method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(value)
  });
}

async function withGateway(run, { metadata: suppliedMetadata } = {}) {
  const root = await mkdtemp(join(tmpdir(), 'owa-security-gateway-'));
  const blobs = new FilesystemBlobStore(root);
  const metadata = suppliedMetadata ?? new FilesystemMetadataStore(root);
  let server;
  try {
    server = createArtifactServer({ blobs, metadata, uploadSecret: 'fixed-local-security-test-secret', auth: { mode: 'dev' } });
    server.listen(0, '127.0.0.1');
    await once(server, 'listening');
    return await run({ root, blobs, metadata, server, port: server.address().port });
  } finally {
    try {
      if (server?.listening) await new Promise((resolve, reject) => server.close(error => error ? reject(error) : resolve()));
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  }
}

async function seed(env, artifact, { slug = 'security', releaseId = `r_${'1'.repeat(20)}`, storeBlobs = true } = {}) {
  if (storeBlobs) for (const [hash, bytes] of artifact.blobs) await env.blobs.put(hash, bytes);
  const site = { id: `s_${digest(Buffer.from(slug)).slice(7, 27)}`, slug, activeReleaseId: releaseId, createdAt: FIXED_TIME };
  const release = { id: releaseId, artifactDigest: artifact.artifactDigest, createdAt: FIXED_TIME, manifest: artifact.manifest };
  await env.metadata.saveSite(site);
  await env.metadata.saveRelease(site.id, release);
  return { site, release };
}

async function snapshotTree(root, prefix = '') {
  const snapshot = {};
  for (const entry of (await readdir(join(root, prefix), { withFileTypes: true })).sort((a, b) => a.name < b.name ? -1 : 1)) {
    const name = join(prefix, entry.name);
    if (entry.isDirectory()) Object.assign(snapshot, await snapshotTree(root, name));
    else snapshot[name] = (await readFile(join(root, name))).toString('base64');
  }
  return snapshot;
}

async function preservingStoredBytes(env, artifacts, run) {
  const before = await snapshotTree(env.root);
  const identities = artifacts.map(artifact => ({
    manifest: structuredClone(artifact.manifest), canonical: canonicalJson(artifact.manifest), hash: artifactDigest(artifact.manifest)
  }));
  try {
    return await run();
  } finally {
    assert.deepEqual(await snapshotTree(env.root), before, 'GET/HEAD must not rewrite stored manifest, metadata, or blob bytes');
    for (const [index, artifact] of artifacts.entries()) {
      assert.deepEqual(artifact.manifest, identities[index].manifest, 'in-memory manifest unchanged');
      assert.equal(canonicalJson(artifact.manifest), identities[index].canonical, 'canonical bytes unchanged');
      assert.equal(artifactDigest(artifact.manifest), identities[index].hash, 'artifact identity unchanged');
      for (const [hash, bytes] of artifact.blobs) {
        assert.equal(digest(bytes), hash, 'source byte digest unchanged');
        assert.deepEqual(Buffer.from(await env.blobs.get(hash)), bytes, 'stored blob bytes unchanged');
      }
    }
  }
}

function assertPolicy(response, label = '') {
  for (const [name, value] of Object.entries(COMMON_HEADERS)) assert.equal(response.headers[name], value, `${label}: exact ${name}`);
  assert.equal(response.headers['x-probe-injected'], undefined, `${label}: MIME cannot inject headers`);
  assert.equal(response.headers['set-cookie'], undefined, `${label}: no response cookie`);
  assert.deepEqual(Object.keys(response.headers).filter(name => name.startsWith('access-control-')), [], `${label}: no CORS headers`);
  assert.notEqual(response.status, 304, `${label}: no cacheable not-modified response`);
}

function assertParity(get, head, label) {
  assert.equal(head.status, get.status, `${label}: status parity`);
  assert.equal(head.body.length, 0, `${label}: HEAD body is empty`);
  for (const name of [...Object.keys(COMMON_HEADERS), 'content-type', 'content-disposition', 'content-length', 'etag']) {
    assert.equal(head.headers[name], get.headers[name], `${label}: GET/HEAD ${name} parity`);
  }
  assertPolicy(get, `${label} GET`);
  assertPolicy(head, `${label} HEAD`);
}

async function assertFile(env, target, artifact, filePath, disposition = 'inline', headers = {}) {
  const file = artifact.manifest.files.find(file => file.path === filePath);
  assert.ok(file, 'test expected path is present');
  const get = await rawRequest(env, target, { headers });
  const head = await rawRequest(env, target, { method: 'HEAD', headers });
  assert.equal(get.status, 200, `${target}: GET succeeds`);
  assert.deepEqual(get.body, artifact.blobs.get(file.digest), `${target}: exact original bytes, not sanitized or rewritten`);
  assert.equal(digest(get.body), file.digest, `${target}: independently hashed served bytes`);
  assert.equal(get.headers['content-length'], String(file.size), `${target}: exact byte length`);
  assert.equal(get.headers.etag, `"${file.digest}"`, `${target}: original blob ETag`);
  assert.equal(get.headers['content-type'], disposition === 'inline' ? file.mediaType : 'application/octet-stream', `${target}: manifest type dispatch, not extension or byte sniffing`);
  assert.equal(get.headers['content-disposition'], disposition, `${target}: disposition`);
  assertParity(get, head, target);
  return get;
}

async function assertErrorPair(env, target, status, { headers = {}, error } = {}) {
  const get = await rawRequest(env, target, { headers });
  const head = await rawRequest(env, target, { method: 'HEAD', headers });
  assert.equal(get.status, status, `${target}: error status`);
  assert.equal(get.headers['content-type'], 'application/json; charset=utf-8');
  assert.equal(typeof JSON.parse(get.body.toString('utf8')).error, 'string');
  if (error) assert.equal(JSON.parse(get.body.toString('utf8')).error, error);
  assertParity(get, head, target);
  // Error JSON may use transfer framing, rather than an explicit Content-Length.
  // If one is emitted it must describe the GET representation, never a HEAD body.
  if (get.headers['content-length'] !== undefined) assert.equal(Number(get.headers['content-length']), get.body.length);
  return get;
}

test('security fixture is a separate, deterministic byte-probe format, not browser evidence', () => {
  assert.equal(fixture.format, 'owa-security-probes-v1');
  assert.equal(fixture.profile, 'sandboxed-web-v1');
  assert.ok(fixture.notes.some(note => note.includes('Header assertions alone')));
  const ids = new Set();
  for (const probe of [...fixture.typeCases, ...fixture.pathCases, ...fixture.requestTargetCases]) {
    const group = Object.hasOwn(probe, 'sample') ? 'type' : Object.hasOwn(probe, 'rawPath') ? 'path' : 'target';
    assert.ok(!ids.has(`${group}:${probe.id}`));
    ids.add(`${group}:${probe.id}`);
  }
  for (const probe of fixture.typeCases) {
    assert.ok(fixture.samples[probe.sample]);
    assert.ok(['inline', 'attachment'].includes(probe.disposition));
  }
  for (const sample of Object.values(fixture.samples)) {
    assert.notEqual(Object.hasOwn(sample, 'text'), Object.hasOwn(sample, 'base64'));
    if (sample.base64) assert.equal(sampleBytes(sample).toString('base64'), sample.base64);
    for (const match of (sample.text ?? '').matchAll(/https:\/\/([^/'"\s<>]+)/g)) assert.ok(match[1].endsWith('.invalid'), 'probe URL is an inert .invalid destination');
  }
  assert.ok(fixture.samples.html.text.includes('window.open('));
  assert.ok(fixture.samples.html.text.includes('navigator.sendBeacon('));
  assert.ok(fixture.samples.html.text.includes('.submit()'));
  assert.ok(fixture.samples.html.text.includes('top.location.href='));
  for (const tag of ['<script', '<base', '<form', '<object', '<iframe']) assert.ok(fixture.samples.html.text.includes(tag));
});

test('HTTP header evidence only: exact MIME policy and unchanged adversarial bytes for every type', async t => {
  const artifact = typeArtifact();
  await withGateway(async env => {
    await seed(env, artifact);
    await preservingStoredBytes(env, [artifact], async () => {
      for (const probe of fixture.typeCases) await t.test(probe.id, async () => {
        await assertFile(env, probe.path, artifact, probe.path, probe.disposition);
      });
    });
  });
});

test('raw HTTP preserves the decode-once resolver contract before URL normalization, with and without SPA', async t => {
  await withGateway(async env => {
    const direct = makeArtifact(fixture.pathFiles);
    const spa = makeArtifact(fixture.pathFiles, { spa: true });
    await seed(env, direct, { slug: 'direct' });
    await seed(env, spa, { slug: 'spa' });
    await preservingStoredBytes(env, [direct, spa], async () => {
      for (const [slug, artifact] of [['direct', direct], ['spa', spa]]) {
        for (const probe of fixture.pathCases) await t.test(`${slug}: ${probe.id}`, async () => {
          const expected = probe.resolvedPath ?? (slug === 'spa' && !probe.unsafe ? '/index.html' : null);
          const headers = { host: `${slug}.localhost` };
          assert.equal(resolveRequestPath(artifact.manifest, probe.rawPath)?.path ?? null, expected, 'unchanged direct resolver expectation');
          if (expected === null) await assertErrorPair(env, probe.rawPath, 404, { headers, error: 'file not found' });
          else await assertFile(env, probe.rawPath, artifact, expected, 'inline', headers);
        });
      }
    });
  });
});

test('all 44 original portable request vectors replay unchanged as DIRECT resolver inputs', async t => {
  assert.equal(requestCorpus.vectors.length, 44);
  for (const vector of requestCorpus.vectors) await t.test(vector.id, () => {
    const before = canonicalJson(vector.input.manifest);
    validateManifest(vector.input.manifest);
    const actual = resolveRequestPath(vector.input.manifest, vector.input.urlPath);
    if (vector.expected.resolvedPath === null) assert.equal(actual, null);
    else assert.deepEqual(actual, vector.input.manifest.files.find(file => file.path === vector.expected.resolvedPath));
    assert.equal(canonicalJson(vector.input.manifest), before);
  });
  assert.deepEqual(await readFile(requestCorpusUrl), requestCorpusBytes, 'legacy corpus was not rewritten');
});

test('HTTP target framing, query selection, host selection, and baseline control dispatch', async t => {
  const artifact = makeArtifact(fixture.pathFiles, { spa: true });
  await withGateway(async env => {
    await seed(env, artifact);
    await preservingStoredBytes(env, [artifact], async () => {
      for (const probe of fixture.requestTargetCases) await t.test(probe.id, async () => {
        const response = await rawRequest(env, probe.target, { method: probe.method ?? 'GET' });
        assert.equal(response.status, probe.status);
        assertPolicy(response, probe.id);
      });
      await t.test('query is split, never included in resolver input', async () => {
        await assertFile(env, '/assets/x.js?site=security&ignored=%2e%2e', artifact, '/assets/x.js', 'inline', { host: 'localhost' });
      });
      await t.test('public query-site lookup remains available without authentication', async () => {
        await assertFile(env, '/?site=security', artifact, '/index.html', 'inline', { host: 'localhost' });
      });
      await t.test('host-site lookup retains precedence over query-site lookup', async () => {
        await assertFile(env, '/?site=not-present', artifact, '/index.html');
      });
      await t.test('query decoding is not a second artifact-path decoding pass', async () => {
        await assertFile(env, '/%252e%252e/secret?site=security', artifact, '/%2e%2e/secret', 'inline', { host: 'localhost' });
      });
      await t.test('health still dispatches using the baseline WHATWG pathname', async () => {
        const response = await rawRequest(env, '/discard/../health');
        assert.equal(response.status, 200);
        assert.deepEqual(JSON.parse(response.body.toString()), { ok: true, spec: 'owa.dev/v1' });
        assertPolicy(response);
      });
      await t.test('preflight gains neither CORS permissions nor authentication requirements', async () => {
        const response = await rawRequest(env, '/index.html', { method: 'OPTIONS', headers: { 'access-control-request-method': 'GET' } });
        assert.equal(response.status, 404);
        assertPolicy(response);
      });
    });
  });
});

test('gateway site selectors cannot traverse the filesystem metadata namespace', async () => {
  await withGateway(async env => {
    const { site } = await seed(env, makeArtifact(fixture.pathFiles));
    const getSite = env.metadata.getSite.bind(env.metadata); let lookups = 0;
    env.metadata.getSite = async slug => { lookups++; return getSite(slug); };
    for (const query of [`../sites/${site.id}/site`, `..%2Fsites%2F${site.id}%2Fsite`,
      `..%5Csites%5C${site.id}%5Csite`, '.', '..', '%00', 'security%00']) {
      await assertErrorPair(env, `/?site=${query}`, 404, {
        headers: { host: 'localhost' }, error: 'site or active release not found'
      });
    }
    for (const host of [`../sites/${site.id}/site.localhost`, '..localhost', '...localhost']) {
      await assertErrorPair(env, '/', 404, { headers: { host }, error: 'site or active release not found' });
    }
    assert.equal(lookups, 0, 'unsafe query/Host selectors are rejected before getSite, not after a filesystem read');
  });
});

test('gateway retains the auth boundary: Unicode and percent-looking selectors are rejected before metadata', async () => {
  const seen = [];
  const metadata = { async getSite(slug) { seen.push(slug); return null; } };
  await withGateway(async env => {
    await assertErrorPair(env, '/?site=%252e%252e%252fsafe', 404, { headers: { host: 'localhost' } });
    await assertErrorPair(env, '/?site=caf%C3%A9', 404, { headers: { host: 'localhost' } });
  }, { metadata });
  assert.deepEqual(seen, [], 'the stronger shared site-scope grammar must not be broadened by the profile');
});

test('GET/HEAD errors 404, 410 and 500 receive the SAME profile and no-store baseline', async t => {
  await withGateway(async env => {
    const normal = makeArtifact(fixture.pathFiles);
    const expired = makeArtifact(fixture.pathFiles, { expiresAt: '2000-01-01T00:00:00Z' });
    const missingBlob = makeArtifact([{ path: '/index.html', text: 'deliberately unstored blob\n', mediaType: 'text/html' }]);
    await seed(env, normal);
    await seed(env, expired, { slug: 'expired' });
    await seed(env, missingBlob, { slug: 'broken', storeBlobs: false });
    const before = await snapshotTree(env.root);
    try {
      for (const probe of [
        { id: 'unresolved-file', target: '/missing', status: 404 },
        { id: 'unknown-site', target: '/?site=unknown', status: 404, headers: { host: 'localhost' } },
        { id: 'no-site-selector', target: '/', status: 404, headers: { host: 'localhost' } },
        { id: 'expired-artifact', target: '/', status: 410, headers: { host: 'expired.localhost' } },
        { id: 'missing-storage-blob', target: '/', status: 500, headers: { host: 'broken.localhost' } }
      ]) await t.test(probe.id, () => assertErrorPair(env, probe.target, probe.status, { headers: probe.headers }));
    } finally {
      assert.deepEqual(await snapshotTree(env.root), before, 'error responses do not mutate storage');
    }
  });
});

test('explicit loopback dev health and plan/upload/commit/activate/list responses all carry policy', async t => {
  const artifact = makeArtifact([
    { path: '/index.html', ...fixture.samples.html },
    { path: '/probe.js', ...fixture.samples.javascript }
  ], { visibility: 'unlisted' });
  const originalManifest = structuredClone(artifact.manifest);
  await withGateway(async env => {
    const health = await rawRequest(env, '/health', { headers: { host: 'localhost' } });
    assert.equal(health.status, 200);
    assertPolicy(health, 'health');
    const planBody = { manifest: artifact.manifest, artifactDigest: artifact.artifactDigest };
    // The legacy tokenless flow opts into loopback dev explicitly; required mode stays fail-closed.
    const planResponse = await jsonRequest(env, '/v1/sites/security/publish/plan', planBody);
    assert.equal(planResponse.status, 200);
    assertPolicy(planResponse, 'plan');
    const plan = JSON.parse(planResponse.body.toString());
    assert.equal(plan.artifactDigest, artifact.artifactDigest);
    assert.equal(plan.uploads.length, 2);
    assert.equal(plan.reused, 0);
    for (const upload of plan.uploads) {
      assert.equal(upload.method, 'PUT');
      // Parse only a server-generated control URL; never normalize a test path.
      // Ignore its host and keep every network connection pinned to loopback.
      const parsed = new URL(upload.url);
      const target = `${parsed.pathname}${parsed.search}`;
      await t.test(`signed upload errors and 204: ${upload.digest}`, async () => {
        const badSignature = await rawRequest(env, `${parsed.pathname}?expires=4102444800&sig=bad`, { method: 'PUT', body: artifact.blobs.get(upload.digest) });
        assert.equal(badSignature.status, 403);
        assertPolicy(badSignature, 'bad upload signature');
        const expired = await rawRequest(env, `${parsed.pathname}?expires=1&sig=bad`, { method: 'PUT', body: artifact.blobs.get(upload.digest) });
        assert.equal(expired.status, 403);
        assertPolicy(expired, 'expired upload');
        const mismatch = await rawRequest(env, target, { method: 'PUT', body: 'fixed mismatching content' });
        assert.equal(mismatch.status, 400);
        assertPolicy(mismatch, 'upload digest mismatch');
        const put = await rawRequest(env, target, { method: 'PUT', body: artifact.blobs.get(upload.digest) });
        assert.equal(put.status, 204);
        assert.equal(put.body.length, 0);
        assertPolicy(put, 'successful empty upload response');
      });
    }
    const commitResponse = await jsonRequest(env, '/v1/sites/security/publish/commit', { ...planBody, activate: true });
    assert.equal(commitResponse.status, 201);
    assertPolicy(commitResponse, 'commit');
    const commit = JSON.parse(commitResponse.body.toString());
    assert.equal(commit.artifactDigest, artifact.artifactDigest);
    assert.equal(commit.activeReleaseId, commit.releaseId);
    const list = await rawRequest(env, '/v1/sites/security/releases');
    assert.equal(list.status, 200);
    assertPolicy(list, 'releases');
    const listed = JSON.parse(list.body.toString());
    assert.deepEqual(listed.releases[0].manifest, originalManifest);
    assert.equal(listed.releases[0].artifactDigest, artifact.artifactDigest);
    const activate = await jsonRequest(env, `/v1/sites/security/activate/${commit.releaseId}`, {});
    assert.equal(activate.status, 200);
    assertPolicy(activate, 'activate');
    const secondPlan = await jsonRequest(env, '/v1/sites/security/publish/plan', planBody);
    assert.equal(secondPlan.status, 200);
    assertPolicy(secondPlan, 'reused plan');
    assert.equal(JSON.parse(secondPlan.body.toString()).reused, 2);
    assert.deepEqual(JSON.parse(secondPlan.body.toString()).uploads, []);
    await preservingStoredBytes(env, [artifact], async () => {
      await assertFile(env, '/', artifact, '/index.html');
      await assertFile(env, '/probe.js', artifact, '/probe.js');
    });
    await t.test('plan digest mismatch remains 400 with policy', async () => {
      const response = await jsonRequest(env, '/v1/sites/security/publish/plan', { ...planBody, artifactDigest: `sha256:${'0'.repeat(64)}` });
      assert.equal(response.status, 400);
      assertPolicy(response);
    });
    await t.test('baseline invalid-JSON and invalid-manifest errors remain 500 with policy', async () => {
      for (const body of ['{', '{}']) {
        const response = await rawRequest(env, '/v1/sites/security/publish/plan', { method: 'POST', body, headers: { 'content-type': 'application/json' } });
        assert.equal(response.status, 500);
        assertPolicy(response);
      }
    });
    await t.test('raw publish body rejects an overwritten duplicate before planning', async () => {
      const body = JSON.stringify(planBody).replace('"manifest":{', '"manifest":{"specVersion":"decoy",');
      assert.notEqual(body, JSON.stringify(planBody));
      const response = await rawRequest(env, '/v1/sites/security/publish/plan', { method: 'POST', body, headers: { 'content-type': 'application/json' } });
      assert.equal(response.status, 500); // Existing fixed-shape operation error for raw body failures.
      assertPolicy(response);
      assert.equal(JSON.parse(response.body.toString()).code, 'OWA_OPERATION_FAILED');
    });
    await t.test('missing release-list site remains 404 with policy', async () => {
      const response = await rawRequest(env, '/v1/sites/unknown/releases');
      assert.equal(response.status, 404);
      assertPolicy(response);
    });
    assert.deepEqual(artifact.manifest, originalManifest);
    assert.equal(artifactDigest(artifact.manifest), artifact.artifactDigest);
  });
});

function deepFreeze(value) {
  if (value && typeof value === 'object') {
    Object.freeze(value);
    for (const child of Object.values(value)) deepFreeze(child);
  }
  return value;
}

test('no-store prevents a compliant cache from hiding active-release, visibility, and availability changes', async () => {
  // Minimal per-test metadata selector, not an authentication system/stub. All
  // immutable release records exist before serving; only the site pointer and
  // whether getSite returns a record change. Public AND unlisted are readable.
  const publicA = makeArtifact([{ path: '/index.html', text: '<h1>same bytes</h1>\n', mediaType: 'text/html' }]);
  const unlistedB = makeArtifact([{ path: '/index.html', text: '<h1>same bytes</h1>\n', mediaType: 'text/html' }], { visibility: 'unlisted' });
  const publicC = makeArtifact([{ path: '/index.html', text: '<h1>new activation</h1>\n', mediaType: 'text/html' }]);
  const artifacts = [publicA, unlistedB, publicC];
  const releaseId = index => `r_${String(index).padStart(20, '0')}`;
  const siteId = `s_${'c'.repeat(20)}`;
  const releases = new Map(artifacts.map((artifact, index) => [releaseId(index), deepFreeze({
    id: releaseId(index), artifactDigest: artifact.artifactDigest, manifest: artifact.manifest, createdAt: FIXED_TIME
  })]));
  const before = [...releases.values()].map(release => canonicalJson(release));
  assert.notEqual(publicA.artifactDigest, unlistedB.artifactDigest, 'visibility belongs to a different immutable manifest');
  assert.equal(publicA.manifest.files[0].digest, unlistedB.manifest.files[0].digest, 'unchanged bytes deliberately share an ETag');
  let activeReleaseId = releaseId(0), siteAvailable = true, metadataReads = 0;
  const metadata = {
    async getSite(slug) {
      metadataReads++;
      return siteAvailable && slug === 'security' ? { id: siteId, slug, activeReleaseId, createdAt: FIXED_TIME } : null;
    },
    async getRelease(requestedSiteId, requestedReleaseId) { return requestedSiteId === siteId ? releases.get(requestedReleaseId) ?? null : null; }
  };
  await withGateway(async env => {
    for (const artifact of artifacts) for (const [hash, bytes] of artifact.blobs) await env.blobs.put(hash, bytes);
    await preservingStoredBytes(env, artifacts, async () => {
      const cache = new Map();
      let networkRequests = 0;
      async function compliantCacheGet(headers = {}) {
        const key = 'GET /';
        if (cache.has(key)) return cache.get(key);
        networkRequests++;
        const response = await rawRequest(env, '/', { headers });
        // Intentionally minimal demonstration: retain only if no-store is absent.
        // It models compliant storage, not a full cache or browser enforcement.
        if (!(response.headers['cache-control'] ?? '').split(',').some(token => token.trim().toLowerCase() === 'no-store')) cache.set(key, response);
        return response;
      }
      const first = await compliantCacheGet();
      assert.equal(first.status, 200);
      assertPolicy(first, 'public A');
      assert.deepEqual(first.body, publicA.blobs.get(publicA.manifest.files[0].digest));
      activeReleaseId = releaseId(1);
      const second = await compliantCacheGet({ 'if-none-match': first.headers.etag });
      assert.equal(second.status, 200, 'unlisted remains public-by-URL; conditional request is not 304');
      assertPolicy(second, 'unlisted B');
      assert.equal(second.headers.etag, first.headers.etag);
      assert.equal(networkRequests, 2, 'same-byte visibility transition must reach server');
      activeReleaseId = releaseId(2);
      const third = await compliantCacheGet({ 'if-none-match': first.headers.etag, 'if-modified-since': 'Fri, 01 Jan 2100 00:00:00 GMT' });
      assert.equal(third.status, 200);
      assertPolicy(third, 'public C');
      assert.deepEqual(third.body, publicC.blobs.get(publicC.manifest.files[0].digest));
      assert.notEqual(third.headers.etag, first.headers.etag);
      const conditionalHead = await rawRequest(env, '/', { method: 'HEAD', headers: { 'if-none-match': third.headers.etag } });
      assertParity(third, conditionalHead, 'conditional active-release HEAD');
      siteAvailable = false;
      const denied = await compliantCacheGet({ 'if-none-match': third.headers.etag });
      assert.equal(denied.status, 404, 'null metadata decision is observed, not a cached former success');
      assertPolicy(denied, 'no site available');
      assert.equal(JSON.parse(denied.body.toString()).error, 'site or active release not found');
      const deniedHead = await rawRequest(env, '/', { method: 'HEAD', headers: { 'if-none-match': '*' } });
      assertParity(denied, deniedHead, 'unavailable HEAD');
      assert.equal(networkRequests, 4);
      assert.equal(metadataReads, 6, 'each GET and HEAD rechecks metadata');
      assert.equal(cache.size, 0, 'no success or denial stored');
    });
  }, { metadata });
  assert.deepEqual([...releases.values()].map(release => canonicalJson(release)), before, 'no immutable release, manifest, or digest changed');
});
