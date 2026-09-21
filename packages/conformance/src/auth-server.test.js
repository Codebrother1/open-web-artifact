import test from 'node:test';
import assert from 'node:assert/strict';
import { createHmac } from 'node:crypto';
import { once } from 'node:events';
import { request as httpRequest } from 'node:http';
import { mkdtemp, readdir, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createArtifactServer } from '../../server/src/index.js';
import { AuthError, CAPABILITIES, createToken } from '../../server/src/auth.js';
import { FilesystemBlobStore, FilesystemMetadataStore } from '../../storage-filesystem/src/index.js';
import { S3BlobStore } from '../../storage-s3/src/index.js';
import { artifactDigest, OWA_MEDIA_TYPE, OWA_SPEC_VERSION, sha256 } from '../../spec/src/index.js';

// Fixed synthetic credentials are generated only in memory. Never print tokens,
// presigned URLs, request objects, or response diffs that could contain credentials.
// Ports and temporary directories are resources, not security test inputs.
const SECRET = Buffer.alloc(32, 0x51);
const UPLOAD_SECRET = Buffer.alloc(32, 0x72);
const NOW = 2000000000;
const JTI = 'http-audit-001';
const RELEASE = `r_${'a'.repeat(20)}`;
const BYTES = Buffer.from('<h1>fixed HTTP fixture</h1>');
const DIGEST = sha256(BYTES);
const messages = {
  OWA_AUTH_MISSING: 'Authentication required',
  OWA_AUTH_INVALID_TOKEN: 'Invalid authentication token',
  OWA_AUTH_INVALID_SIGNATURE: 'Invalid authentication signature',
  OWA_AUTH_EXPIRED: 'Authentication token expired',
  OWA_AUTH_SITE: 'Authentication does not permit this site',
  OWA_AUTH_CAPABILITY: 'Authentication does not permit this operation',
  OWA_AUTH_DEV_ONLY: 'Development authentication requires a direct loopback connection'
};

function manifest({ duplicate = false, spa = false } = {}) {
  const file = { path: '/index.html', digest: DIGEST, size: BYTES.length, mediaType: 'text/html; charset=utf-8' };
  return {
    specVersion: OWA_SPEC_VERSION, artifactType: OWA_MEDIA_TYPE, entrypoint: '/index.html',
    files: duplicate ? [file, { ...file, path: '/copy.html' }] : [file],
    ...(spa ? { routing: { spaFallback: '/index.html' } } : {}),
    access: { visibility: 'unlisted' }, lifecycle: { expiresAt: null },
    annotations: { fixture: 'manifest-only-marker' }
  };
}

function mint(capabilities = [...CAPABILITIES], overrides = {}) {
  return createToken({ secret: SECRET, jti: JTI, exp: NOW + 1200, sites: ['demo'], capabilities, now: () => NOW, ...overrides });
}

function memoryStores() {
  const data = new Map(), sites = new Map(), releases = new Map(), calls = [];
  const blobs = {
    async has(digest) { calls.push('has'); return data.has(digest); },
    async put(digest, bytes) { calls.push('put'); data.set(digest, Buffer.from(bytes)); },
    async get(digest) { calls.push('get'); return data.get(digest); }
  };
  const metadata = {
    async getSite(slug) { calls.push('getSite'); return structuredClone(sites.get(slug) ?? null); },
    async createSite(slug) {
      calls.push('createSite');
      const site = { id: `s_${String(sites.size + 1).padStart(20, '0')}`, slug, activeReleaseId: null, createdAt: new Date(NOW * 1000).toISOString() };
      sites.set(slug, structuredClone(site)); return site;
    },
    async saveSite(site) { calls.push('saveSite'); sites.set(site.slug, structuredClone(site)); },
    async saveRelease(siteId, release) { calls.push('saveRelease'); releases.set(`${siteId}/${release.id}`, structuredClone(release)); },
    async getRelease(siteId, releaseId) { calls.push('getRelease'); return structuredClone(releases.get(`${siteId}/${releaseId}`) ?? null); },
    async listReleases(siteId) {
      calls.push('listReleases');
      return [...releases.entries()].filter(([key]) => key.startsWith(`${siteId}/`)).map(([, value]) => structuredClone(value));
    }
  };
  return { blobs, metadata, data, sites, releases, calls };
}

async function fixture(t, { filesystem = false, stores = memoryStores(), mode = 'required', audit = null } = {}) {
  let root = null;
  if (filesystem) {
    root = await mkdtemp(join(tmpdir(), 'owa-auth-http-'));
    stores = { blobs: new FilesystemBlobStore(root), metadata: new FilesystemMetadataStore(root) };
  }
  const clock = { value: NOW };
  let server;
  t.after(async () => {
    if (server?.listening) {
      const closed = once(server, 'close');
      server.close(); server.closeAllConnections(); await closed;
    }
    if (root) await rm(root, { recursive: true, force: true });
  });
  server = createArtifactServer({ ...stores, uploadSecret: UPLOAD_SECRET, auth: { mode, secret: SECRET, now: () => clock.value }, audit });
  server.listen(0, '127.0.0.1'); await once(server, 'listening');
  return { ...stores, root, clock, server, base: `http://127.0.0.1:${server.address().port}` };
}

// Only local HTTP is allowed. Fixed error labels also prevent client diagnostics
// from accidentally serializing Authorization headers or signed query strings.
function send(f, path, { method = 'GET', token, json, bytes, headers = {}, rawHeaders, afterFirstChunk } = {}) {
  let url;
  try { url = new URL(path, f.base); } catch { throw new Error('Invalid local HTTP target'); }
  assert.ok(url.origin === f.base, 'HTTP fixtures never contact an external provider');
  const payload = json !== undefined ? Buffer.from(JSON.stringify(json)) : (bytes ?? Buffer.alloc(0));
  const requestHeaders = rawHeaders ?? {
    connection: 'close', ...(token === undefined ? {} : { authorization: `Bearer ${token}` }),
    ...(json === undefined ? {} : { 'content-type': 'application/json' }),
    ...(method === 'GET' || method === 'HEAD' ? {} : { 'content-length': String(payload.length) }), ...headers
  };
  return new Promise((resolve, reject) => {
    const req = httpRequest(url, { method, headers: requestHeaders, agent: false }, res => {
      const chunks = [];
      res.on('error', () => reject(new Error('HTTP response failed')));
      res.on('data', chunk => chunks.push(chunk));
      res.on('end', () => {
        const text = Buffer.concat(chunks).toString('utf8');
        let body = null;
        if (text && res.headers['content-type']?.startsWith('application/json')) {
          try { body = JSON.parse(text); } catch { reject(new Error('Invalid HTTP JSON response')); return; }
        }
        resolve({ status: res.statusCode, headers: res.headers, text, body });
      });
    });
    req.on('error', () => reject(new Error('HTTP request failed')));
    req.setTimeout(5000, () => req.destroy());
    if (afterFirstChunk) {
      // A server-side data event proves early authorization passed and the body
      // is being read. Advance only the injected clock, without timing sleeps.
      f.server.once('request', incoming => incoming.once('data', () => {
        afterFirstChunk(); req.end(payload.subarray(1));
      }));
      req.write(payload.subarray(0, 1));
    } else req.end(payload);
  });
}

function expectAuth(response, code, status = 401) {
  assert.equal(response.status, status, 'HTTP auth status');
  assert.ok(JSON.stringify(response.body) === JSON.stringify({ error: messages[code], code }), 'fixed auth error envelope');
  assert.ok(response.headers['cache-control'] === 'no-store', 'auth response is not cacheable');
  assert.ok(status !== 401 || response.headers['www-authenticate'] === 'Bearer realm="owa"', '401 includes Bearer challenge');
  assert.ok(status === 401 || response.headers['www-authenticate'] === undefined, '403 is not a token challenge');
}

function expectOperationFailure(response, missingBlob = false) {
  assert.equal(response.status, 500, 'HTTP operation status');
  const expected = missingBlob ? { error: 'Missing blob', code: 'OWA_BLOB_MISSING' } : { error: 'Operation failed', code: 'OWA_OPERATION_FAILED' };
  assert.ok(JSON.stringify(response.body) === JSON.stringify(expected), 'fixed operation error envelope');
}

function expectUploadFailure(response, status = 403, code = 'OWA_UPLOAD_INVALID') {
  assert.equal(response.status, status, 'HTTP upload rejection status');
  assert.ok(response.body?.code === code, 'fixed upload rejection code');
}

async function plan(f, token = mint(['plan', 'upload']), value = manifest(), site = 'demo') {
  const result = await send(f, `/v1/sites/${site}/publish/plan`, { method: 'POST', token, json: { manifest: value, artifactDigest: artifactDigest(value) } });
  assert.equal(result.status, 200, 'plan succeeds');
  return result.body;
}

async function grant(f, token = mint(['plan', 'upload'])) {
  const result = await plan(f, token);
  assert.equal(result.uploads.length, 1, 'one grant for one missing digest');
  return result.uploads[0];
}

async function seed(f, slug = 'demo', value = manifest()) {
  await f.blobs.put(DIGEST, BYTES);
  const site = await f.metadata.createSite(slug);
  const release = { id: RELEASE, artifactDigest: artifactDigest(value), createdAt: new Date(NOW * 1000).toISOString(), manifest: value };
  await f.metadata.saveRelease(site.id, release);
  site.activeReleaseId = RELEASE; await f.metadata.saveSite(site);
  return { site, release };
}

function changedUrl(upload, edit) {
  const url = new URL(upload.url); edit(url.searchParams); return url.toString();
}

const controlRoutes = [
  ['plan', 'POST', '/v1/sites/demo/publish/plan'],
  ['commit', 'POST', '/v1/sites/demo/publish/commit'],
  ['activate', 'POST', `/v1/sites/demo/activate/${RELEASE}`],
  ['read', 'GET', '/v1/sites/demo/releases']
];

test('server construction defaults to required auth and fails closed without a valid secret', () => {
  for (const auth of [undefined, {}, { mode: 'required' }, { mode: 'required', secret: Buffer.alloc(31) }, { mode: 'disabled', secret: SECRET }]) {
    let error;
    try { createArtifactServer({ ...memoryStores(), ...(auth === undefined ? {} : { auth }) }); } catch (caught) { error = caught; }
    assert.ok(error instanceof AuthError && error.code === 'OWA_AUTH_CONFIG', 'startup rejects invalid auth configuration');
  }
  for (const uploadSecret of [SECRET, Buffer.alloc(31)]) {
    let error;
    try { createArtifactServer({ ...memoryStores(), uploadSecret, auth: { secret: SECRET, now: () => NOW } }); } catch (caught) { error = caught; }
    assert.ok(error instanceof AuthError && error.code === 'OWA_AUTH_CONFIG', 'local grants need an independent strong key');
  }
});

for (const [operation, method, path] of controlRoutes) {
  test(`HTTP ${operation} requires auth before storage or body validation`, async t => {
    const f = await fixture(t);
    expectAuth(await send(f, path, { method, ...(method === 'POST' ? { bytes: Buffer.from('{') } : {}) }), 'OWA_AUTH_MISSING');
    assert.equal(f.calls.length, 0, 'denied request does not touch stores');
  });

  test(`HTTP ${operation} rejects cross-site credentials before storage`, async t => {
    const f = await fixture(t);
    expectAuth(await send(f, path.replace('/demo/', '/other/'), { method, token: mint(), json: method === 'POST' ? {} : undefined }), 'OWA_AUTH_SITE', 403);
    assert.equal(f.calls.length, 0, 'cross-site request does not touch stores');
  });
}

for (const [label, credential, code] of [
  ['expired at the exact expiry boundary', () => mint(['plan'], { exp: NOW, now: () => NOW - 1 }), 'OWA_AUTH_EXPIRED'],
  ['tampered signature', () => { const parts = mint(['plan']).split('.'); const mac = Buffer.from(parts[2], 'base64url'); mac[0] ^= 1; parts[2] = mac.toString('base64url'); return parts.join('.'); }, 'OWA_AUTH_INVALID_SIGNATURE'],
  ['malformed wire token', () => 'not-a-token', 'OWA_AUTH_INVALID_TOKEN']
]) {
  test(`HTTP rejects ${label} with fixed 401 errors`, async t => {
    const f = await fixture(t);
    expectAuth(await send(f, '/v1/sites/demo/publish/plan', { method: 'POST', token: credential(), json: { manifest: manifest() } }), code);
    assert.equal(f.calls.length, 0, 'invalid bearer does not touch stores');
  });
}

test('HTTP rejects ambiguous and non-Bearer Authorization headers', async t => {
  const f = await fixture(t), token = mint();
  for (const value of [`Basic ${token}`, `Bearer ${token}, Bearer ${token}`, `Bearer  ${token}`]) {
    expectAuth(await send(f, '/v1/sites/demo/releases', { headers: { authorization: value } }), 'OWA_AUTH_INVALID_TOKEN');
  }
  expectAuth(await send(f, '/v1/sites/demo/releases', { rawHeaders: ['Host', 'localhost', 'Connection', 'close', 'Authorization', `Bearer ${token}`, 'authorization', `Bearer ${token}`] }), 'OWA_AUTH_INVALID_TOKEN');
  assert.equal(f.calls.length, 0, 'ambiguous headers do not reach metadata');
});

for (const [operation, method, path] of controlRoutes.filter(([operation]) => operation !== 'read')) {
  test(`read-only credentials cannot ${operation}`, async t => {
    const f = await fixture(t);
    expectAuth(await send(f, path, { method, token: mint(['read']), json: {} }), 'OWA_AUTH_CAPABILITY', 403);
    assert.equal(f.calls.length, 0, 'read-only mutation denied before storage');
  });
}

test('plan-only can deduplicate existing blobs but cannot mint a missing-blob upload', async t => {
  const f = await fixture(t);
  expectAuth(await send(f, '/v1/sites/demo/publish/plan', { method: 'POST', token: mint(['plan']), json: { manifest: manifest() } }), 'OWA_AUTH_CAPABILITY', 403);
  assert.ok(!f.calls.includes('put'), 'grant denial never writes a blob');
  await f.blobs.put(DIGEST, BYTES);
  const result = await plan(f, mint(['plan']), manifest({ duplicate: true }));
  assert.equal(result.reused, 1, 'duplicate file digests count once');
  assert.equal(result.uploads.length, 0, 'deduplicated plan needs no upload grant');
});

test('upload permission does not imply plan permission and plan does not imply commit', async t => {
  const f = await fixture(t);
  expectAuth(await send(f, '/v1/sites/demo/publish/plan', { method: 'POST', token: mint(['upload']), json: { manifest: manifest() } }), 'OWA_AUTH_CAPABILITY', 403);
  expectAuth(await send(f, '/v1/sites/demo/publish/commit', { method: 'POST', token: mint(['plan']), json: {} }), 'OWA_AUTH_CAPABILITY', 403);
  assert.equal(f.calls.length, 0, 'independent capability checks precede storage');
});

test('commit-only cannot use default or non-literal-false activation, even with an empty body', async t => {
  const f = await fixture(t);
  for (const body of [{}, { manifest: manifest() }, ...[true, null, 0, '', 'false'].map(activate => ({ manifest: manifest(), activate }))]) {
    expectAuth(await send(f, '/v1/sites/demo/publish/commit', { method: 'POST', token: mint(['commit']), json: body }), 'OWA_AUTH_CAPABILITY', 403);
  }
  assert.equal(f.calls.length, 0, 'activation denial occurs before any metadata or blob access');
  assert.equal(f.sites.size, 0, 'denied commit creates no site');
  assert.equal(f.releases.size, 0, 'denied commit creates no release');
});

test('literal activate false allows commit-only; activation is separately authorized', async t => {
  const f = await fixture(t); await f.blobs.put(DIGEST, BYTES);
  const value = manifest();
  const committed = await send(f, '/v1/sites/demo/publish/commit', { method: 'POST', token: mint(['commit']), json: { manifest: value, artifactDigest: artifactDigest(value), activate: false } });
  assert.equal(committed.status, 201, 'commit-only creates an inactive release');
  assert.ok(/^r_[0-9a-f]{20}$/.test(committed.body?.releaseId), 'core release ID uses safe grammar');
  assert.ok(committed.body.activeReleaseId === null, 'commit remains inactive');
  assert.ok(committed.body.artifactDigest === artifactDigest(value), 'artifact identity is unchanged');
  const path = `/v1/sites/demo/activate/${committed.body.releaseId}`;
  expectAuth(await send(f, path, { method: 'POST', token: mint(['commit']) }), 'OWA_AUTH_CAPABILITY', 403);
  const activated = await send(f, path, { method: 'POST', token: mint(['activate']) });
  assert.equal(activated.status, 200, 'activate-only credential can activate');
  assert.ok(activated.body.activeReleaseId === committed.body.releaseId, 'selected release becomes active');
});

test('commit plus activate retains default activation; missing blobs use a fixed redacted error', async t => {
  const f = await fixture(t), token = mint(['commit', 'activate']);
  const body = { manifest: manifest() };
  expectOperationFailure(await send(f, '/v1/sites/demo/publish/commit', { method: 'POST', token, json: body }), true);
  assert.equal(f.sites.size, 0, 'missing blob cannot create metadata');
  await f.blobs.put(DIGEST, BYTES);
  const result = await send(f, '/v1/sites/demo/publish/commit', { method: 'POST', token, json: body });
  assert.equal(result.status, 201, 'default-activating commit succeeds');
  assert.ok(result.body.activeReleaseId === result.body.releaseId, 'activation remains the default');
});

test('read returns full inspection metadata and honors multi-site and no-read scopes', async t => {
  const f = await fixture(t); const demo = await seed(f); const other = await seed(f, 'other');
  const token = mint(['read'], { sites: ['demo', 'other'] });
  for (const { site, release } of [demo, other]) {
    const result = await send(f, `/v1/sites/${site.slug}/releases`, { token });
    assert.equal(result.status, 200, 'multi-site read succeeds');
    assert.ok(JSON.stringify(result.body.site) === JSON.stringify(site), 'inspection contains the site metadata');
    assert.ok(JSON.stringify(result.body.releases) === JSON.stringify([release]), 'inspection contains complete release manifests');
  }
  expectAuth(await send(f, '/v1/sites/third/releases', { token }), 'OWA_AUTH_SITE', 403);
  expectAuth(await send(f, '/v1/sites/demo/releases', { token: mint(['plan', 'upload', 'commit', 'activate']) }), 'OWA_AUTH_CAPABILITY', 403);
  const absent = await send(f, '/v1/sites/absent/releases', { token: mint(['read'], { sites: ['absent'] }) });
  assert.equal(absent.status, 404, 'authorized absent site remains a 404');
});

test('filesystem grants bind site and HMAC, advertise bearer, and clamp expiry', async t => {
  const f = await fixture(t, { filesystem: true });
  const upload = await grant(f, mint(['plan', 'upload'], { exp: NOW + 37 }));
  const url = new URL(upload.url);
  assert.ok(upload.authorization === 'bearer' && upload.method === 'PUT' && upload.digest === DIGEST, 'local upload contract');
  assert.equal(upload.expiresIn, 37, 'grant TTL does not exceed token lifetime');
  assert.ok(url.searchParams.get('site') === 'demo', 'grant is site scoped');
  assert.ok(url.searchParams.get('expires') === String(NOW + 37), 'grant has exact fixed expiry');
  const expected = createHmac('sha256', UPLOAD_SECRET).update(`owa-upload-v1\ndemo\n${DIGEST}\n${NOW + 37}`).digest('hex');
  assert.ok(url.searchParams.get('sig') === expected, 'site participates in the independent storage signature');
  const uploaded = await send(f, upload.url, { method: 'PUT', token: mint(['upload']), bytes: BYTES });
  assert.equal(uploaded.status, 204, 'upload-only bearer plus valid grant succeeds');
  assert.ok(Buffer.from(await f.blobs.get(DIGEST)).equals(BYTES), 'stored blob bytes match');
});

for (const [label, getToken, code, status] of [
  ['missing bearer', () => undefined, 'OWA_AUTH_MISSING', 401],
  ['wrong site', () => mint(['upload'], { sites: ['other'] }), 'OWA_AUTH_SITE', 403],
  ['plan-only bearer', () => mint(['plan']), 'OWA_AUTH_CAPABILITY', 403],
  ['read-only bearer', () => mint(['read']), 'OWA_AUTH_CAPABILITY', 403],
  ['expired bearer', () => mint(['upload'], { exp: NOW, now: () => NOW - 1 }), 'OWA_AUTH_EXPIRED', 401]
]) {
  test(`filesystem PUT rejects ${label} despite a valid storage signature`, async t => {
    const f = await fixture(t, { filesystem: true }), upload = await grant(f);
    expectAuth(await send(f, upload.url, { method: 'PUT', token: getToken(), bytes: BYTES }), code, status);
    assert.ok(!(await f.blobs.has(DIGEST)), 'denied PUT writes no blob');
  });
}

for (const [label, edit, status, code] of [
  ['signature tamper', p => p.set('sig', '0'.repeat(64)), 403, 'OWA_UPLOAD_INVALID'],
  ['site query tamper', p => p.set('site', 'other'), 403, 'OWA_UPLOAD_INVALID'],
  ['duplicate site', p => p.append('site', 'demo'), 400, 'OWA_INVALID_SITE'],
  ['duplicate signature', p => p.append('sig', p.get('sig')), 403, 'OWA_UPLOAD_INVALID'],
  ['duplicate expiry', p => p.append('expires', p.get('expires')), 403, 'OWA_UPLOAD_INVALID'],
  ['missing signature', p => p.delete('sig'), 403, 'OWA_UPLOAD_INVALID'],
  ['missing expiry', p => p.delete('expires'), 403, 'OWA_UPLOAD_INVALID'],
  ['unscoped URL', p => p.delete('site'), 400, 'OWA_INVALID_SITE']
]) {
  test(`filesystem PUT rejects ${label} despite an authorized bearer`, async t => {
    const f = await fixture(t, { filesystem: true }), upload = await grant(f);
    const response = await send(f, changedUrl(upload, edit), { method: 'PUT', token: mint(['upload'], { sites: ['demo', 'other'] }), bytes: BYTES });
    expectUploadFailure(response, status, code);
    assert.ok(!(await f.blobs.has(DIGEST)), 'invalid grant writes no blob');
  });
}

test('legacy unscoped local signature cannot be upgraded by appending a site in required mode', async t => {
  const f = await fixture(t), expires = NOW + 900;
  const sig = createHmac('sha256', UPLOAD_SECRET).update(`${DIGEST}\n${expires}`).digest('hex');
  const path = `/v1/uploads/${encodeURIComponent(DIGEST)}?expires=${expires}&sig=${sig}`;
  expectUploadFailure(await send(f, path, { method: 'PUT', token: mint(['upload']), bytes: BYTES }), 400, 'OWA_INVALID_SITE');
  expectUploadFailure(await send(f, `${path}&site=demo`, { method: 'PUT', token: mint(['upload']), bytes: BYTES }));
  assert.ok(!f.calls.includes('put'), 'legacy signature writes no blob in required mode');
});

test('expired local grant is denied even when the upload bearer is still valid', async t => {
  const f = await fixture(t), upload = await grant(f, mint(['plan', 'upload'], { exp: NOW + 20 }));
  f.clock.value = NOW + 20;
  expectUploadFailure(await send(f, upload.url, { method: 'PUT', token: mint(['upload']), bytes: BYTES }));
  assert.ok(!f.calls.includes('put'), 'expired grant writes no blob');
});

for (const [label, token, advanced, authExpiry] of [
  ['bearer expiry', () => mint(['upload'], { exp: NOW + 10 }), NOW + 10, true],
  ['grant expiry', () => mint(['upload']), NOW + 900, false]
]) {
  test(`PUT rechecks ${label} after receiving a slow body`, async t => {
    const f = await fixture(t), upload = await grant(f);
    const result = await send(f, upload.url, { method: 'PUT', token: token(), bytes: BYTES, afterFirstChunk: () => { f.clock.value = advanced; } });
    if (authExpiry) expectAuth(result, 'OWA_AUTH_EXPIRED'); else expectUploadFailure(result);
    assert.ok(!f.calls.includes('put'), 'expiry during body receipt writes no blob');
  });
}

for (const storage of ['local', 's3']) {
  test(`${storage} rechecks token expiry after asynchronous blob existence checks before minting`, async t => {
    const f = await fixture(t); let grants = 0;
    f.blobs.has = async () => { await Promise.resolve(); f.clock.value = NOW + 10; return false; };
    if (storage === 's3') f.blobs.createUpload = async () => { grants++; return {}; };
    expectAuth(await send(f, '/v1/sites/demo/publish/plan', { method: 'POST', token: mint(['plan', 'upload'], { exp: NOW + 10 }), json: { manifest: manifest() } }), 'OWA_AUTH_EXPIRED');
    assert.equal(grants, 0, 'expired token never reaches provider grant factory');
    assert.ok(!f.calls.includes('put'), 'expired plan writes no blob');
  });
}

test('deduplicated plan rejects expiry during body receipt before any existence lookup', async t => {
  const audits = [];
  const f = await fixture(t, { audit: event => audits.push(event) });
  await f.blobs.put(DIGEST, BYTES); f.calls.length = 0;
  const result = await send(f, '/v1/sites/demo/publish/plan', {
    method: 'POST', token: mint(['plan'], { exp: NOW + 10 }), json: { manifest: manifest() },
    afterFirstChunk: () => { f.clock.value = NOW + 10; }
  });
  expectAuth(result, 'OWA_AUTH_EXPIRED');
  assert.equal(f.calls.length, 0, 'expired slow body reaches no storage');
  assert.equal(audits.length, 0, 'expired plan emits no success audit');
});

test('deduplicated plan rechecks expiry after asynchronous existence lookups', async t => {
  const audits = [];
  const f = await fixture(t, { audit: event => audits.push(event) });
  f.blobs.has = async () => { await Promise.resolve(); f.clock.value = NOW + 10; return true; };
  // Reuse is integrity-aware (security-integrity.test.js covers that); this
  // fixture isolates auth ordering, so the existing blob simply verifies.
  f.blobs.verifyBlob = async () => ({ ok: true, method: 'fixture' });
  expectAuth(await send(f, '/v1/sites/demo/publish/plan', {
    method: 'POST', token: mint(['plan'], { exp: NOW + 10 }), json: { manifest: manifest() }
  }), 'OWA_AUTH_EXPIRED');
  assert.equal(audits.length, 0, 'no deduplication response is audited after expiry');
  assert.equal(f.calls.length, 0, 'expired plan touches no metadata');
});

test('local grant absolute expiry stays bounded when clock ticks between checks', async t => {
  const f = await fixture(t); let ticks = NOW;
  Object.defineProperty(f.clock, 'value', { get: () => ticks++ });
  const upload = await grant(f, mint(['plan', 'upload'], { exp: NOW + 10 }));
  assert.ok(Number(new URL(upload.url).searchParams.get('expires')) <= NOW + 10,
    'separate clock reads must not extend a grant beyond the bearer expiry');
});

test('local grant uses remaining lifetime after an asynchronous existence check', async t => {
  const f = await fixture(t);
  f.blobs.has = async () => { await Promise.resolve(); f.clock.value = NOW + 50; return false; };
  const upload = await grant(f, mint(['plan', 'upload'], { exp: NOW + 60 }));
  assert.equal(upload.expiresIn, 10, 'local TTL is measured at mint time');
  assert.ok(new URL(upload.url).searchParams.get('expires') === String(NOW + 60), 'local grant never outlives the bearer');
});

for (const [provider, endpoint, region] of [
  ['R2', 'https://account.r2.cloudflarestorage.com', 'auto'],
  ['AWS', 'https://s3.us-east-1.amazonaws.com', 'us-east-1']
]) {
  for (const addressingStyle of ['path', 'virtual']) {
    for (const lifetime of [60, 3600]) {
      test(`${provider} ${addressingStyle} presign is bearer-free and bounded at lifetime ${lifetime}`, async t => {
        const stores = memoryStores(); let f, grants = 0, requestedTtl;
        const blobs = new S3BlobStore({ endpoint, bucket: 'artifacts', region, addressingStyle, accessKeyId: 'SYNTHETICACCESS', secretAccessKey: Buffer.alloc(32, 0x35).toString('hex'), now: () => new Date(f.clock.value * 1000) });
        blobs.has = async () => { await Promise.resolve(); f.clock.value = NOW + 5; return false; };
        blobs.signedFetch = async () => { throw new Error('External provider I/O is forbidden in this fixture'); };
        const originalCreateUpload = blobs.createUpload.bind(blobs);
        blobs.createUpload = async (digest, options) => { grants++; requestedTtl = options.expires; return originalCreateUpload(digest, options); };
        f = await fixture(t, { stores: { ...stores, blobs } });
        const token = mint(['plan', 'upload'], { exp: NOW + lifetime });
        const upload = await grant(f, token), url = new URL(upload.url);
        const ttl = Math.min(900, lifetime - 5);
        assert.equal(grants, 1, 'real provider signing invoked once');
        assert.equal(requestedTtl, ttl, 'server passes current remaining lifetime');
        assert.equal(upload.expiresIn, ttl, 'provider advertises bounded lifetime');
        assert.ok(url.searchParams.get('X-Amz-Expires') === String(ttl), 'SigV4 expiry is bounded');
        assert.ok(url.searchParams.get('X-Amz-Date') === new Date((NOW + 5) * 1000).toISOString().replace(/[:-]|\.\d{3}/g, ''), 'provider clock is fixed');
        assert.ok(url.hostname === (addressingStyle === 'virtual' ? `artifacts.${new URL(endpoint).hostname}` : new URL(endpoint).hostname), 'provider addressing style is preserved');
        assert.ok(url.pathname === `${addressingStyle === 'path' ? '/artifacts' : ''}/owa/blobs/sha256/${DIGEST.split(':')[1]}`, 'provider object path is preserved');
        assert.ok(/^[0-9a-f]{64}$/.test(url.searchParams.get('X-Amz-Signature')), 'real SigV4 signature is present');
        assert.ok(url.searchParams.get('X-Amz-SignedHeaders') === 'host;if-none-match;x-amz-checksum-sha256', 'only host plus the integrity-binding storage headers are signed; bearer is not');
        assert.ok(!Object.hasOwn(upload, 'authorization'), 'direct upload has no bearer forwarding instruction');
        assert.deepEqual(upload.headers, { 'x-amz-checksum-sha256': Buffer.from(DIGEST.split(':')[1], 'hex').toString('base64'), 'if-none-match': '*' }, 'grant pins exactly the checksum-bound create-once storage headers');
        assert.ok(!JSON.stringify(upload).includes(token) && !JSON.stringify(upload).includes('owa1.') && !JSON.stringify(upload).toLowerCase().includes('bearer'), 'grant does not embed the credential');
        assert.ok(![...url.searchParams.keys()].some(key => /authorization|bearer/i.test(key)), 'storage query is bearer-free');
      });
    }
  }
}

test('S3 missing-blob grant requires upload independently, while plan-only dedup is allowed', async t => {
  const f = await fixture(t); let grants = 0, exists = false;
  f.blobs.has = async () => exists;
  f.data.set(DIGEST, BYTES); // "exists" now also means "verifies": reuse is integrity-aware.
  f.blobs.createUpload = async () => { grants++; return {}; };
  expectAuth(await send(f, '/v1/sites/demo/publish/plan', { method: 'POST', token: mint(['plan']), json: { manifest: manifest() } }), 'OWA_AUTH_CAPABILITY', 403);
  assert.equal(grants, 0, 'denied plan cannot mint a provider grant');
  exists = true;
  const result = await plan(f, mint(['plan']));
  assert.equal(result.reused, 1); assert.equal(result.uploads.length, 0); assert.equal(grants, 0);
});

test('explicit loopback dev retains old unscoped URLs without bearer auth', async t => {
  const f = await fixture(t, { mode: 'dev' });
  const planned = await send(f, '/v1/sites/demo/publish/plan', { method: 'POST', json: { manifest: manifest() } });
  assert.equal(planned.status, 200, 'dev plan needs no bearer');
  assert.equal(planned.body.uploads.length, 1, 'dev plan returns one grant');
  const upload = planned.body.uploads[0], url = new URL(upload.url);
  assert.equal(upload.expiresIn, 900, 'dev retains the local grant lifetime');
  assert.ok(!url.searchParams.has('site') && !Object.hasOwn(upload, 'authorization'), 'dev grants retain the legacy shape');
  const sig = createHmac('sha256', UPLOAD_SECRET).update(`${DIGEST}\n${NOW + 900}`).digest('hex');
  assert.ok(url.searchParams.get('sig') === sig, 'dev retains the legacy signing input');
  assert.equal((await send(f, upload.url, { method: 'PUT', bytes: BYTES })).status, 204, 'dev upload needs no bearer');
  assert.equal((await send(f, '/v1/sites/demo/publish/commit', { method: 'POST', json: { manifest: manifest() } })).status, 201, 'dev commit needs no bearer');
  assert.equal((await send(f, '/v1/sites/demo/releases', { headers: { host: 'not-a-loopback.example' } })).status, 200, 'actual local socket, not Host text, determines dev access');
});

for (const [label, headers] of [
  ['forwarded external address', { forwarded: 'for=198.51.100.7' }],
  ['forwarded loopback claim', { forwarded: 'for=127.0.0.1' }],
  ['forwarded-for external address', { 'x-forwarded-for': '198.51.100.7' }],
  ['forwarded-for loopback claim', { 'x-forwarded-for': '127.0.0.1' }],
  ['empty forwarded-for', { 'x-forwarded-for': '' }]
]) {
  test(`dev rejects ${label} even over a loopback connection`, async t => {
    const f = await fixture(t, { mode: 'dev' });
    expectAuth(await send(f, '/v1/sites/demo/publish/plan', { method: 'POST', headers, json: { manifest: manifest() } }), 'OWA_AUTH_DEV_ONLY', 403);
    assert.equal(f.calls.length, 0, 'proxy-shaped dev request does not reach storage');
  });
}

test('health and public gateway GET/HEAD retain existing unauthenticated serving behavior', async t => {
  const f = await fixture(t); await seed(f, 'demo', manifest({ spa: true }));
  const health = await send(f, '/health');
  assert.equal(health.status, 200); assert.ok(health.body.ok === true, 'health remains public');
  const page = await send(f, '/?site=demo');
  assert.equal(page.status, 200); assert.ok(page.text === BYTES.toString('utf8'), 'public gateway serves artifact content');
  assert.ok(page.headers['www-authenticate'] === undefined, 'public gateway has no bearer challenge');
  assert.equal((await send(f, '/', { headers: { host: 'demo.localhost' } })).status, 200, 'localhost hostname routing remains public');
  const head = await send(f, '/?site=demo', { method: 'HEAD' });
  assert.equal(head.status, 200); assert.ok(head.text === '', 'HEAD returns no file bytes');
  for (const path of ['/v1?site=demo', '/v1/unknown?site=demo', `/v1/sites/demo/releases/${RELEASE}?site=demo`]) {
    const result = await send(f, path);
    assert.equal(result.status, 200, 'unimplemented paths retain the existing public SPA behavior, not release inspection');
    assert.ok(result.text === BYTES.toString('utf8'), 'only public artifact bytes are returned, never release metadata');
  }
});

const invalidSites = ['Demo', '-demo', '_demo', 'demo.example', 'a'.repeat(64), 'd%C3%A9mo', 'demo%0A', 'demo%0D', 'demo%00', 'demo%09', 'demo%2fother', '..%2fother', 'demo%5cother', '%ZZ'];
for (const [operation, method, path] of controlRoutes) {
  test(`${operation} rejects malformed site labels and encoded path traversal before storage`, async t => {
    const f = await fixture(t);
    for (const site of invalidSites) {
      const result = await send(f, path.replace('/demo/', `/${site}/`), { method, token: mint(), json: method === 'POST' ? {} : undefined });
      assert.equal(result.status, 400, 'malformed control site rejected');
      assert.ok(result.body?.code === 'OWA_INVALID_SITE', 'fixed invalid-site code');
    }
    assert.equal(f.calls.length, 0, 'invalid site paths never touch metadata');
  });
}

test('site grammar accepts lower-ASCII 63-character scopes without widening them', async t => {
  const f = await fixture(t); const site = `a${'b'.repeat(60)}_1`;
  await f.blobs.put(DIGEST, BYTES);
  const result = await plan(f, mint(['plan'], { sites: [site] }), manifest(), site);
  assert.ok(result.slug === site && result.reused === 1, 'max-length safe label remains exact');
});

test('activate rejects unsafe release identifiers including encoded slash traversal before metadata', async t => {
  const f = await fixture(t);
  for (const release of ['..%2fsite', '%2e%2e%2freleases%2fother', 'r_short', `r_${'A'.repeat(20)}`, `r_${'a'.repeat(21)}`, `${RELEASE}%00`, `${RELEASE}%0a`, `${RELEASE}%5cother`, '%ZZ']) {
    const result = await send(f, `/v1/sites/demo/activate/${release}`, { method: 'POST', token: mint(['activate']) });
    assert.equal(result.status, 400, 'malformed release path rejected');
  }
  assert.equal(f.calls.length, 0, 'unsafe release IDs never reach metadata');
});

test('public site and artifact-path traversal guards do not expose metadata or SPA fallback', async t => {
  const f = await fixture(t);
  for (const site of invalidSites) assert.equal((await send(f, `/?site=${site}`)).status, 404, 'malformed public scope rejected');
  assert.equal((await send(f, '/', { headers: { host: 'demo.other.localhost' } })).status, 404, 'multi-label host is not a scope');
  assert.equal(f.calls.length, 0, 'public malformed scopes do not read metadata');
  await seed(f, 'demo', manifest({ spa: true }));
  for (const path of ['/..%2foutside', '/%2e%2e%2foutside', '/%5coutside', '/%00']) {
    assert.equal((await send(f, `${path}?site=demo`)).status, 404, 'encoded artifact traversal cannot use SPA fallback');
  }
});

for (const [label, corrupt] of [
  ['mismatched slug', site => ({ ...site, slug: 'other' })],
  ['unsafe namespace ID', site => ({ ...site, id: '../outside' })]
]) {
  test(`control and public routes reject a site record with ${label}`, async t => {
    const f = await fixture(t); const { site } = await seed(f);
    f.sites.set('demo', corrupt(site)); f.calls.length = 0;
    for (const [method, path, json] of [
      ['GET', '/v1/sites/demo/releases'], ['POST', '/v1/sites/demo/publish/commit', { manifest: manifest(), activate: false }],
      ['POST', `/v1/sites/demo/activate/${RELEASE}`], ['GET', '/?site=demo']
    ]) expectOperationFailure(await send(f, path, { method, token: mint(), json }));
    assert.ok(f.calls.every(call => call === 'getSite'), 'unsafe site record is not dereferenced or mutated');
  });
}

test('public gateway rejects an unsafe active release ID before dereferencing it', async t => {
  const f = await fixture(t); const { site } = await seed(f);
  f.sites.set('demo', { ...site, activeReleaseId: '../outside' }); f.calls.length = 0;
  expectOperationFailure(await send(f, '/?site=demo'));
  assert.ok(f.calls.length === 1 && f.calls[0] === 'getSite', 'unsafe active release is never read');
});

async function storedJson(root) {
  const values = [];
  for (const entry of await readdir(root, { withFileTypes: true })) {
    const path = join(root, entry.name);
    if (entry.isDirectory()) values.push(...await storedJson(path));
    else if (entry.name.endsWith('.json')) values.push(await readFile(path, 'utf8'));
  }
  return values;
}

test('full filesystem publish audits only jti/site/operation and persists no auth or request data', async t => {
  const events = [], f = await fixture(t, { filesystem: true, audit: event => events.push(event) });
  const token = mint(), value = manifest();
  const upload = await grant(f, token);
  assert.equal((await send(f, upload.url, { method: 'PUT', token, bytes: BYTES })).status, 204);
  const committed = await send(f, '/v1/sites/demo/publish/commit', { method: 'POST', token, json: { manifest: value, activate: false, requestOnly: 'body-only-marker' } });
  assert.equal(committed.status, 201);
  const activated = await send(f, `/v1/sites/demo/activate/${committed.body.releaseId}`, { method: 'POST', token });
  assert.equal(activated.status, 200);
  const inspection = await send(f, '/v1/sites/demo/releases', { token });
  assert.equal(inspection.status, 200);
  assert.ok(JSON.stringify(inspection.body.releases[0].manifest) === JSON.stringify(value), 'bearer handling does not mutate the artifact manifest');
  assert.equal(events.length, 5, 'each successful protected operation is audited once');
  for (let i = 0; i < events.length; i++) {
    const event = events[i];
    assert.ok(Object.keys(event).sort().join(',') === 'jti,operation,site', 'audit contains no request, headers, token, manifest, body, or claims');
    assert.ok(event.jti === JTI && event.site === 'demo' && event.operation === ['plan', 'upload', 'commit', 'activate', 'read'][i], 'audit values are the explicit identifier, site and operation');
  }
  const files = await storedJson(f.root);
  assert.equal(files.length, 3, 'only site index, site record and release metadata are persisted');
  const persisted = files.join('\n'), auditText = JSON.stringify(events), responseText = inspection.text;
  for (const output of [persisted, auditText, responseText]) {
    for (const sensitive of [token, `Bearer ${token}`, SECRET.toString('hex'), SECRET.toString('utf8'), UPLOAD_SECRET.toString('hex'), new URL(upload.url).searchParams.get('sig')]) {
      assert.ok(!output.includes(sensitive), 'credentials and grant signatures never leak into audit or metadata');
    }
    assert.ok(!output.includes('body-only-marker'), 'request body outside the manifest is not retained');
  }
  assert.ok(!persisted.includes(JTI), 'audit identifier is not artifact metadata');
  assert.ok(!auditText.includes('manifest-only-marker') && !auditText.includes(BYTES.toString('utf8')), 'audit does not include manifest or uploaded body');
  const before = events.length;
  expectAuth(await send(f, '/v1/sites/demo/releases'), 'OWA_AUTH_MISSING');
  assert.equal(events.length, before, 'denied requests do not generate a success audit');
});

for (const [operation, method, path, target] of [
  ['plan', 'POST', '/v1/sites/demo/publish/plan', 'has'],
  ['commit', 'POST', '/v1/sites/demo/publish/commit', 'getSite'],
  ['activate', 'POST', `/v1/sites/demo/activate/${RELEASE}`, 'getRelease'],
  ['read', 'GET', '/v1/sites/demo/releases', 'listReleases'],
  ['public read', 'GET', '/?site=demo', 'get'],
  ['upload', 'PUT', null, 'put']
]) {
  test(`${operation} redacts provider errors and nested causes`, async t => {
    const f = await fixture(t), token = mint(); let upload;
    if (operation === 'upload') upload = await grant(f, token);
    else await seed(f);
    const providerUrl = `https://storage.invalid/blob?X-Amz-Signature=${Buffer.alloc(32, 0x45).toString('hex')}`;
    const nested = new Error(`nested ${providerUrl}`, { cause: new Error(`Bearer ${token}`) });
    const failure = new Error(`provider ${token} ${SECRET.toString('hex')}`, { cause: nested });
    failure.request = { headers: { authorization: `Bearer ${token}` }, url: providerUrl };
    if (['has', 'get', 'put'].includes(target)) f.blobs[target] = async () => { throw failure; };
    else f.metadata[target] = async () => { throw failure; };
    const result = await send(f, path ?? upload.url, { method, ...(operation === 'public read' ? {} : { token }), ...(method === 'POST' ? { json: { manifest: manifest() } } : {}), ...(method === 'PUT' ? { bytes: BYTES } : {}) });
    expectOperationFailure(result);
    const wire = result.text + JSON.stringify(result.headers);
    assert.ok(!wire.includes(token) && !wire.includes(providerUrl) && !wire.includes(SECRET.toString('hex')), 'nested provider secrets are not reflected');
  });
}

test('audit callback failures cannot expose credentials or fail an otherwise valid request', async t => {
  const token = mint(['read']);
  for (const asynchronous of [false, true]) {
    const f = await fixture(t, { audit: () => {
      const error = new Error(`audit ${token}`);
      if (asynchronous) return Promise.reject(error);
      throw error;
    } });
    await seed(f);
    const result = await send(f, '/v1/sites/demo/releases', { token });
    assert.equal(result.status, 200, 'audit failure is contained');
    assert.ok(!result.text.includes(token), 'audit error is not reflected');
  }
});
