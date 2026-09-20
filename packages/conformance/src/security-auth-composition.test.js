import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash, createHmac } from 'node:crypto';
import { once } from 'node:events';
import { request } from 'node:http';
import { mkdtemp, readdir, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createArtifactServer } from '../../server/src/index.js';
import { CAPABILITIES, createToken, isSiteScope } from '../../server/src/auth.js';
import { FilesystemBlobStore, FilesystemMetadataStore } from '../../storage-filesystem/src/index.js';
import { S3BlobStore } from '../../storage-s3/src/index.js';
import { artifactDigest, canonicalJson, OWA_MEDIA_TYPE, OWA_SPEC_VERSION, sha256 } from '../../spec/src/index.js';

// Composition evidence, not browser-enforcement or private-serving evidence.
// Every request uses real loopback HTTP, real core, and filesystem metadata.
// Credentials are synthetic, fixed, constructed in memory, and never printed by
// assertion diffs. Temporary names/ports allocate resources, not security inputs.
// Deliberately do not import the production response-policy helper as an oracle.
const CSP = "sandbox; default-src 'none'; script-src 'none'; style-src 'unsafe-inline'; img-src data:; connect-src 'none'; font-src 'none'; media-src 'none'; object-src 'none'; frame-src 'none'; worker-src 'none'; form-action 'none'; frame-ancestors 'none'; base-uri 'none'";
const POLICY = {
  'content-security-policy': CSP,
  'x-content-type-options': 'nosniff',
  'referrer-policy': 'no-referrer',
  'x-robots-tag': 'noindex, nofollow, noarchive',
  'cache-control': 'no-store',
  'x-frame-options': 'DENY',
  'x-dns-prefetch-control': 'off',
  'x-owa-security-profile': 'sandboxed-web-v1'
};
const SECRET = Buffer.alloc(32, 0x53);
const UPLOAD_SECRET = Buffer.alloc(32, 0x75);
const NOW = 2000000000;
const JTI = 'composition-audit-001';
const SITE_ID = `s_${'1'.repeat(20)}`;
const RELEASE_ID = `r_${'a'.repeat(20)}`;
const CREATED_AT = new Date(NOW * 1000).toISOString();
const BYTES = Buffer.from('<h1>Composed policy</h1><script>window.probe = true</script>');
const DIGEST = sha256(BYTES);
const AUTH_MESSAGES = {
  OWA_AUTH_MISSING: 'Authentication required',
  OWA_AUTH_INVALID_TOKEN: 'Invalid authentication token',
  OWA_AUTH_INVALID_SIGNATURE: 'Invalid authentication signature',
  OWA_AUTH_EXPIRED: 'Authentication token expired',
  OWA_AUTH_SITE: 'Authentication does not permit this site',
  OWA_AUTH_CAPABILITY: 'Authentication does not permit this operation',
  OWA_AUTH_DEV_ONLY: 'Development authentication requires a direct loopback connection'
};

function mint(capabilities = [...CAPABILITIES], overrides = {}) {
  return createToken({ secret: SECRET, now: () => NOW, jti: JTI, exp: NOW + 1200, sites: ['demo'], capabilities, ...overrides });
}
function manifest({ spa = false, mediaType = 'text/html; charset=utf-8', path = '/index.html', expiresAt = null } = {}) {
  return {
    specVersion: OWA_SPEC_VERSION, artifactType: OWA_MEDIA_TYPE, entrypoint: path,
    files: [{ path, digest: DIGEST, size: BYTES.length, mediaType }],
    ...(spa ? { routing: { spaFallback: path } } : {}),
    access: { visibility: 'public' }, lifecycle: { expiresAt },
    annotations: { fixture: 'composition-manifest-marker' }
  };
}
function assertAbsent(text, forbidden) {
  for (const value of forbidden) assert.ok(!value || !text.includes(value), 'sensitive data is not reflected or persisted');
}
function assertPolicy(response) {
  for (const [name, value] of Object.entries(POLICY)) assert.ok(response.headers[name] === value, `exact response ${name}`);
  assert.ok(response.headers['set-cookie'] === undefined, 'no response cookies');
  assert.ok(!Object.keys(response.headers).some(name => name.startsWith('access-control-')), 'no implicit CORS grant');
  assert.ok(response.headers['www-authenticate'] === (response.status === 401 ? 'Bearer realm="owa"' : undefined), 'Bearer challenge belongs only to 401');
}
function json(response) {
  try { return JSON.parse(response.bytes.toString('utf8')); } catch { throw new Error('Expected local JSON response'); }
}
function expectAuth(response, code, status = 401) {
  assert.equal(response.status, status, 'authorization HTTP status');
  assert.ok(JSON.stringify(json(response)) === JSON.stringify({ error: AUTH_MESSAGES[code], code }), 'fixed authorization error envelope');
}
function expectError(response, status, code) {
  assert.equal(response.status, status, 'operation HTTP status');
  if (code) assert.ok(json(response).code === code, 'fixed operation error code');
}

async function fixture(t, { mode = 'required', audit = null, blobs: suppliedBlobs } = {}) {
  const root = await mkdtemp(join(tmpdir(), 'owa-security-auth-composition-'));
  const blobs = suppliedBlobs ?? new FilesystemBlobStore(root);
  const metadata = new FilesystemMetadataStore(root);
  const calls = [], clock = { value: NOW };
  // Record only method names, never arguments, HTTP objects, URLs or credentials.
  for (const [store, methods] of [[blobs, ['has', 'get', 'put']], [metadata, ['getSite', 'createSite', 'saveSite', 'getRelease', 'saveRelease', 'listReleases']]]) {
    for (const method of methods) {
      const original = store[method].bind(store);
      store[method] = async (...args) => { calls.push(method); return original(...args); };
    }
  }
  let server;
  t.after(async () => {
    try {
      if (server?.listening) {
        const closed = once(server, 'close');
        server.close(); server.closeAllConnections(); await closed;
      }
    } finally { await rm(root, { recursive: true, force: true }); }
  });
  server = createArtifactServer({ blobs, metadata, uploadSecret: UPLOAD_SECRET, auth: { mode, secret: SECRET, now: () => clock.value }, audit });
  server.listen(0, '127.0.0.1'); await once(server, 'listening');
  return { root, blobs, metadata, calls, clock, server, port: server.address().port };
}

// The path option preserves literal/encoded dot segments and backslashes. Never
// pass a caller-supplied test target through new URL/fetch before transmission.
// Only generated local upload URLs are parsed separately, with origin checking.
async function send(f, path, { method = 'GET', token, value, bytes, headers = {}, rawHeaders, afterFirstChunk } = {}) {
  const payload = value === undefined ? (bytes ?? Buffer.alloc(0)) : Buffer.from(JSON.stringify(value));
  const response = await new Promise((resolve, reject) => {
    const req = request({ hostname: '127.0.0.1', port: f.port, path, method, agent: false,
      headers: rawHeaders ?? {
        host: `127.0.0.1:${f.port}`, connection: 'close', origin: 'https://untrusted.invalid',
        ...(token === undefined ? {} : { authorization: `Bearer ${token}` }),
        ...(value === undefined ? {} : { 'content-type': 'application/json' }),
        ...(method === 'GET' || method === 'HEAD' ? {} : { 'content-length': String(payload.length) }), ...headers
      }
    }, res => {
      const chunks = [];
      res.on('data', chunk => chunks.push(chunk));
      res.on('error', () => reject(new Error('Local response failed')));
      res.on('aborted', () => reject(new Error('Local response aborted')));
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, bytes: Buffer.concat(chunks) }));
    });
    req.on('error', () => reject(new Error('Local request failed')));
    req.setTimeout(5000, () => req.destroy());
    if (afterFirstChunk) {
      // Observing server-side body receipt makes clock advancement deterministic;
      // no sleep, real-clock race, or cancellation-of-backend-I/O requirement.
      f.server.once('request', incoming => incoming.once('data', () => {
        afterFirstChunk(); req.end(payload.subarray(1));
      }));
      req.write(payload.subarray(0, 1));
    } else req.end(payload);
  });
  assertPolicy(response); // Every application response, including 204 and errors.
  assertAbsent(response.bytes.toString('utf8') + JSON.stringify(response.headers), [
    token, JTI, SECRET.toString('hex'), SECRET.toString('utf8'), UPLOAD_SECRET.toString('hex'), UPLOAD_SECRET.toString('utf8')
  ]);
  return response;
}
function localTarget(f, upload, edit) {
  let url;
  try { url = new URL(upload.url); } catch { throw new Error('Invalid local upload grant'); }
  assert.ok(url.origin === `http://127.0.0.1:${f.port}`, 'upload destination stays loopback');
  if (edit) edit(url.searchParams);
  return url.pathname + url.search;
}
async function plan(f, token = mint(['plan', 'upload']), value = manifest()) {
  const response = await send(f, '/v1/sites/demo/publish/plan', { method: 'POST', token, value: { manifest: value, artifactDigest: artifactDigest(value) } });
  assert.equal(response.status, 200, 'authorized plan succeeds');
  return json(response);
}
async function grant(f, token) {
  const planned = await plan(f, token);
  assert.equal(planned.uploads.length, 1, 'one missing digest produces one grant');
  return planned.uploads[0];
}
async function seed(f, value = manifest()) {
  const site = { id: SITE_ID, slug: 'demo', activeReleaseId: RELEASE_ID, createdAt: CREATED_AT };
  const release = { id: RELEASE_ID, createdAt: CREATED_AT, artifactDigest: artifactDigest(value), manifest: value };
  await f.blobs.put(DIGEST, BYTES);
  await f.metadata.saveSite(site); await f.metadata.saveRelease(site.id, release);
  return { site, release };
}
async function tree(root, prefix = '') {
  const entries = [];
  for (const entry of (await readdir(join(root, prefix), { withFileTypes: true })).sort((a, b) => a.name.localeCompare(b.name))) {
    const path = join(prefix, entry.name);
    if (entry.isDirectory()) entries.push(...await tree(root, path));
    else entries.push([path, (await readFile(join(root, path))).toString('base64')]);
  }
  return JSON.stringify(entries);
}

const ROUTES = [
  ['plan', 'POST', '/v1/sites/demo/publish/plan'],
  ['commit', 'POST', '/v1/sites/demo/publish/commit'],
  ['activate', 'POST', `/v1/sites/demo/activate/${RELEASE_ID}`],
  ['read', 'GET', '/v1/sites/demo/releases']
];
for (const [operation, method, path] of ROUTES) {
  test(`composition: ${operation} missing/wrong-site/wrong-capability auth retains the full profile`, async t => {
    const f = await fixture(t), before = await tree(f.root);
    expectAuth(await send(f, path, { method, ...(method === 'POST' ? { bytes: Buffer.from('{') } : {}) }), 'OWA_AUTH_MISSING');
    expectAuth(await send(f, path.replace('/demo/', '/other/'), { method, token: mint(), ...(method === 'POST' ? { value: {} } : {}) }), 'OWA_AUTH_SITE', 403);
    expectAuth(await send(f, path, { method, token: mint([operation === 'read' ? 'plan' : 'read']), ...(method === 'POST' ? { value: {} } : {}) }), 'OWA_AUTH_CAPABILITY', 403);
    assert.equal(f.calls.length, 0, 'denied control requests do not reach storage or body validation');
    assert.ok(await tree(f.root) === before, 'denied control requests have no filesystem effects');
  });
}
for (const [label, credential, code] of [
  ['malformed token', () => 'not-a-token', 'OWA_AUTH_INVALID_TOKEN'],
  ['other signing key', () => mint(['plan'], { secret: Buffer.alloc(32, 0x45) }), 'OWA_AUTH_INVALID_SIGNATURE'],
  ['tampered signature', () => { const parts = mint(['plan']).split('.'); const mac = Buffer.from(parts[2], 'base64url'); mac[0] ^= 1; parts[2] = mac.toString('base64url'); return parts.join('.'); }, 'OWA_AUTH_INVALID_SIGNATURE'],
  ['exact expiry boundary', () => mint(['plan'], { exp: NOW, now: () => NOW - 1 }), 'OWA_AUTH_EXPIRED']
]) {
  test(`composition: ${label} returns a redacted profiled 401`, async t => {
    const f = await fixture(t), token = credential();
    expectAuth(await send(f, '/v1/sites/demo/publish/plan', { method: 'POST', token, value: { manifest: manifest() } }), code);
    assert.equal(f.calls.length, 0, 'invalid credentials cannot reach storage');
  });
}
test('composition: duplicate and non-Bearer authorization remain rejected with policy', async t => {
  const f = await fixture(t), token = mint();
  for (const authorization of [`Basic ${token}`, `Bearer ${token}, Bearer ${token}`]) {
    const response = await send(f, '/v1/sites/demo/releases', { headers: { authorization } });
    expectAuth(response, 'OWA_AUTH_INVALID_TOKEN'); assertAbsent(response.bytes.toString() + JSON.stringify(response.headers), [token]);
  }
  const response = await send(f, '/v1/sites/demo/releases', { rawHeaders: [
    'Host', 'localhost', 'Connection', 'close', 'Authorization', `Bearer ${token}`, 'authorization', `Bearer ${token}`
  ] });
  expectAuth(response, 'OWA_AUTH_INVALID_TOKEN'); assertAbsent(response.bytes.toString() + JSON.stringify(response.headers), [token]);
  assert.equal(f.calls.length, 0);
});

test('composition: real filesystem publish keeps capabilities, profile, audit and artifact identity independent', async t => {
  const events = [], logs = [];
  for (const name of ['log', 'warn', 'error', 'info', 'debug']) t.mock.method(console, name, (...args) => logs.push(args.map(String).join(' ')));
  const f = await fixture(t, { audit: event => events.push(event) }), token = mint(), value = manifest();
  const beforeManifest = canonicalJson(value), upload = await grant(f, token), url = new URL(upload.url);
  assert.ok(upload.authorization === 'bearer' && upload.method === 'PUT' && upload.digest === DIGEST, 'FS advertises explicit bearer authorization');
  assert.ok(url.searchParams.get('site') === 'demo', 'FS grant binds one safe scope');
  assert.ok(Number(url.searchParams.get('expires')) === NOW + 900 && upload.expiresIn === 900, 'FS grant has capped fixed lifetime');
  const signature = createHmac('sha256', UPLOAD_SECRET).update(`owa-upload-v1\ndemo\n${DIGEST}\n${NOW + 900}`).digest('hex');
  assert.ok(url.searchParams.get('sig') === signature, 'FS signature uses independent key and site-scoped signing input');
  assertAbsent(JSON.stringify(upload), [token, JTI]);
  const uploaded = await send(f, localTarget(f, upload), { method: 'PUT', token: mint(['upload']), bytes: BYTES });
  assert.equal(uploaded.status, 204); assert.equal(uploaded.bytes.length, 0);
  const committed = await send(f, '/v1/sites/demo/publish/commit', { method: 'POST', token: mint(['commit']), value: { manifest: value, artifactDigest: artifactDigest(value), activate: false, requestOnly: 'composition-request-only' } });
  assert.equal(committed.status, 201);
  const record = json(committed);
  assert.ok(/^r_[0-9a-f]{20}$/.test(record.releaseId) && record.activeReleaseId === null, 'commit-only creates an inactive valid release');
  const activated = await send(f, `/v1/sites/demo/activate/${record.releaseId}`, { method: 'POST', token: mint(['activate']) });
  assert.equal(activated.status, 200); assert.ok(json(activated).activeReleaseId === record.releaseId);
  const inspected = await send(f, '/v1/sites/demo/releases', { token: mint(['read']), headers: { cookie: 'composition-cookie-marker' } });
  assert.equal(inspected.status, 200);
  const listing = json(inspected);
  assert.ok(/^s_[0-9a-f]{20}$/.test(listing.site.id), 'real core/filesystem IDs keep their grammar');
  assert.ok(Number.isFinite(Date.parse(listing.site.createdAt)) && Number.isFinite(Date.parse(listing.releases[0].createdAt)), 'metadata has valid creation dates');
  assert.ok(canonicalJson(listing.releases[0].manifest) === beforeManifest && listing.releases[0].artifactDigest === artifactDigest(value), 'inspection preserves the complete original manifest and identity');
  assert.ok(canonicalJson(value) === beforeManifest && Buffer.from(await f.blobs.get(DIGEST)).equals(BYTES), 'auth and profile do not rewrite manifest or bytes');
  const operations = ['plan', 'upload', 'commit', 'activate', 'read'];
  assert.equal(events.length, operations.length, 'one success audit per protected operation');
  events.forEach((event, index) => {
    assert.ok(Object.keys(event).sort().join(',') === 'jti,operation,site' && Object.isFrozen(event), 'audit fields are minimal and frozen');
    assert.ok(event.jti === JTI && event.site === 'demo' && event.operation === operations[index], 'audit exposes only explicit identifier/site/operation');
  });
  const persisted = [];
  async function collect(dir) {
    for (const entry of await readdir(dir, { withFileTypes: true })) {
      const path = join(dir, entry.name);
      if (entry.isDirectory()) await collect(path); else persisted.push((await readFile(path)).toString('utf8'));
    }
  }
  await collect(f.root);
  const sensitive = [token, 'owa1.', signature, SECRET.toString('hex'), SECRET.toString('utf8'), UPLOAD_SECRET.toString('hex'), UPLOAD_SECRET.toString('utf8'), 'composition-request-only', 'composition-cookie-marker'];
  assertAbsent(persisted.join('\n') + inspected.bytes.toString() + JSON.stringify(inspected.headers), [...sensitive, JTI]);
  assertAbsent(JSON.stringify(events), [...sensitive, 'composition-manifest-marker', BYTES.toString()]);
  assertAbsent(logs.join('\n'), [...sensitive, JTI]);
  expectAuth(await send(f, '/v1/sites/demo/releases'), 'OWA_AUTH_MISSING');
  assert.equal(events.length, operations.length, 'denial creates no success audit');
});

test('composition: plan/upload gates and literal false/default commit activation retain PR11 semantics', async t => {
  const f = await fixture(t), value = manifest();
  expectAuth(await send(f, '/v1/sites/demo/publish/plan', { method: 'POST', token: mint(['upload']), value: { manifest: value } }), 'OWA_AUTH_CAPABILITY', 403);
  expectAuth(await send(f, '/v1/sites/demo/publish/plan', { method: 'POST', token: mint(['plan']), value: { manifest: value } }), 'OWA_AUTH_CAPABILITY', 403);
  assert.ok(!f.calls.includes('put') && !f.calls.includes('saveRelease'), 'grant denials never write artifacts');
  await f.blobs.put(DIGEST, BYTES); f.calls.length = 0;
  const reused = await plan(f, mint(['plan']), value);
  assert.ok(reused.reused === 1 && reused.uploads.length === 0, 'plan-only may deduplicate without upload capability');
  f.calls.length = 0;
  for (const body of [{}, { manifest: value }, ...[true, null, 0, '', 'false'].map(activate => ({ manifest: value, activate }))]) {
    expectAuth(await send(f, '/v1/sites/demo/publish/commit', { method: 'POST', token: mint(['commit']), value: body }), 'OWA_AUTH_CAPABILITY', 403);
  }
  assert.equal(f.calls.length, 0, 'implicit activation requires its capability before any storage access');
  const result = await send(f, '/v1/sites/demo/publish/commit', { method: 'POST', token: mint(['commit', 'activate']), value: { manifest: value } });
  assert.equal(result.status, 201); assert.ok(json(result).activeReleaseId === json(result).releaseId, 'activation remains the default');
});

for (const [label, credential, code, status] of [
  ['no bearer', () => undefined, 'OWA_AUTH_MISSING', 401],
  ['wrong site', () => mint(['upload'], { sites: ['other'] }), 'OWA_AUTH_SITE', 403],
  ['read-only capability', () => mint(['read']), 'OWA_AUTH_CAPABILITY', 403],
  ['plan-only capability', () => mint(['plan']), 'OWA_AUTH_CAPABILITY', 403],
  ['expired bearer', () => mint(['upload'], { exp: NOW, now: () => NOW - 1 }), 'OWA_AUTH_EXPIRED', 401]
]) {
  test(`composition: FS signed PUT with ${label} cannot write`, async t => {
    const f = await fixture(t), upload = await grant(f), before = await tree(f.root);
    f.calls.length = 0;
    expectAuth(await send(f, localTarget(f, upload), { method: 'PUT', token: credential(), bytes: BYTES }), code, status);
    assert.equal(f.calls.length, 0, 'denied upload never reaches blob or metadata methods');
    assert.ok(await tree(f.root) === before, 'denied upload has no filesystem effects');
  });
}
for (const [label, edit, status, code] of [
  ['bad storage signature', p => p.set('sig', '0'.repeat(64)), 403, 'OWA_UPLOAD_INVALID'],
  ['bearer-key storage signature', p => p.set('sig', createHmac('sha256', SECRET).update(`owa-upload-v1\ndemo\n${DIGEST}\n${p.get('expires')}`).digest('hex')), 403, 'OWA_UPLOAD_INVALID'],
  ['legacy unscoped signature', p => p.set('sig', createHmac('sha256', UPLOAD_SECRET).update(`${DIGEST}\n${p.get('expires')}`).digest('hex')), 403, 'OWA_UPLOAD_INVALID'],
  ['changed signed site', p => p.set('site', 'other'), 403, 'OWA_UPLOAD_INVALID'],
  ['duplicate site', p => p.append('site', 'demo'), 400, 'OWA_INVALID_SITE'],
  ['missing site', p => p.delete('site'), 400, 'OWA_INVALID_SITE'],
  ['unsafe site', p => p.set('site', '../demo'), 400, 'OWA_INVALID_SITE'],
  ['duplicate signature', p => p.append('sig', p.get('sig')), 403, 'OWA_UPLOAD_INVALID'],
  ['duplicate expiry', p => p.append('expires', p.get('expires')), 403, 'OWA_UPLOAD_INVALID'],
  ['missing signature', p => p.delete('sig'), 403, 'OWA_UPLOAD_INVALID'],
  ['expired grant', p => p.set('expires', String(NOW)), 403, 'OWA_UPLOAD_INVALID']
]) {
  test(`composition: FS PUT rejects ${label} independently of an authorized bearer`, async t => {
    const f = await fixture(t), upload = await grant(f), before = await tree(f.root);
    f.calls.length = 0;
    const result = await send(f, localTarget(f, upload, edit), { method: 'PUT', token: mint(['upload'], { sites: ['demo', 'other'] }), bytes: BYTES });
    expectError(result, status, code);
    assertAbsent(result.bytes.toString() + JSON.stringify(result.headers), [new URL(upload.url).searchParams.get('sig')]);
    assert.equal(f.calls.length, 0, 'bad grant never reaches storage');
    assert.ok(await tree(f.root) === before, 'bad grant has no filesystem effects');
  });
}

test('composition: FS grant TTL is remaining bearer lifetime and upload digest errors retain policy', async t => {
  const f = await fixture(t), upload = await grant(f, mint(['plan', 'upload'], { exp: NOW + 37 }));
  assert.ok(upload.expiresIn === 37 && new URL(upload.url).searchParams.get('expires') === String(NOW + 37), 'FS grant never outlives its bearer');
  const before = await tree(f.root);
  const result = await send(f, localTarget(f, upload), { method: 'PUT', token: mint(['upload']), bytes: Buffer.from('mismatching fixed bytes') });
  expectError(result, 400); assert.ok(await tree(f.root) === before, 'digest mismatch is not stored');
});
for (const operation of ['plan', 'upload', 'commit']) {
  test(`composition: slow ${operation} body expires at the injected boundary with profiled 401 and no writes`, async t => {
    const f = await fixture(t), upload = operation === 'upload' ? await grant(f) : null;
    const before = await tree(f.root); f.calls.length = 0;
    const result = await send(f, upload ? localTarget(f, upload) : `/v1/sites/demo/publish/${operation}`, {
      method: upload ? 'PUT' : 'POST', token: mint([...CAPABILITIES], { exp: NOW + 10 }),
      ...(upload ? { bytes: BYTES } : { value: { manifest: manifest(), activate: false } }),
      afterFirstChunk: () => { f.clock.value = NOW + 10; }
    });
    expectAuth(result, 'OWA_AUTH_EXPIRED');
    assert.equal(f.calls.length, 0, 'post-body expiry is rechecked before storage');
    assert.ok(await tree(f.root) === before, 'slow expired request has no filesystem effects');
  });
}

test('composition: explicit dev accepts direct loopback but denies every forwarding-header family', async t => {
  const f = await fixture(t, { mode: 'dev' });
  const direct = await send(f, '/v1/sites/demo/publish/plan', { method: 'POST', value: { manifest: manifest() } });
  assert.equal(direct.status, 200);
  assert.equal(json(direct).uploads.length, 1);
  const upload = json(direct).uploads[0];
  assert.ok(!Object.hasOwn(upload, 'authorization') && !new URL(upload.url).searchParams.has('site'), 'token-free dev retains legacy grant protocol');
  for (const headers of [
    { forwarded: 'for=127.0.0.1' }, { forwarded: '' }, { 'x-forwarded-for': '127.0.0.1' },
    { 'x-forwarded-host': 'localhost' }, { 'x-forwarded-proto': 'http' }, { 'x-forwarded-arbitrary': '' }
  ]) {
    f.calls.length = 0;
    expectAuth(await send(f, '/v1/sites/demo/publish/plan', { method: 'POST', value: { manifest: manifest() }, headers }), 'OWA_AUTH_DEV_ONLY', 403);
    assert.equal(f.calls.length, 0, 'forwarded dev request is rejected before storage');
    expectAuth(await send(f, localTarget(f, upload), { method: 'PUT', bytes: BYTES, headers }), 'OWA_AUTH_DEV_ONLY', 403);
    assert.equal(f.calls.length, 0, 'forwarded dev upload is rejected before storage');
  }
});

// Independent SigV4 recomputation uses only provider fields, never OWA inputs.
// Equality is boolean so a failure cannot dump the presigned credential URL.
function expectedStorageSignature(url, key, region) {
  const enc = value => encodeURIComponent(value).replace(/[!'()*]/g, c => `%${c.charCodeAt(0).toString(16).toUpperCase()}`);
  const params = [...url.searchParams].filter(([name]) => name !== 'X-Amz-Signature').sort(([a, av], [b, bv]) => a === b ? av.localeCompare(bv) : a.localeCompare(b));
  const query = params.map(([name, value]) => `${enc(name)}=${enc(value)}`).join('&');
  const timestamp = url.searchParams.get('X-Amz-Date'), date = timestamp.slice(0, 8), scope = `${date}/${region}/s3/aws4_request`;
  const canonical = ['PUT', url.pathname, query, `host:${url.host}\n`, 'host', 'UNSIGNED-PAYLOAD'].join('\n');
  const signing = ['AWS4-HMAC-SHA256', timestamp, scope, createHash('sha256').update(canonical).digest('hex')].join('\n');
  const hmac = (secret, value) => createHmac('sha256', secret).update(value).digest();
  const derived = hmac(hmac(hmac(hmac(`AWS4${key}`, date), region), 's3'), 'aws4_request');
  return createHmac('sha256', derived).update(signing).digest('hex');
}
for (const [provider, endpoint, region] of [
  ['S3', 'https://s3.us-east-1.amazonaws.com', 'us-east-1'],
  ['R2', 'https://account.r2.cloudflarestorage.com', 'auto']
]) {
  for (const addressingStyle of ['path', 'virtual']) {
    for (const lifetime of [37, 1200]) {
      test(`composition: ${provider} ${addressingStyle} real offline presign at lifetime ${lifetime} is bearer-free with policy`, async t => {
        let f, externalRequests = 0;
        const providerKey = Buffer.alloc(32, 0x35).toString('hex'), signingInputs = [];
        const blobs = new S3BlobStore({ endpoint, bucket: 'artifacts', region, addressingStyle, accessKeyId: 'SYNTHETICCOMPOSITION', secretAccessKey: providerKey, now: () => new Date(f.clock.value * 1000) });
        blobs.has = async () => { await Promise.resolve(); f.clock.value = NOW + 5; return false; };
        const forbiddenNetwork = async () => { externalRequests++; throw new Error('External provider I/O forbidden'); };
        blobs.signedFetch = forbiddenNetwork;
        t.mock.method(globalThis, 'fetch', forbiddenNetwork);
        const original = blobs.presign.bind(blobs);
        blobs.presign = (method, key, options) => { signingInputs.push({ method, key, options }); return original(method, key, options); };
        f = await fixture(t, { blobs });
        expectAuth(await send(f, '/v1/sites/demo/publish/plan', { method: 'POST', token: mint(['plan']), value: { manifest: manifest() } }), 'OWA_AUTH_CAPABILITY', 403);
        assert.equal(signingInputs.length, 0, 'plan capability alone never signs a provider grant');
        const token = mint(['plan', 'upload'], { exp: NOW + lifetime }), upload = await grant(f, token), url = new URL(upload.url);
        const ttl = Math.min(900, lifetime - 5);
        assert.equal(signingInputs.length, 1); assert.equal(externalRequests, 0, 'presigning is completely offline');
        assert.ok(signingInputs[0].options.expires === ttl && upload.expiresIn === ttl && url.searchParams.get('X-Amz-Expires') === String(ttl), 'all TTLs use current remaining lifetime');
        assert.ok(url.searchParams.get('X-Amz-Date') === new Date((NOW + 5) * 1000).toISOString().replace(/[:-]|\.\d{3}/g, ''), 'provider signing uses fixed clock');
        assert.ok(url.hostname === `${addressingStyle === 'virtual' ? 'artifacts.' : ''}${new URL(endpoint).hostname}`, 'provider destination remains unchanged');
        assert.ok(url.pathname === `${addressingStyle === 'path' ? '/artifacts' : ''}/owa/blobs/sha256/${DIGEST.split(':')[1]}`, 'provider object key remains unchanged');
        assert.ok(url.searchParams.get('X-Amz-SignedHeaders') === 'host' && url.searchParams.get('X-Amz-Signature') === expectedStorageSignature(url, providerKey, region), 'real signature independently verifies without OWA data');
        assert.ok(!Object.hasOwn(upload, 'authorization') && !Object.hasOwn(upload, 'headers'), 'direct storage grants do not forward control headers');
        assertAbsent(JSON.stringify(upload) + JSON.stringify(signingInputs), [token, 'owa1.', JTI, SECRET.toString('hex'), SECRET.toString('utf8'), UPLOAD_SECRET.toString('hex'), 'Bearer']);
        assert.ok(![...url.searchParams.keys()].some(name => /authorization|bearer|^site$/i.test(name)), 'provider signing query has no OWA scope or authorization');
      });
    }
  }
}

for (const [label, options, contentType, disposition] of [
  ['manifest HTML in a .bin path', { path: '/page.bin' }, 'text/html; charset=utf-8', 'inline'],
  ['unsupported manifest type in .html', { mediaType: 'application/x-composition' }, 'application/octet-stream', 'attachment'],
  ['malformed MIME metadata in .html', { mediaType: 'text/html; bad="unterminated' }, 'application/octet-stream', 'attachment']
]) {
  test(`composition: public token-free GET/HEAD ${label} retains full policy and original bytes`, async t => {
    const f = await fixture(t), value = manifest(options); await seed(f, value);
    const before = await tree(f.root), target = `${value.entrypoint}?site=demo`;
    const get = await send(f, target), head = await send(f, target, { method: 'HEAD' });
    assert.equal(get.status, 200); assert.equal(head.status, 200); assert.equal(head.bytes.length, 0);
    assert.ok(get.bytes.equals(BYTES) && sha256(get.bytes) === DIGEST, 'public bytes are original, not rewritten');
    assert.ok(get.headers.etag === `"${DIGEST}"` && get.headers['content-length'] === String(BYTES.length), 'original digest and byte count');
    assert.ok(get.headers['content-type'] === contentType && get.headers['content-disposition'] === disposition, 'dispatch uses complete manifest MIME, not extension or sniffing');
    for (const name of [...Object.keys(POLICY), 'etag', 'content-length', 'content-type', 'content-disposition']) assert.ok(head.headers[name] === get.headers[name], `GET/HEAD parity for ${name}`);
    const host = await send(f, value.entrypoint, { headers: { host: 'demo.localhost' } }); assert.equal(host.status, 200);
    const conditional = await send(f, target, { headers: { 'if-none-match': `"${DIGEST}"` } }); assert.equal(conditional.status, 200, 'no-store policy does not produce a stale 304');
    assert.ok(await tree(f.root) === before, 'public GET/HEAD cannot mutate storage');
  });
}

test('composition: public 404/410 and authorized 404 retain policy without a challenge', async t => {
  const f = await fixture(t); await seed(f, manifest({ expiresAt: '2000-01-01T00:00:00.000Z' }));
  for (const method of ['GET', 'HEAD']) {
    expectError(await send(f, '/?site=absent', { method }), 404);
    expectError(await send(f, '/?site=demo', { method }), 410);
  }
  expectError(await send(f, '/v1/sites/absent/releases', { token: mint(['read'], { sites: ['absent'] }) }), 404);
  const health = await send(f, '/health'); assert.equal(health.status, 200);
});
for (const [operation, method, path, store, member] of [
  ['plan', 'POST', '/v1/sites/demo/publish/plan', 'blobs', 'has'],
  ['commit', 'POST', '/v1/sites/demo/publish/commit', 'metadata', 'getSite'],
  ['read', 'GET', '/v1/sites/demo/releases', 'metadata', 'listReleases'],
  ['activate', 'POST', `/v1/sites/demo/activate/${RELEASE_ID}`, 'metadata', 'getRelease'],
  ['public', 'GET', '/?site=demo', 'blobs', 'get'],
  ['upload', 'PUT', null, 'blobs', 'put']
]) {
  test(`composition: ${operation} provider failure/cause yields profiled redacted 500`, async t => {
    const f = await fixture(t), token = mint(), upload = operation === 'upload' ? await grant(f) : null;
    if (!upload) await seed(f);
    const providerUrl = new URL('https://storage.invalid/blob');
    providerUrl.searchParams.set('X-Amz-Signature', Buffer.alloc(32, 0x46).toString('hex'));
    const failure = new Error('Provider failure', { cause: new Error(providerUrl.toString(), { cause: new Error(`Bearer ${token}`) }) });
    failure.request = { headers: { authorization: `Bearer ${token}` } };
    f[store][member] = async () => { throw failure; };
    const response = await send(f, upload ? localTarget(f, upload) : path, {
      method, ...(operation === 'public' ? {} : { token }), ...(method === 'POST' ? { value: { manifest: manifest() } } : {}), ...(upload ? { bytes: BYTES } : {})
    });
    expectError(response, 500, 'OWA_OPERATION_FAILED');
    assert.ok(json(response).error === 'Operation failed', 'fixed operation message');
    assertAbsent(response.bytes.toString() + JSON.stringify(response.headers), [token, providerUrl.toString(), 'Provider failure', '[cause]', '    at ']);
    if (operation === 'public') {
      const head = await send(f, path, { method: 'HEAD' }); assert.equal(head.status, 500); assert.equal(head.bytes.length, 0);
    }
  });
}

test('composition: raw public dot segments, bad escapes and backslashes cannot become SPA fallbacks', async t => {
  const f = await fixture(t); await seed(f, manifest({ spa: true }));
  const before = await tree(f.root);
  for (const rawPath of ['/../index.html', '/junk/../index.html', '/%2e%2e/index.html', '/junk/%2E%2E/index.html', '/..%2findex.html', '/%ZZ', '/%E0%A4%A', '/bad\\index.html', '/%5cindex.html', '/%00']) {
    for (const method of ['GET', 'HEAD']) {
      const response = await send(f, `${rawPath}?site=demo`, { method });
      expectError(response, 404); if (method === 'HEAD') assert.equal(response.bytes.length, 0);
    }
  }
  const safe = await send(f, '/safe-spa-route?site=demo'); assert.equal(safe.status, 200); assert.ok(safe.bytes.equals(BYTES), 'safe SPA fallback remains public');
  assert.ok(await tree(f.root) === before, 'raw target validation does not modify artifacts');
});

test('composition: strict PR11 scopes reject Unicode, percent-looking, slash, case and namespace traversal selectors', async t => {
  const f = await fixture(t);
  for (const scope of ['demo', 'a', 'a_b-0', `a${'b'.repeat(62)}`]) assert.ok(isSiteScope(scope), 'safe lower-ASCII scope is accepted');
  const invalid = ['Demo', '-demo', '_demo', 'demo.example', 'a'.repeat(64), 'café', '%2e%2e%2fdemo', 'demo/other', 'demo\\other', '../demo', '.', '..', 'demo\n', 'demo\r', 'demo\0', 'demo\t'];
  for (const scope of invalid) {
    assert.ok(!isSiteScope(scope), 'strict PR11 scope is not widened');
    const encoded = encodeURIComponent(scope);
    expectError(await send(f, `/?site=${encoded}`), 404);
    const control = await send(f, `/v1/sites/${encoded}/releases`, { token: mint(['read']) });
    // Dot-only segments normalize away from the control route; they still cannot
    // select metadata. Other encoded malformed scopes use the fixed 400 code.
    if (scope === '.' || scope === '..') expectError(control, 404);
    else expectError(control, 400, 'OWA_INVALID_SITE');
  }
  expectError(await send(f, '/?site=%ZZ'), 404);
  expectError(await send(f, '/v1/sites/%ZZ/releases', { token: mint(['read']) }), 400, 'OWA_INVALID_SITE');
  for (const host of ['Demo.localhost', 'demo.other.localhost', '%64emo.localhost']) expectError(await send(f, '/', { headers: { host } }), 404);
  assert.equal(f.calls.length, 0, 'invalid selectors never become filesystem metadata keys');
});

test('composition: URL-parsed control aliases still require bearer and exact site scope before metadata', async t => {
  const f = await fixture(t); await seed(f, manifest({ spa: true })); f.calls.length = 0;
  for (const path of ['/junk/../v1/sites/other/releases', '/junk/%2e%2e/v1/sites/other/releases']) {
    expectAuth(await send(f, path), 'OWA_AUTH_MISSING');
    expectAuth(await send(f, path, { token: mint(['read']) }), 'OWA_AUTH_SITE', 403);
  }
  assert.equal(f.calls.length, 0, 'normalized control aliases cannot reach another site or public fallback');
  const own = await send(f, '/junk/../v1/sites/demo/releases', { token: mint(['read']) });
  assert.equal(own.status, 200); assert.ok(json(own).site.slug === 'demo', 'authorized own-scope control alias retains baseline dispatch');
});
