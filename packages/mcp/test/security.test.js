import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import { once } from 'node:events';
import { mkdtemp, mkdir, rm, symlink, writeFile } from 'node:fs/promises';
import { createServer } from 'node:http';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { Client } from '@modelcontextprotocol/client';
import { StdioClientTransport } from '@modelcontextprotocol/client/stdio';
import { artifactDigest, validateManifest } from '../../spec/src/index.js';
import { S3BlobStore } from '../../storage-s3/src/index.js';

// These are deliberately synthetic canaries, never operator credentials. Only
// the child environment supplies OWA_TOKEN; no production adapter internals,
// in-memory MCP transport, direct packer, or direct store writes are used.
const TOKEN = 'owa1.security_test_process_secret.signature_test_only';
const PROVIDER_SECRET = 'synthetic_provider_error_secret_9d172';
const SIGNED_URL = 'https://storage.invalid/private?X-Amz-Credential=SYNTHETIC&X-Amz-Signature=never-a-real-signature';
const FILE_BYTES = '<!doctype html><title>private fixture bytes must not reach MCP</title>';
const ASSET_BYTES = 'private fixture asset bytes must not reach MCP';
const SITE = 'security-site';
const RELEASE = `r_${'a'.repeat(20)}`;
const DIGEST = `sha256:${'b'.repeat(64)}`;
const ENTRY = fileURLToPath(new URL('../src/index.js', import.meta.url));
const CWD = dirname(dirname(ENTRY));
const POISON = { message: PROVIDER_SECRET, url: SIGNED_URL, cause: { message: TOKEN, cause: { stack: `${PROVIDER_SECRET} ${SIGNED_URL}` } } };
const ERRORS = {
  OWA_MCP_INVALID_INPUT: ['invalid_input', 'Invalid input'],
  OWA_MCP_INVALID_RESPONSE: ['invalid_response', 'Invalid control-plane response'],
  OWA_MCP_CONTROL_FAILED: ['control_plane', 'Control-plane request failed'],
  OWA_MCP_UPLOAD_FAILED: ['upload', 'Blob upload failed'],
  OWA_MCP_NETWORK_FAILED: ['network', 'Network request failed'],
  OWA_AUTH_CONFIG: ['configuration', 'Invalid authentication configuration'],
  OWA_AUTH_INVALID_TOKEN: ['authentication', 'Invalid authentication token'],
  OWA_AUTH_INVALID_SIGNATURE: ['authentication', 'Invalid authentication signature'],
  OWA_AUTH_EXPIRED: ['authentication', 'Authentication token expired'],
  OWA_AUTH_MISSING: ['authentication', 'Authentication required'],
  OWA_AUTH_SITE: ['site_scope', 'Authentication does not permit this site'],
  OWA_AUTH_CAPABILITY: ['capability', 'Authentication does not permit this operation'],
  OWA_AUTH_DEV_ONLY: ['authentication', 'Development authentication requires a direct loopback connection']
};

function checkClean(value, extra = []) {
  const text = typeof value === 'string' ? value : JSON.stringify(value);
  for (const secret of [TOKEN, PROVIDER_SECRET, SIGNED_URL, FILE_BYTES, ASSET_BYTES,
    'SYNTHETIC_ACCESS_KEY', 'synthetic-s3-secret-never-real', 'synthetic-s3-session-token', ...extra]) {
    // Never let node:assert include a token, provider body, URL or path in TAP.
    assert.ok(!text.includes(secret), 'MCP output must not disclose a sensitive canary');
  }
}

function checkTool(result, code, status) {
  checkClean(result);
  const data = result?.structuredContent;
  assert.ok(data !== null && typeof data === 'object', 'Tool result must be structured');
  assert.ok(result.content?.length === 1 && result.content[0].type === 'text', 'Tool result must have one JSON text block');
  let parsed;
  try { parsed = JSON.parse(result.content[0].text); } catch { assert.fail('Tool text must be JSON'); }
  assert.ok(JSON.stringify(parsed) === JSON.stringify(data), 'Text and structured results must agree');
  if (code) {
    const [category, message] = ERRORS[code];
    const expected = { ok: false, error: { code, category, message, ...(status === undefined ? {} : { status }) } };
    assert.ok(JSON.stringify(data) === JSON.stringify(expected), `Expected fixed ${code} result`);
    assert.ok(result.isError === true, 'Failure must carry isError');
  } else {
    assert.ok(data.ok === true && result.isError !== true, 'Expected successful tool result');
  }
  return data;
}

function childEnv(root, origin, changes = {}) {
  // Do not inherit operator OWA_*, NODE_OPTIONS, proxies or provider credentials.
  const env = { PATH: process.env.PATH ?? '', OWA_MCP_ROOT: root, OWA_MCP_SERVER: origin, OWA_TOKEN: TOKEN, ...changes };
  for (const key of Object.keys(env)) if (env[key] === undefined) delete env[key];
  return env;
}

async function listen(t, handler) {
  const errors = [];
  const server = createServer((req, res) => {
    Promise.resolve(handler(req, res)).catch(() => {
      errors.push(true);
      if (!res.headersSent) res.writeHead(500);
      res.end('Fixture failed');
    });
  });
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  t.after(async () => {
    const closed = once(server, 'close');
    server.close();
    server.closeAllConnections();
    await closed;
    assert.ok(errors.length === 0, 'Local HTTP fixture must not fail');
  });
  return `http://127.0.0.1:${server.address().port}`;
}

async function body(req) {
  const chunks = [];
  for await (const chunk of req) chunks.push(chunk);
  return Buffer.concat(chunks);
}
function json(res, data, status = 200) {
  res.writeHead(status, { 'content-type': 'application/json' });
  res.end(JSON.stringify(data));
}
function fsGrant(origin, digest) {
  return { digest, method: 'PUT', authorization: 'bearer', url: `${origin}/v1/uploads/${encodeURIComponent(digest)}?site=${SITE}&expires=2000000000&sig=${'c'.repeat(64)}` };
}

async function fixture(t, options = {}) {
  const home = await mkdtemp(join(tmpdir(), 'owa-mcp-isolation-'));
  t.after(() => rm(home, { recursive: true, force: true }));
  const root = join(home, 'staging');
  const site = join(root, 'site');
  const outside = join(home, 'outside');
  const sibling = `${root}-sibling`;
  for (const path of [site, outside, sibling, join(root, 'child-link')]) {
    await mkdir(path, { recursive: true });
    await writeFile(join(path, 'index.html'), FILE_BYTES);
  }
  await writeFile(join(site, 'asset.txt'), ASSET_BYTES);
  // Duplicate bytes intentionally test unique blob counts, not file counts.
  await writeFile(join(site, 'asset-copy.txt'), ASSET_BYTES);
  await mkdir(join(outside, 'nested'));
  await writeFile(join(outside, 'nested', 'index.html'), FILE_BYTES);
  await symlink(site, join(root, 'selected-link'));
  await symlink(outside, join(root, 'ancestor-link'));
  await symlink(join(outside, 'index.html'), join(root, 'child-link', 'leak.txt'));
  await symlink(root, join(home, 'root-link'));

  const state = { mode: {}, requests: [], puts: [], commits: [], plans: [], grants: [], stored: new Map(), sinkHits: 0, active: null };
  state.reset = mode => {
    state.mode = mode;
    state.requests.length = state.puts.length = state.commits.length = state.plans.length = 0;
    state.stored.clear();
    state.sinkHits = 0;
    state.active = null;
  };
  const sink = await listen(t, async (req, res) => {
    state.sinkHits++;
    await body(req);
    json(res, {});
  });
  async function receivePut(req, res, origin) {
    const bytes = await body(req);
    const url = new URL(req.url, origin);
    state.puts.push({ headers: { ...req.headers }, url, bytes });
    if (state.mode.putRedirect) {
      res.writeHead(state.mode.putRedirect, { location: `${sink}/redirect-target` });
      res.end(JSON.stringify(POISON));
      return;
    }
    if (state.mode.putError) { json(res, POISON, state.mode.putError); return; }
    const digest = `sha256:${createHash('sha256').update(bytes).digest('hex')}`;
    state.stored.set(digest, bytes);
    res.writeHead(204);
    res.end();
  }
  let storage;
  storage = await listen(t, (req, res) => receivePut(req, res, storage));
  let origin;
  origin = await listen(t, async (req, res) => {
    if (req.method === 'PUT') return receivePut(req, res, origin);
    const raw = await body(req);
    const data = raw.length ? JSON.parse(raw) : undefined;
    state.requests.push({ method: req.method, url: req.url, headers: { ...req.headers }, data });
    if (state.mode.disconnect) { req.socket.destroy(); return; }
    if (state.mode.controlRedirect) {
      res.writeHead(state.mode.controlRedirect, { location: `${sink}/redirect-target` });
      res.end(JSON.stringify(POISON));
      return;
    }
    if (state.mode.controlError) { json(res, { ...POISON, code: state.mode.authCode ?? PROVIDER_SECRET }, state.mode.controlError); return; }
    if (state.mode.badJson) { res.writeHead(state.mode.badJson); res.end(`not-json ${JSON.stringify(POISON)}`); return; }
    if (req.url.endsWith('/publish/plan')) {
      validateManifest(data.manifest);
      assert.ok(data.artifactDigest === artifactDigest(data.manifest), 'Control plan must receive canonical manifest digest');
      const digests = [...new Set(data.manifest.files.map(file => file.digest))];
      assert.ok(digests.length === 2 && data.manifest.files.length === 3, 'Plan must describe all fixture files and unique blobs');
      state.plans.push(data);
      let uploads = [];
      for (const digest of digests) {
        let grant;
        if (state.mode.kind === 'fs') grant = fsGrant(origin, digest);
        else if (state.mode.kind === 'unmarked-fs') { grant = fsGrant(origin, digest); delete grant.authorization; }
        else {
          const store = new S3BlobStore({
            endpoint: state.mode.sameOrigin ? origin : storage, bucket: 'fake-bucket',
            region: state.mode.region ?? 'auto', accessKeyId: 'SYNTHETIC_ACCESS_KEY',
            secretAccessKey: 'synthetic-s3-secret-never-real', sessionToken: 'synthetic-s3-session-token',
            now: () => new Date('2025-01-02T03:04:05.000Z')
          });
          // Only sign. All bytes must pass through the real MCP child and HTTP.
          grant = await store.createUpload(digest, { expires: 600 });
        }
        uploads.push(grant);
      }
      if (state.mode.grants) uploads = state.mode.grants(uploads, { origin, storage, digests });
      state.grants.push(...uploads.map(upload => upload.url).filter(url => typeof url === 'string'));
      let plan = { slug: SITE, artifactDigest: data.artifactDigest, uploads, reused: 0 };
      if (state.mode.poisonMetadata) plan = { ...plan, ...POISON, manifest: data.manifest };
      if (state.mode.plan) plan = state.mode.plan(plan);
      json(res, plan);
      return;
    }
    if (req.url.endsWith('/publish/commit')) {
      assert.ok(data.artifactDigest === artifactDigest(data.manifest), 'Commit must preserve canonical digest');
      assert.ok(data.manifest.files.every(file => state.stored.has(file.digest)), 'Commit must follow real successful PUTs');
      state.commits.push(data);
      if (data.activate !== false) state.active = RELEASE;
      let commit = { slug: SITE, artifactDigest: data.artifactDigest, releaseId: RELEASE, activeReleaseId: state.active };
      if (state.mode.poisonMetadata) commit = { ...commit, ...POISON, manifest: data.manifest, grant: state.grants[0] };
      if (state.mode.commit) commit = state.mode.commit(commit);
      json(res, commit);
      return;
    }
    if (req.url.endsWith('/releases')) {
      let listing = { site: { slug: SITE, activeReleaseId: RELEASE }, releases: [{ id: RELEASE, artifactDigest: DIGEST, createdAt: '2025-01-02T03:04:05.000Z' }] };
      if (state.mode.poisonMetadata) {
        listing = { ...listing, ...POISON };
        listing.site.debug = POISON;
        listing.releases[0] = { ...listing.releases[0], manifest: { files: [FILE_BYTES] }, ...POISON };
      }
      if (state.mode.listing) listing = state.mode.listing(listing);
      json(res, listing);
      return;
    }
    if (req.url.includes('/activate/')) {
      state.active = RELEASE;
      let activation = { slug: SITE, activeReleaseId: RELEASE };
      if (state.mode.poisonMetadata) activation = { ...activation, ...POISON };
      if (state.mode.activation) activation = state.mode.activation(activation);
      json(res, activation);
      return;
    }
    json(res, {}, 404);
  });

  const f = { home, root, site, outside, sibling, state, origin, storage, sink };
  if (options.noClient) return f;
  const transport = new StdioClientTransport({ command: process.execPath, args: [ENTRY], cwd: CWD, env: childEnv(root, origin), stderr: 'pipe' });
  const client = new Client({ name: 'owa-isolation-tests', version: '1.0.0' });
  let stderr = '';
  const messages = [];
  transport.stderr.on('data', chunk => { stderr += chunk.toString(); });
  client.onerror = () => {}; // Check actual wire errors below, not SDK stack traces.
  t.after(async () => {
    await client.close();
    checkClean(stderr, [...state.grants, home]);
    checkClean(messages, [...state.grants, home]);
    assert.ok(stderr === '', 'Normal MCP session must not write diagnostics');
  });
  try { await client.connect(transport, { timeout: 5000 }); }
  catch { assert.fail('Official MCP client must initialize over stdio'); }
  assert.ok(client.getServerVersion()?.name === 'owa-mcp', 'Must initialize the actual MCP adapter');
  const receive = transport.onmessage;
  transport.onmessage = message => { messages.push(message); receive(message); };
  const tools = await client.listTools();
  assert.ok(tools.tools.map(tool => tool.name).sort().join(',') === 'activate,list_releases,publish,rollback', 'Expected public tool surface');
  f.client = client;
  f.transport = transport;
  f.messages = messages;
  f.stderr = () => stderr;
  f.call = async (name = 'publish', args = {}) => {
    let result;
    try {
      result = await client.callTool({ name, arguments: { site: SITE, server: origin, ...(name === 'publish' ? { directory: 'site' } : {}), ...args } }, { timeout: 5000 });
    } catch (error) {
      checkClean(String(error), state.grants);
      assert.fail('Official MCP call must return a structured tool result');
    }
    checkClean(result, [...state.grants, home]);
    return result;
  };
  return f;
}

function checkControlCredentials(f) {
  assert.ok(f.state.requests.length > 0, 'Expected real control-plane HTTP requests');
  assert.ok(f.state.requests.every(request => request.headers.authorization === `Bearer ${TOKEN}`), 'Control requests must use only the process credential');
  assert.ok(f.state.requests.every(request => !request.url.includes(TOKEN)), 'Control credentials must never enter URLs');
}
function checkPublish(f, result, activate = true) {
  const data = checkTool(result);
  assert.ok(data.site === SITE && data.releaseId === RELEASE && data.artifactDigest === f.state.plans[0].artifactDigest, 'Publish must return canonical release metadata');
  assert.ok(data.uploaded === 2 && data.reused === 0, 'Publish counts must use unique blobs');
  assert.ok(data.activeReleaseId === (activate ? RELEASE : null), 'Publish activation must match request');
  // `url` appears only when the control plane returned a canonical content URL.
  // These fixtures configure no content origin, so the adapter must omit it
  // rather than synthesizing one; any other extra key is still a leak.
  const keys = Object.keys(data).sort().join(',');
  assert.ok(keys === 'activeReleaseId,artifactDigest,ok,releaseId,reused,site,uploaded', 'Publish must not expose manifests, grants or arbitrary metadata');
  assert.ok(!Object.hasOwn(data, 'url'), 'No public URL is invented when the server provides none');
  assert.ok(f.state.puts.length === 2 && f.state.commits.length === 1 && f.state.stored.size === 2, 'Publish must upload bytes and commit over HTTP');
  assert.ok(f.state.active === (activate ? RELEASE : null), 'Commit must have the expected response effect');
  assert.ok(f.state.puts.every(put => [FILE_BYTES, ASSET_BYTES].includes(put.bytes.toString())), 'Storage must receive the actual packed file bytes');
  checkControlCredentials(f);
}

test('security: official stdio publish isolates S3/R2 and same-origin storage credentials', { timeout: 30000 }, async t => {
  const f = await fixture(t);
  for (const sameOrigin of [false, true]) for (const region of ['us-east-1', 'auto']) {
    await t.test(`${region === 'auto' ? 'R2' : 'S3'} ${sameOrigin ? 'same' : 'separate'} origin`, async () => {
      f.state.reset({ sameOrigin, region });
      checkPublish(f, await f.call());
      for (const put of f.state.puts) {
        assert.ok(put.headers.authorization === undefined, 'Unmarked storage PUT must never receive OWA authorization');
        assert.ok(put.url.origin === (sameOrigin ? f.origin : f.storage), 'PUT must reach the selected local provider');
        const query = put.url.searchParams;
        assert.ok(query.get('X-Amz-Algorithm') === 'AWS4-HMAC-SHA256', 'S3 algorithm must survive the HTTP request');
        assert.ok(query.get('X-Amz-Date') === '20250102T030405Z' && query.get('X-Amz-Expires') === '600', 'Fixed signer date and expiry must survive');
        assert.ok(query.get('X-Amz-SignedHeaders') === 'host;if-none-match;x-amz-checksum-sha256', 'Provider signs host plus the integrity-binding storage headers, never OWA material');
        assert.ok(typeof put.headers['x-amz-checksum-sha256'] === 'string' && put.headers['if-none-match'] === '*', 'CLI sends exactly the grant storage headers with the PUT');
        assert.ok(query.get('X-Amz-Credential') === `SYNTHETIC_ACCESS_KEY/20250102/${region}/s3/aws4_request`, 'Expected fake provider credential scope');
        assert.ok(query.get('X-Amz-Security-Token') === 'synthetic-s3-session-token', 'Provider session token must stay in the grant');
        assert.ok(/^[0-9a-f]{64}$/.test(query.get('X-Amz-Signature')), 'Provider signature must be present');
      }
    });
  }
  await t.test('validated FS marker receives process bearer; false stages rather than activates', async () => {
    f.state.reset({ kind: 'fs' });
    checkPublish(f, await f.call('publish', { activate: false }), false);
    assert.ok(f.state.commits[0].activate === false, 'Staging flag must reach commit');
    assert.ok(f.state.puts.every(put => put.headers.authorization === `Bearer ${TOKEN}`), 'Validated FS PUT must receive process bearer');
  });
  await t.test('same FS URL without an explicit marker receives no bearer', async () => {
    f.state.reset({ kind: 'unmarked-fs' });
    checkPublish(f, await f.call());
    assert.ok(f.state.puts.every(put => put.headers.authorization === undefined), 'URL shape alone must not authorize credential forwarding');
  });
});

test('security: reject every invalid upload grant before the first PUT', { timeout: 30000 }, async t => {
  const f = await fixture(t);
  const cases = [
    ['external bearer marker', (g, c) => ({ ...g, url: g.url.replace(c.origin, c.storage) })],
    ['wrong site', g => ({ ...g, url: g.url.replace(`site=${SITE}`, 'site=other-site') })],
    ['wrong URL digest', g => ({ ...g, url: g.url.replace(encodeURIComponent(g.digest), encodeURIComponent(DIGEST)) })],
    ['unknown marker', g => ({ ...g, authorization: 'provider-magic' })],
    ['null marker', g => ({ ...g, authorization: null })],
    ['arbitrary authorization headers', g => ({ ...g, headers: { authorization: `Bearer ${PROVIDER_SECRET}` } })],
    ['even empty headers', g => ({ ...g, headers: {} })],
    ['wrong method', g => ({ ...g, method: 'POST' })],
    ['unknown blob digest', g => ({ ...g, digest: DIGEST })],
    ['duplicate site', g => ({ ...g, url: `${g.url}&site=${SITE}` })],
    ['extra query', g => ({ ...g, url: `${g.url}&debug=1` })],
    ['non-numeric expiry', g => ({ ...g, url: g.url.replace('2000000000', 'NaN') })],
    ['unsafe integer expiry', g => ({ ...g, url: g.url.replace('2000000000', '999999999999999999') })],
    ['malformed signature', g => ({ ...g, url: g.url.replace('c'.repeat(64), 'bad') })],
    ['path normalization', g => ({ ...g, url: g.url.replace('/v1/uploads/', '/v1/extra/../uploads/') })],
    ['URL userinfo', g => ({ ...g, url: g.url.replace('http://', `http://${PROVIDER_SECRET}@`) })],
    ['URL fragment', g => ({ ...g, url: `${g.url}#fragment` })],
    ['URL backslash', g => ({ ...g, url: g.url.replace('/v1/', '/v1\\') })],
    ['non-HTTP URL', g => ({ ...g, url: `file:///tmp/${PROVIDER_SECRET}` })]
  ];
  for (const [label, change] of cases) await t.test(label, async () => {
    // A valid instruction comes first: late invalid grants must still stop ALL PUTs.
    f.state.reset({ kind: 'fs', grants: (uploads, context) => [uploads[0], change(uploads[1], context)] });
    checkTool(await f.call(), 'OWA_MCP_INVALID_RESPONSE');
    assert.ok(f.state.plans.length === 1 && f.state.puts.length === 0 && f.state.commits.length === 0, 'Grant validation must finish before any PUT or commit');
  });
  await t.test('duplicate digest instructions', async () => {
    f.state.reset({ kind: 'fs', grants: uploads => [uploads[0], uploads[0]] });
    checkTool(await f.call(), 'OWA_MCP_INVALID_RESPONSE');
    assert.ok(f.state.puts.length === 0 && f.state.commits.length === 0, 'Duplicate grants must be rejected before PUT');
  });
});

test('security: redirects never follow control, bearer PUT or unmarked PUT destinations', { timeout: 30000 }, async t => {
  const f = await fixture(t);
  for (const status of [301, 302, 303, 307, 308]) {
    for (const phase of ['control', 'fs', 'unmarked']) await t.test(`${phase} redirect ${status}`, async () => {
      f.state.reset(phase === 'control' ? { controlRedirect: status } : { kind: phase === 'fs' ? 'fs' : undefined, putRedirect: status });
      checkTool(await f.call(), 'OWA_MCP_NETWORK_FAILED');
      assert.ok(f.state.sinkHits === 0, 'Redirect sink must receive zero requests');
      assert.ok(f.state.commits.length === 0 && f.state.stored.size === 0, 'Redirect failure must prevent storage effects and commit');
      if (phase !== 'control') {
        assert.ok(f.state.puts.length === 1, 'Only initial PUT may be attempted');
        assert.ok(f.state.puts[0].headers.authorization === (phase === 'fs' ? `Bearer ${TOKEN}` : undefined), 'Initial PUT must preserve its own credential policy');
      }
    });
  }
});

test('security: trust origin and argument validation reject locally with fixed input errors', { timeout: 30000 }, async t => {
  const f = await fixture(t);
  const inputs = [
    ['HTTPS origin mismatch before packing', 'publish', { server: 'https://127.0.0.1:1', directory: 'child-link' }],
    ['different local origin', 'publish', { server: f.sink }],
    ['userinfo', 'publish', { server: f.origin.replace('http://', `http://${PROVIDER_SECRET}@`) }],
    ['query', 'publish', { server: `${f.origin}?secret=${PROVIDER_SECRET}` }],
    ['fragment', 'publish', { server: `${f.origin}#${PROVIDER_SECRET}` }],
    ['path prefix', 'publish', { server: `${f.origin}/prefix` }],
    ['backslash', 'publish', { server: `${f.origin}\\prefix` }],
    ['HTTP nonloopback with token', 'publish', { server: 'http://192.0.2.1' }],
    ['server object', 'publish', { server: { secret: TOKEN } }],
    ['site type', 'publish', { site: 123 }],
    ['site array', 'publish', { site: [SITE] }],
    ['site traversal', 'publish', { site: '../outside' }],
    ['site newline', 'publish', { site: `${SITE}\n` }],
    ['site overlong', 'publish', { site: 's'.repeat(64) }],
    ['directory type', 'publish', { directory: { secret: TOKEN } }],
    ['activate type', 'publish', { activate: 'false' }],
    ['activate null', 'publish', { activate: null }],
    ['credential argument', 'publish', { token: TOKEN }],
    ['headers argument', 'list_releases', { headers: { authorization: TOKEN } }],
    ['missing release', 'activate', {}],
    ['release type', 'activate', { releaseId: 7 }],
    ['release newline', 'activate', { releaseId: `${RELEASE}\n` }],
    ['release path', 'rollback', { releaseId: '../outside' }],
    ['release arbitrary text', 'rollback', { releaseId: PROVIDER_SECRET }]
  ];
  for (const [label, name, args] of inputs) await t.test(label, async () => {
    f.state.reset({});
    checkTool(await f.call(name, args), 'OWA_MCP_INVALID_INPUT');
    assert.ok(f.state.requests.length === 0 && f.state.puts.length === 0 && f.state.sinkHits === 0, 'Invalid input must be rejected before all network access');
  });
  for (const [label, args] of [['array arguments', []], ['null arguments', null], ['missing required arguments', {}]]) await t.test(label, async () => {
    const result = await f.client.callTool({ name: 'publish', arguments: args }, { timeout: 5000 }).catch(() => null);
    // Invalid params can be rejected by the official SDK before adapter dispatch.
    if (result) checkTool(result, 'OWA_MCP_INVALID_INPUT');
    else {
      const error = f.messages.at(-1)?.error;
      assert.ok(error?.code === -32602 && error.message === 'Invalid parameters' && !Object.hasOwn(error, 'data'), 'SDK parameter errors must be fixed and sanitized');
    }
    assert.ok(f.state.requests.length === 0, 'Malformed arguments must not access HTTP');
  });
});

test('security: filesystem containment rejects escapes and symlinks before HTTP', { timeout: 20000 }, async t => {
  const f = await fixture(t);
  const cases = [
    ['parent escape', '../outside'], ['absolute outside', f.outside],
    ['sibling prefix', f.sibling], ['selected root symlink', 'selected-link'],
    ['ancestor symlink outside', 'ancestor-link/nested'], ['packer child symlink', 'child-link'],
    ['nonexistent directory', 'missing'], ['file not directory', 'site/index.html'],
    ['file URL', `file://${f.site}`], ['HTTP URL', `${f.origin}/site`], ['NUL path', 'site\0private'], ['empty path', '']
  ];
  for (const [label, directory] of cases) await t.test(label, async () => {
    f.state.reset({});
    checkTool(await f.call('publish', { directory }), 'OWA_MCP_INVALID_INPUT');
    assert.ok(f.state.requests.length === 0 && f.state.puts.length === 0, 'Filesystem rejection must precede HTTP');
  });
});

test('security: control/provider errors expose fixed categories and preserve all eight OWA auth codes', { timeout: 30000 }, async t => {
  const f = await fixture(t);
  for (const code of Object.keys(ERRORS).filter(code => code.startsWith('OWA_AUTH_'))) await t.test(code, async () => {
    f.state.reset({ controlError: 403, authCode: code });
    checkTool(await f.call('list_releases'), code, 403);
    checkControlCredentials(f);
  });
  for (const status of [400, 403, 429, 500, 503]) await t.test(`unrecognized provider control error ${status}`, async () => {
    f.state.reset({ controlError: status });
    checkTool(await f.call('list_releases'), 'OWA_MCP_CONTROL_FAILED', status);
  });
  for (const status of [400, 403, 500, 503]) await t.test(`unmarked storage error ${status}`, async () => {
    f.state.reset({ putError: status });
    checkTool(await f.call(), 'OWA_MCP_UPLOAD_FAILED', status);
    assert.ok(f.state.puts.length === 1 && f.state.puts[0].headers.authorization === undefined, 'Failed provider PUT must never receive OWA bearer');
    assert.ok(f.state.commits.length === 0 && f.state.stored.size === 0, 'Provider error must stop all subsequent effects');
  });
  for (const status of [200, 502]) await t.test(`non-JSON poisoned body ${status}`, async () => {
    f.state.reset({ badJson: status });
    checkTool(await f.call('list_releases'), status === 200 ? 'OWA_MCP_INVALID_RESPONSE' : 'OWA_MCP_CONTROL_FAILED', status === 200 ? undefined : status);
  });
  await t.test('local network disconnect has no nested-cause output', async () => {
    f.state.reset({ disconnect: true });
    checkTool(await f.call('list_releases'), 'OWA_MCP_NETWORK_FAILED');
  });
});

test('security: response projection excludes manifests, signed URLs and poisoned metadata', { timeout: 30000 }, async t => {
  const f = await fixture(t);
  for (const name of ['publish', 'list_releases', 'activate', 'rollback']) await t.test(`extra metadata on ${name}`, async () => {
    f.state.reset({ poisonMetadata: true });
    const result = await f.call(name, ['activate', 'rollback'].includes(name) ? { releaseId: RELEASE } : {});
    if (result.structuredContent?.ok === false) checkTool(result, 'OWA_MCP_INVALID_RESPONSE');
    else {
      const data = checkTool(result);
      if (name === 'publish') checkPublish(f, result);
      if (name === 'list_releases') {
        assert.ok(Object.keys(data).sort().join(',') === 'activeReleaseId,ok,releases,site', 'Listing must expose only declared metadata');
        assert.ok(data.releases.every(release => Object.keys(release).sort().join(',') === 'artifactDigest,createdAt,releaseId'), 'Release projection must strip full manifests');
      }
      if (name === 'activate' || name === 'rollback') assert.ok(Object.keys(data).sort().join(',') === 'activeReleaseId,ok,site', 'Activation must expose only declared metadata');
    }
  });
  const cases = [
    ['plan total mismatch', { plan: p => ({ ...p, reused: 1 }) }, 'publish'],
    ['plan wrong digest', { plan: p => ({ ...p, artifactDigest: DIGEST }) }, 'publish'],
    ['plan wrong slug', { plan: p => ({ ...p, slug: PROVIDER_SECRET }) }, 'publish'],
    ['plan uploads type', { plan: p => ({ ...p, uploads: POISON }) }, 'publish'],
    ['commit release poison', { commit: c => ({ ...c, releaseId: SIGNED_URL }) }, 'publish'],
    ['commit digest poison', { commit: c => ({ ...c, artifactDigest: TOKEN }) }, 'publish'],
    ['listing release poison', { listing: l => ({ ...l, releases: [{ ...l.releases[0], id: PROVIDER_SECRET }] }) }, 'list_releases'],
    ['listing invalid timestamp', { listing: l => ({ ...l, releases: [{ ...l.releases[0], createdAt: SIGNED_URL }] }) }, 'list_releases'],
    ['listing invalid active pointer', { listing: l => ({ ...l, site: { slug: SITE, activeReleaseId: TOKEN } }) }, 'list_releases'],
    ['activation poison', { activation: a => ({ ...a, activeReleaseId: TOKEN }) }, 'activate']
  ];
  for (const [label, mode, name] of cases) await t.test(label, async () => {
    f.state.reset(mode);
    checkTool(await f.call(name, name === 'activate' ? { releaseId: RELEASE } : {}), 'OWA_MCP_INVALID_RESPONSE');
    if (mode.plan) assert.ok(f.state.puts.length === 0 && f.state.commits.length === 0, 'Bad plans must have no upload effects');
  });
});

async function runRaw(t, env, frames = '') {
  const child = spawn(process.execPath, [ENTRY], { cwd: CWD, env, stdio: ['pipe', 'pipe', 'pipe'] });
  let stdout = '', stderr = '';
  child.stdout.on('data', chunk => { stdout += chunk.toString(); });
  child.stderr.on('data', chunk => { stderr += chunk.toString(); });
  child.stdin.on('error', () => {});
  const closed = once(child, 'close');
  const timer = setTimeout(() => child.kill('SIGKILL'), 5000);
  t.after(() => { clearTimeout(timer); if (child.exitCode === null) child.kill('SIGKILL'); });
  child.stdin.end(frames);
  const [code, signal] = await closed;
  clearTimeout(timer);
  checkClean(stdout);
  checkClean(stderr);
  assert.ok(signal === null, 'Child must exit without test timeout');
  return { code, stdout, stderr };
}

test('security: invalid startup configuration fails closed without leaking paths or environment', { timeout: 30000 }, async t => {
  const f = await fixture(t, { noClient: true });
  const cases = [
    ['missing root', { OWA_MCP_ROOT: undefined }], ['relative root', { OWA_MCP_ROOT: 'site' }],
    ['missing directory', { OWA_MCP_ROOT: join(f.home, PROVIDER_SECRET) }],
    ['file root', { OWA_MCP_ROOT: join(f.site, 'index.html') }],
    ['selected symlink root', { OWA_MCP_ROOT: join(f.home, 'root-link') }],
    ['URL root', { OWA_MCP_ROOT: `file://${f.root}` }],
    ['missing origin', { OWA_MCP_SERVER: undefined }],
    ['userinfo origin', { OWA_MCP_SERVER: f.origin.replace('http://', `http://${PROVIDER_SECRET}@`) }],
    ['query origin', { OWA_MCP_SERVER: `${f.origin}?${PROVIDER_SECRET}` }],
    ['fragment origin', { OWA_MCP_SERVER: `${f.origin}#${PROVIDER_SECRET}` }],
    ['path origin', { OWA_MCP_SERVER: `${f.origin}/${PROVIDER_SECRET}` }],
    ['backslash origin', { OWA_MCP_SERVER: `${f.origin}\\${PROVIDER_SECRET}` }],
    ['HTTP nonloopback origin', { OWA_MCP_SERVER: 'http://192.0.2.1' }],
    ['malformed process token', { OWA_TOKEN: `invalid ${PROVIDER_SECRET}` }]
  ];
  for (const [label, changes] of cases) await t.test(label, async sub => {
    const output = await runRaw(sub, childEnv(f.root, f.origin, changes));
    checkClean(output, [f.home]);
    assert.ok(output.code !== 0 && output.stdout === '', 'Invalid configuration must fail without protocol output');
    assert.ok(output.stderr === 'owa-mcp: OWA_MCP_CONFIG: Unable to start adapter\n', 'Startup must use only the fixed configuration diagnostic');
    assert.ok(f.state.requests.length === 0, 'Startup validation must not contact HTTP');
  });
});

test('security: SDK protocol sanitizer protects secret names, keys and methods', { timeout: 20000 }, async t => {
  const f = await fixture(t);
  for (const [label, request] of [
    ['unknown tool name', { method: 'tools/call', params: { name: TOKEN, arguments: {} } }],
    ['unknown argument property key', { method: 'tools/call', params: { name: 'publish', arguments: { site: SITE, server: f.origin, directory: 'site', [TOKEN]: true } } }],
    ['SDK-invalid field with secret key', { method: 'tools/call', params: { name: { [TOKEN]: true }, arguments: {} } }]
  ]) await t.test(label, async () => {
    f.state.reset({});
    const before = f.messages.length;
    try { await f.client.request(request, { timeout: 5000 }); } catch (error) { checkClean(String(error)); }
    const replies = f.messages.slice(before).filter(message => Object.hasOwn(message, 'id'));
    assert.ok(replies.length > 0, 'Negative request must exercise real SDK wire response');
    checkClean(replies);
    for (const reply of replies) {
      if (reply.error) {
        assert.ok([-32601, -32602].includes(reply.error.code), 'Expected fixed protocol error category');
        assert.ok(['Method not found', 'Invalid parameters'].includes(reply.error.message) && !Object.hasOwn(reply.error, 'data'), 'SDK error must drop all diagnostic text/data');
      } else checkTool(reply.result, 'OWA_MCP_INVALID_INPUT');
    }
    assert.ok(f.state.requests.length === 0 && f.state.puts.length === 0, 'Malformed protocol must not mutate HTTP state');
  });
  await t.test('unknown params property key is either rejected or safely stripped by SDK', async () => {
    f.state.reset({});
    const result = await f.client.request({ method: 'tools/call', params: { name: 'list_releases', arguments: { site: SITE, server: f.origin }, [TOKEN]: true } }, { timeout: 5000 });
    if (result.structuredContent?.ok === false) checkTool(result, 'OWA_MCP_INVALID_INPUT');
    else checkTool(result);
    checkClean(f.messages);
    assert.ok(f.state.puts.length === 0 && f.state.requests.every(request => request.method === 'GET'), 'SDK stripping an unknown params key must not introduce mutation');
  });
  await t.test('unknown request method reaches the initialized server through the official transport', async () => {
    f.state.reset({});
    const before = f.messages.length;
    // Client.request rejects unregistered methods locally (and may include the
    // caller-supplied method in its own error). Public Transport.send exercises
    // the server sanitizer rather than confusing that local error with output.
    await f.transport.send({ jsonrpc: '2.0', id: 900001, method: TOKEN, params: {} });
    const deadline = Date.now() + 3000;
    while (f.messages.length === before && Date.now() < deadline) await new Promise(resolve => setTimeout(resolve, 10));
    const reply = f.messages.slice(before).find(message => message.id === 900001);
    assert.ok(reply?.error?.code === -32601 && reply.error.message === 'Method not found', 'Unknown method must receive a fixed server error');
    assert.ok(!Object.hasOwn(reply.error, 'data'), 'Unknown-method errors must omit diagnostic data');
    assert.ok(f.state.requests.length === 0, 'Unknown method must not dispatch a tool');
    checkClean(f.messages);
  });
});

test('security: actual malformed JSON and invalid wire envelopes never echo secrets', { timeout: 20000 }, async t => {
  const f = await fixture(t, { noClient: true });
  const invalidEnvelope = JSON.stringify({ jsonrpc: 'not-2.0', id: TOKEN, method: 'tools/call', params: { [TOKEN]: SIGNED_URL } });
  const frames = [
    // SDK ReadBuffer deliberately drops JSON syntax errors. Follow one with an
    // invalid envelope to prove the real parser continues on the same stream.
    `{"jsonrpc":"2.0","id":"${TOKEN}","method":\n${invalidEnvelope}`,
    invalidEnvelope,
    JSON.stringify({ jsonrpc: '2.0', id: { [TOKEN]: SIGNED_URL }, method: 'tools/call' }),
    // The official client owns request ids and its receive schema rejects null
    // ids; raw negative input/output is necessary to assert null-id sanitation.
    JSON.stringify({ jsonrpc: '2.0', id: TOKEN, method: 'tools/call', params: { name: 'publish', arguments: { site: SITE, server: f.origin, directory: 'site' } } })
  ];
  for (let index = 0; index < frames.length; index++) await t.test(`negative raw frame ${index + 1}`, async sub => {
    // Raw stdin is restricted to frames the official client cannot serialize.
    // The production StdioServerTransport still performs all parsing/validation.
    const output = await runRaw(sub, childEnv(f.root, f.origin), `${frames[index]}\n`);
    assert.ok(output.code === 0, 'Malformed frames must not crash the process');
    assert.ok(output.stdout !== '' || output.stderr !== '', 'The actual SDK must observe the malformed frame');
    if (index === 3) assert.ok(output.stdout !== '', 'Secret-bearing request id must produce a null-id rejection');
    assert.ok(output.stderr.split('\n').filter(Boolean).every(line => line === 'owa-mcp: OWA_MCP_FAILED: Protocol operation failed'), 'Malformed-wire diagnostics must be fixed');
    for (const line of output.stdout.split('\n').filter(Boolean)) {
      let reply;
      try { reply = JSON.parse(line); } catch { assert.fail('Protocol stdout must contain JSON frames only'); }
      assert.ok(reply.id === null && [-32700, -32600].includes(reply.error?.code), 'Malformed wire must return only a sanitized protocol error');
      assert.ok(['Parse error', 'Invalid request'].includes(reply.error.message) && !Object.hasOwn(reply.error, 'data'), 'Wire errors must not contain SDK diagnostics');
    }
    assert.ok(f.state.requests.length === 0, 'Malformed frames must not contact control plane');
  });
});
