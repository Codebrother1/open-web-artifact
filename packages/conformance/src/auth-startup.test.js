import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import { request as httpRequest } from 'node:http';
import { connect } from 'node:net';
import { mkdtemp, readdir, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { isAbsolute, join, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createToken } from '../../server/src/auth.js';
import { SHARED_ORIGIN_WARNING } from '../../server/src/index.js';

// Exercise main in a real Node child, never createArtifactServer or a test loader.
// All security inputs are fixed and synthetic. Only ports/temp paths are dynamic;
// timeouts synchronize resources, not claims. Never print captured output, tokens,
// signed URLs, request objects, or assertion diffs containing response bodies.
const SERVER = fileURLToPath(new URL('../../server/src/index.js', import.meta.url));
const REPO = fileURLToPath(new URL('../../../', import.meta.url));
const SECRET = Buffer.alloc(32, 0x53).toString('utf8');
const SHORT_SECRET = Buffer.alloc(31, 0x73).toString('utf8');
const SITE = 'startup-demo';
const OTHER_SITE = 'startup-other';
const JTI = 'startup-synthetic-audit';
const LIMIT = 64 * 1024;
const WAIT_MS = 10000;
const STARTUP_ERROR = 'artifactd startup failed; check authentication and storage configuration\n';
const digest = bytes => `sha256:${createHash('sha256').update(bytes).digest('hex')}`;
const EMPTY_DIGEST = digest(Buffer.alloc(0));
// Literal pack-equivalent fixture: keys are already in canonical ASCII order,
// including file keys. Hash independently with crypto, not the server's helpers.
const MANIFEST = {
  access: { visibility: 'unlisted' },
  artifactType: 'application/vnd.openwebartifact.site.v1+json',
  entrypoint: '/index.html',
  files: [{ digest: EMPTY_DIGEST, mediaType: 'text/html; charset=utf-8', path: '/index.html', size: 0 }],
  lifecycle: { expiresAt: null },
  specVersion: 'owa.dev/v1'
};
const PLAN = { manifest: MANIFEST, artifactDigest: digest(JSON.stringify(MANIFEST)) };

function environment(dataDir, overrides) {
  const env = { ...process.env };
  for (const key of Object.keys(env)) {
    if (/^OWA_/i.test(key) || /^(PORT|HOST|NODE_OPTIONS|NODE_PATH)$/i.test(key)) delete env[key];
  }
  return { ...env, NODE_ENV: 'production', OWA_STORAGE: 'filesystem', OWA_DATA_DIR: dataDir,
    PORT: '0', HOST: '127.0.0.1', ...overrides };
}

async function bounded(promise, message) {
  let timer;
  try {
    return await Promise.race([promise, new Promise((_, reject) => {
      timer = setTimeout(() => reject(new Error(message)), WAIT_MS);
    })]);
  } finally { clearTimeout(timer); }
}

async function launch(t, { args = [], env = {} } = {}) {
  const temporaryBase = resolve(tmpdir());
  const rel = relative(REPO, temporaryBase);
  assert.ok(rel === '..' || rel.startsWith(`..${process.platform === 'win32' ? '\\' : '/'}`) || isAbsolute(rel),
    'temporary storage must be outside the repository');
  const root = await mkdtemp(join(temporaryBase, 'owa-auth-startup-'));
  const dataDir = join(root, 'data'); // Deliberately absent until main opens stores.
  const state = { root, dataDir, stdout: '', stderr: '', overflow: false, spawnFailed: false,
    closed: false, forbidden: [SECRET, SHORT_SECRET] };
  let child;
  t.after(async () => {
    try {
      if (child && !state.closed) {
        child.kill('SIGTERM');
        try { await bounded(state.exit, 'server did not exit after SIGTERM'); }
        catch {
          child.kill('SIGKILL');
          await bounded(state.exit, 'server did not exit after SIGKILL');
          throw new Error('server cleanup required SIGKILL');
        }
      }
      assert.ok(!state.overflow, 'child output stays within the capture limit');
      const output = state.stdout + state.stderr;
      for (const value of state.forbidden) assert.ok(!output.includes(value), 'child never prints a secret or bearer');
      assert.ok(!output.includes('Bearer ') && !/owa1\.[A-Za-z0-9_-]+\./.test(output), 'child never prints serialized bearers');
      assert.ok(!output.includes('[cause]') && !output.includes('    at '), 'child never prints nested causes or stacks');
    } finally { await rm(root, { recursive: true, force: true }); }
  });
  child = spawn(process.execPath, [SERVER, ...args], {
    cwd: root, env: environment(dataDir, env), stdio: ['ignore', 'pipe', 'pipe']
  });
  let ready;
  state.ready = new Promise(resolveReady => { ready = resolveReady; });
  state.exit = new Promise(resolveExit => {
    child.once('error', () => { state.spawnFailed = true; ready(null); });
    child.once('close', (code, signal) => {
      state.closed = true; ready(null); resolveExit({ code, signal });
    });
  });
  for (const name of ['stdout', 'stderr']) {
    child[name].setEncoding('utf8');
    child[name].on('data', chunk => {
      if (Buffer.byteLength(state[name]) + Buffer.byteLength(chunk) > LIMIT) {
        state.overflow = true; child.kill('SIGTERM'); return;
      }
      state[name] += chunk;
      if (name === 'stdout') {
        const match = /^artifactd \(filesystem, auth (required|dev)\) listening on port ([0-9]+)\n/m.exec(state.stdout);
        if (match) ready({ mode: match[1], port: Number(match[2]) });
      }
    });
    child[name].on('error', () => { state.spawnFailed = true; ready(null); });
  }
  return state;
}

async function running(state, mode) {
  const ready = await bounded(state.ready, 'server readiness log timed out');
  assert.ok(ready !== null && !state.spawnFailed && !state.closed, 'server remains running after readiness');
  assert.ok(ready.mode === mode, 'readiness reports the selected auth mode');
  assert.ok(Number.isInteger(ready.port) && ready.port > 0 && ready.port <= 65535, 'PORT=0 log reports the actual bound port');
  // Successful startup prints nothing on stderr except, when no content origin
  // is configured, the one fixed shared-origin topology warning. Secret, bearer,
  // cause and stack-trace exclusion is asserted separately over stdout+stderr.
  assert.ok(state.stderr === '' || state.stderr === `${SHARED_ORIGIN_WARNING}\n`,
    'successful startup has no stderr beyond the fixed topology warning');
  assert.ok(state.stdout === `artifactd (filesystem, auth ${mode}) listening on port ${ready.port}\n`, 'startup emits only the static readiness line');
  state.port = ready.port;
  return state;
}

function send(state, path, { method = 'GET', token, json, headers = {} } = {}) {
  const payload = json === undefined ? null : Buffer.from(JSON.stringify(json));
  return new Promise((resolveResponse, reject) => {
    let timer, settled = false;
    const finish = (error, value) => {
      if (settled) return;
      settled = true; clearTimeout(timer);
      if (error) reject(new Error(error)); else resolveResponse(value);
    };
    const req = httpRequest({ hostname: '127.0.0.1', port: state.port, path, method, agent: false,
      headers: { connection: 'close', ...headers,
        ...(token === undefined ? {} : { authorization: `Bearer ${token}` }),
        ...(payload === null ? {} : { 'content-type': 'application/json', 'content-length': String(payload.length) }) }
    }, res => {
      let text = '';
      res.setEncoding('utf8');
      res.on('data', chunk => {
        if (Buffer.byteLength(text) + Buffer.byteLength(chunk) > LIMIT) {
          finish('HTTP response exceeded capture limit'); res.destroy(); req.destroy(); return;
        }
        text += chunk;
      });
      res.on('error', () => finish('HTTP response failed'));
      res.on('aborted', () => finish('HTTP response aborted'));
      res.on('end', () => {
        let body;
        try { body = JSON.parse(text); } catch { finish('HTTP response was not JSON'); return; }
        finish(null, { status: res.statusCode, headers: res.headers, body, text });
      });
    });
    req.on('error', () => finish('local HTTP request failed'));
    timer = setTimeout(() => { finish('local HTTP request timed out'); req.destroy(); }, WAIT_MS);
    req.end(payload);
  });
}

// A wildcard listener would accept another IPv4 loopback address, even though
// 127.0.0.1 works too. Probe it directly rather than trusting Host or a log label.
async function expectLoopbackOnly(state) {
  const accepted = await new Promise((resolveProbe, reject) => {
    const socket = connect({ host: '127.0.0.2', port: state.port });
    const timer = setTimeout(() => { socket.destroy(); reject(new Error('loopback binding probe timed out')); }, WAIT_MS);
    socket.once('connect', () => { clearTimeout(timer); socket.destroy(); resolveProbe(true); });
    socket.once('error', error => {
      clearTimeout(timer); socket.destroy();
      if (error.code === 'ECONNREFUSED') resolveProbe(false);
      else reject(new Error('loopback binding probe failed'));
    });
  });
  assert.ok(!accepted, 'explicit dev ignores HOST=0.0.0.0 and binds only 127.0.0.1');
}

function expectAuth(response, code, status, message) {
  assert.equal(response.status, status, 'auth gate status');
  assert.ok(JSON.stringify(response.body) === JSON.stringify({ error: message, code }), 'auth error is only its static envelope');
  assert.ok(response.headers['cache-control'] === 'no-store', 'auth errors are not cached');
  assert.ok(response.headers['www-authenticate'] === (status === 401 ? 'Bearer realm="owa"' : undefined), 'only 401 sends a Bearer challenge');
}

async function expectHealth(state, headers = {}) {
  const response = await send(state, '/health', { headers });
  assert.equal(response.status, 200, 'public health remains available');
  assert.ok(JSON.stringify(response.body) === JSON.stringify({ ok: true, spec: 'owa.dev/v1' }), 'public health body is fixed');
}

function expectPlan(response, required) {
  assert.equal(response.status, 200, 'literal zero-byte-file plan succeeds');
  assert.ok(response.body?.slug === SITE && response.body.artifactDigest === PLAN.artifactDigest, 'plan has the expected site and independent manifest hash');
  assert.ok(response.body.reused === 0 && response.body.uploads?.length === 1, 'missing empty blob produces exactly one upload');
  const upload = response.body.uploads[0];
  assert.ok(upload.digest === EMPTY_DIGEST && upload.method === 'PUT', 'upload instruction addresses the empty blob');
  assert.ok(required ? upload.authorization === 'bearer' : !Object.hasOwn(upload, 'authorization'), 'only required mode marks uploads as bearer protected');
  let url;
  try { url = new URL(upload.url); } catch { throw new Error('upload instruction has an invalid URL'); }
  assert.ok(required ? url.searchParams.get('site') === SITE : !url.searchParams.has('site'), 'only required mode scopes the upload URL');
}

for (const scenario of [
  { name: 'missing secret', env: {} },
  { name: '31-byte secret', env: { OWA_AUTH_SECRET: SHORT_SECRET } },
  { name: 'invalid auth mode', env: { OWA_AUTH_MODE: 'startup-invalid-mode', OWA_AUTH_SECRET: SECRET } }
]) {
  test(`executable production startup rejects ${scenario.name} before storage/listening`, { timeout: 30000 }, async t => {
    const state = await launch(t, { env: scenario.env });
    const result = await bounded(state.exit, 'invalid startup did not exit');
    assert.ok(!state.spawnFailed, 'Node executable started successfully');
    assert.equal(result.code, 1, 'configuration failure exits 1');
    assert.equal(result.signal, null, 'configuration failure exits without a signal');
    assert.ok(state.stdout === '', 'failure never announces a listener or success');
    assert.ok(state.stderr === STARTUP_ERROR, 'failure prints only the static diagnostic, not config or nested causes');
    assert.equal((await readdir(state.root)).length, 0, 'failure creates neither storage nor a fallback data directory');
  });
}

for (const scenario of [
  { name: '--dev', args: ['--dev'], env: { HOST: '0.0.0.0' } },
  { name: 'OWA_AUTH_MODE=dev', args: [], env: { HOST: '0.0.0.0', OWA_AUTH_MODE: 'dev' } }
]) {
  test(`executable ${scenario.name} is direct-loopback-only and permits tokenless local operations`, { timeout: 30000 }, async t => {
    const state = await running(await launch(t, scenario), 'dev');
    await expectHealth(state);
    await expectLoopbackOnly(state);
    expectPlan(await send(state, `/v1/sites/${SITE}/publish/plan`, { method: 'POST', json: PLAN }), false);
    const read = await send(state, `/v1/sites/${SITE}/releases`);
    assert.equal(read.status, 404, 'tokenless read passes auth and reaches the missing-site lookup');
    assert.ok(JSON.stringify(read.body) === JSON.stringify({ error: 'site not found' }), 'read reaches the expected route');
    for (const headers of [{ Forwarded: 'for=127.0.0.1;proto=http' }, { 'X-Forwarded-Proto': 'https' }]) {
      for (const [path, options] of [
        [`/v1/sites/${SITE}/publish/plan`, { method: 'POST', json: PLAN }],
        [`/v1/sites/${SITE}/releases`, {}]
      ]) {
        expectAuth(await send(state, path, { ...options, headers }), 'OWA_AUTH_DEV_ONLY', 403,
          'Development authentication requires a direct loopback connection');
      }
      await expectHealth(state, headers);
    }
    await expectHealth(state);
  });
}

test('executable required mode enforces bearer auth and site scope with a 32-byte secret', { timeout: 30000 }, async t => {
  // Fixed claims are valid against the real executable's current Unix clock;
  // no Date.now-derived fixture, sleep, or injected server clock is needed.
  const token = createToken({ secret: SECRET, jti: JTI, exp: Number.MAX_SAFE_INTEGER,
    sites: [SITE], capabilities: ['plan', 'upload', 'read'], now: () => 0 });
  const state = await running(await launch(t, { env: { OWA_AUTH_MODE: 'required', OWA_AUTH_SECRET: SECRET } }), 'required');
  state.forbidden.push(token, JTI);
  await expectHealth(state);
  expectAuth(await send(state, `/v1/sites/${SITE}/publish/plan`, { method: 'POST', json: PLAN }),
    'OWA_AUTH_MISSING', 401, 'Authentication required');
  expectAuth(await send(state, `/v1/sites/${SITE}/releases`), 'OWA_AUTH_MISSING', 401, 'Authentication required');
  expectPlan(await send(state, `/v1/sites/${SITE}/publish/plan`, { method: 'POST', json: PLAN, token }), true);
  const read = await send(state, `/v1/sites/${SITE}/releases`, { token });
  assert.equal(read.status, 404, 'correct scoped bearer passes auth to the missing-site lookup');
  assert.ok(JSON.stringify(read.body) === JSON.stringify({ error: 'site not found' }), 'authorized read reaches storage');
  for (const [path, options] of [
    [`/v1/sites/${OTHER_SITE}/publish/plan`, { method: 'POST', json: PLAN }],
    [`/v1/sites/${OTHER_SITE}/releases`, {}]
  ]) {
    const denied = await send(state, path, { ...options, token });
    expectAuth(denied, 'OWA_AUTH_SITE', 403, 'Authentication does not permit this site');
    for (const value of [SECRET, token, JTI, SITE, OTHER_SITE]) {
      assert.ok(!denied.text.includes(value), 'wrong-site denial discloses no secret, bearer, audit ID, or site');
    }
    assert.ok(!/\b[rs]_[0-9a-f]{20}\b/.test(denied.text), 'wrong-site denial discloses no stored IDs');
  }
  await expectHealth(state);
});
