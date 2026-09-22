import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { request } from 'node:http';
import { createServer } from 'node:net';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createToken } from '../../server/src/auth.js';
import { SHARED_ORIGIN_WARNING, STARTUP_ABORTED } from '../../server/src/index.js';

// Executable-level startup regressions for the separated control/content
// topology. These spawn the REAL server entry point: a helper-function test
// could not observe a process that stays alive on one listener after the other
// failed, which is the defect these cover.
const SERVER = fileURLToPath(new URL('../../server/src/index.js', import.meta.url));
const AUTH_SECRET = 'listener-group-auth-secret-0123456789ab';
const UPLOAD_SECRET = 'listener-group-upload-secret-0123456789';
const WAIT_MS = 15_000;
const LIMIT = 64 * 1024;

function baseEnv(dataDir, overrides = {}) {
  const env = { ...process.env };
  for (const key of Object.keys(env)) {
    if (/^OWA_/i.test(key) || /^(PORT|HOST|NODE_OPTIONS|NODE_PATH)$/i.test(key)) delete env[key];
  }
  return {
    ...env,
    NODE_ENV: 'production',
    OWA_STORAGE: 'filesystem',
    OWA_DATA_DIR: dataDir,
    OWA_AUTH_SECRET: AUTH_SECRET,
    ...overrides
  };
}

function bounded(promise, message) {
  let timer;
  return Promise.race([
    promise.finally(() => clearTimeout(timer)),
    new Promise((_, reject) => { timer = setTimeout(() => reject(new Error(message)), WAIT_MS); })
  ]);
}

/** The child's lifecycle state for a failure message — never its output. */
function describeChild(state) {
  const { exitCode, signalCode } = state.child;
  return exitCode === null && signalCode === null ? 'child still running' : `child exited (code ${exitCode}, signal ${signalCode})`;
}

/**
 * Resolve with `ready(state.stdout)`'s value as soon as it is not undefined,
 * re-checking on every stdout chunk; reject if the child exits first, or when
 * `waitMs` elapses. Every settle path removes the stdout listener and clears
 * the timer, so a wait that fails leaves nothing behind that could keep the
 * test process alive. (A self-rescheduling poll raced against a deadline did
 * not stop when the deadline won, and its live timer kept `npm run test:auth`
 * from ever exiting after test 4 failed — the job then ran into the
 * workflow's 15-minute limit.)
 */
function awaitReadiness(state, ready, message, waitMs = WAIT_MS) {
  return new Promise((resolve, reject) => {
    let timer, settled = false;
    const settle = (fn, value) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      state.child.stdout.off('data', check);
      fn(value);
    };
    function check() {
      const value = ready(state.stdout);
      if (value !== undefined) settle(resolve, value);
    }
    timer = setTimeout(() => settle(reject, new Error(`${message} (${describeChild(state)})`)), waitMs);
    state.child.stdout.on('data', check);
    state.exit.then(({ code, signal }) => settle(reject, new Error(`${message}: child exited before readiness (code ${code}, signal ${signal})`)));
    check();
  });
}

/** Live timers in this process; a failed readiness wait must not add one. */
const activeTimers = () => process.getActiveResourcesInfo().filter(resource => resource === 'Timeout').length;

/** Bind a port, then release it, returning a port number that was free just now. */
async function borrowPort() {
  const probe = createServer();
  probe.listen(0, '127.0.0.1');
  await once(probe, 'listening');
  const { port } = probe.address();
  await new Promise(done => probe.close(done));
  return port;
}

/** Hold a port for the lifetime of a test so the child's bind must fail. */
async function holdPort(t, port) {
  const holder = createServer();
  holder.on('error', () => {});
  holder.listen(port, '127.0.0.1');
  await once(holder, 'listening');
  t.after(() => new Promise(done => holder.close(() => done())));
  return holder;
}

/** True when nothing is listening on the port, proven by binding it ourselves. */
async function portIsFree(port) {
  const probe = createServer();
  probe.on('error', () => {});
  probe.listen(port, '127.0.0.1');
  const [event] = await Promise.race([
    once(probe, 'listening').then(() => ['listening']),
    once(probe, 'error').then(() => ['error'])
  ]);
  if (event === 'listening') await new Promise(done => probe.close(done));
  return event === 'listening';
}

function launch(t, env, args = [], entry = SERVER) {
  const state = { stdout: '', stderr: '', overflow: false };
  const child = spawn(process.execPath, [entry, ...args], {
    cwd: resolve(tmpdir()), env, stdio: ['ignore', 'pipe', 'pipe']
  });
  state.child = child;
  state.exit = new Promise(done => child.once('close', (code, signal) => done({ code, signal })));
  for (const name of ['stdout', 'stderr']) {
    child[name].setEncoding('utf8');
    child[name].on('data', chunk => {
      if (Buffer.byteLength(state[name]) + Buffer.byteLength(chunk) > LIMIT) {
        state.overflow = true; child.kill('SIGKILL'); return;
      }
      state[name] += chunk;
    });
  }
  t.after(async () => {
    if (child.exitCode === null && child.signalCode === null) {
      child.kill('SIGKILL');
      await state.exit;
    }
  });
  return state;
}

/** Startup output must never carry credentials, causes, stacks or provider bodies. */
function assertSafeDiagnostics(state) {
  const output = state.stdout + state.stderr;
  assert.ok(!state.overflow, 'startup output stays bounded');
  assert.ok(!output.includes(AUTH_SECRET), 'never prints the auth secret');
  assert.ok(!output.includes(UPLOAD_SECRET), 'never prints the upload secret');
  assert.ok(!output.includes('Bearer ') && !/owa1\.[A-Za-z0-9_-]+\./.test(output), 'never prints bearer material');
  assert.ok(!output.includes('    at ') && !output.includes('[cause]'), 'never prints a stack or nested cause');
  assert.ok(!/EADDRINUSE|EACCES|errno|<\?xml|<Error>/.test(output), 'never prints an errno or provider error body');
  assert.ok(!output.includes(AUTH_SECRET.slice(0, 12)), 'never prints a secret prefix');
}

const SEPARATED = { OWA_CONTENT_BASE_DOMAIN: 'localhost', OWA_CONTENT_SCHEME: 'http' };

async function withDataDir(t) {
  const root = await mkdtemp(join(tmpdir(), 'owa-listener-group-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  return join(root, 'data');
}

function get(port, path, headers = {}) {
  return new Promise((done, fail) => {
    const req = request({ hostname: '127.0.0.1', port, path, method: 'GET', agent: false, headers: { connection: 'close', ...headers } }, res => {
      const chunks = [];
      res.on('data', chunk => chunks.push(chunk));
      res.on('end', () => done({ status: res.statusCode, body: Buffer.concat(chunks).toString('utf8') }));
    });
    req.setTimeout(5000, () => req.destroy(new Error('probe timeout')));
    req.on('error', fail);
    req.end();
  });
}

// ---------------------------------------------------------------- gate 1 ---

test('1. identical control/content bind target fails closed before anything listens', async t => {
  const dataDir = await withDataDir(t);
  const port = await borrowPort();
  const state = launch(t, baseEnv(dataDir, {
    ...SEPARATED,
    OWA_CONTROL_HOST: '127.0.0.1', OWA_CONTROL_PORT: String(port),
    OWA_CONTENT_LISTEN_HOST: '127.0.0.1', OWA_CONTENT_LISTEN_PORT: String(port)
  }));

  const { code } = await bounded(state.exit, 'process did not exit');
  assert.equal(code, 1, 'a same-address configuration must exit nonzero');
  assert.equal(state.stdout, '', 'no readiness is announced');
  assert.match(state.stderr, /same host and port/, 'the reason is stated in fixed terms');
  assert.equal(await portIsFree(port), true, 'no listener survives the failed startup');
  assertSafeDiagnostics(state);
});

test('2. a content bind failure closes the control listener that already bound', async t => {
  const dataDir = await withDataDir(t);
  const controlPort = await borrowPort();
  const contentPort = await borrowPort();
  await holdPort(t, contentPort); // The content listener cannot possibly bind.

  const state = launch(t, baseEnv(dataDir, {
    ...SEPARATED,
    OWA_CONTROL_HOST: '127.0.0.1', OWA_CONTROL_PORT: String(controlPort),
    OWA_CONTENT_LISTEN_HOST: '127.0.0.1', OWA_CONTENT_LISTEN_PORT: String(contentPort)
  }));

  const { code } = await bounded(state.exit, 'process did not exit');
  assert.equal(code, 1, 'the process must terminate nonzero, not linger on one listener');
  assert.equal(state.stdout, '', 'readiness is never announced for a half-started topology');
  assert.match(state.stderr, /artifactd content failed to bind/);
  assert.ok(state.stderr.includes(STARTUP_ABORTED), 'startup reports that nothing is running');
  // The decisive assertion: the control port is bindable again, so the control
  // listener that DID bind was closed rather than left serving.
  assert.equal(await portIsFree(controlPort), true, 'the bound control listener was closed');
  assertSafeDiagnostics(state);
});

test('3. the symmetric case also closes the content listener', async t => {
  const dataDir = await withDataDir(t);
  const controlPort = await borrowPort();
  const contentPort = await borrowPort();
  await holdPort(t, controlPort); // Now the CONTROL listener is the one that fails.

  const state = launch(t, baseEnv(dataDir, {
    ...SEPARATED,
    OWA_CONTROL_HOST: '127.0.0.1', OWA_CONTROL_PORT: String(controlPort),
    OWA_CONTENT_LISTEN_HOST: '127.0.0.1', OWA_CONTENT_LISTEN_PORT: String(contentPort)
  }));

  const { code } = await bounded(state.exit, 'process did not exit');
  assert.equal(code, 1);
  assert.equal(state.stdout, '');
  assert.match(state.stderr, /artifactd control failed to bind/);
  assert.equal(await portIsFree(contentPort), true, 'the content listener was closed too');
  assertSafeDiagnostics(state);
});

test('4. successful separated startup binds both listeners with the right route surfaces', async t => {
  const dataDir = await withDataDir(t);
  const controlPort = await borrowPort();
  const contentPort = await borrowPort();
  const state = launch(t, baseEnv(dataDir, {
    ...SEPARATED,
    OWA_CONTROL_HOST: '127.0.0.1', OWA_CONTROL_PORT: String(controlPort),
    OWA_CONTENT_LISTEN_HOST: '127.0.0.1', OWA_CONTENT_LISTEN_PORT: String(contentPort),
    OWA_CONTENT_PUBLIC_PORT: String(contentPort)
  }));

  await awaitReadiness(state,
    stdout => (/artifactd control .* listening on port \d+\nartifactd content .* listening on port \d+\n/.test(stdout) ? true : undefined),
    'both readiness lines timed out');

  // Readiness output is deterministic: control first, content second, one line each.
  assert.equal(state.stdout,
    `artifactd control (filesystem, auth required) listening on port ${controlPort}\n`
    + `artifactd content (filesystem, auth required) listening on port ${contentPort}\n`);
  assert.equal(state.stderr, '', 'a fully configured separated startup warns about nothing');

  // Control origin serves control routes and no artifact bytes.
  assert.equal((await get(controlPort, '/health')).status, 200);
  assert.equal((await get(controlPort, '/v1/sites/demo/releases')).status, 401, 'control auth is still enforced');
  assert.equal((await get(controlPort, '/', { host: 'demo.localhost' })).status, 404, 'control serves no content');

  // Content origin exposes no control route and requires no bearer.
  assert.equal((await get(contentPort, '/v1/sites/demo/releases', { host: 'demo.localhost' })).status, 404);
  assert.equal((await get(contentPort, '/health', { host: 'demo.localhost' })).status, 404);
  assert.equal((await get(contentPort, '/', { host: 'demo.localhost' })).status, 404, 'no site published yet');
  assert.equal((await get(contentPort, '/', { host: 'unbound.invalid' })).status, 404, 'unknown host is rejected');

  // A real token proves the control plane is the same authenticated surface.
  const token = createToken({
    secret: AUTH_SECRET, jti: 'listener-group', exp: Math.floor(Date.now() / 1000) + 600,
    sites: ['demo'], capabilities: ['read']
  });
  const authorized = await get(controlPort, '/v1/sites/demo/releases', { authorization: `Bearer ${token}` });
  assert.equal(authorized.status, 404, 'authorized read reaches the handler; the site simply does not exist');

  state.child.kill('SIGTERM');
  await bounded(state.exit, 'process did not exit after SIGTERM');
  assertSafeDiagnostics(state);
});

test('5. an invalid listener port is rejected instead of silently becoming ephemeral', async t => {
  // Number('nope') is NaN, and node would have bound a RANDOM port for it.
  for (const value of ['nope', '70000', '-1', '1.5', '0x10', ' 80']) {
    const dataDir = await withDataDir(t);
    const state = launch(t, baseEnv(dataDir, { ...SEPARATED, OWA_CONTENT_LISTEN_PORT: value }));
    const { code } = await bounded(state.exit, `process did not exit for port ${value}`);
    assert.equal(code, 1, `port ${JSON.stringify(value)} must fail closed`);
    assert.equal(state.stdout, '', 'no readiness for an invalid port');
    assertSafeDiagnostics(state);
  }
});

test('6. legacy shared-origin startup keeps its exact readiness and warning contract', async t => {
  const dataDir = await withDataDir(t);
  const state = launch(t, baseEnv(dataDir, { PORT: '0', HOST: '127.0.0.1' }));

  const ready = await awaitReadiness(state, stdout => {
    const match = /^artifactd \(filesystem, auth required\) listening on port (\d+)\n/m.exec(stdout);
    return match ? Number(match[1]) : undefined;
  }, 'legacy readiness timed out');

  assert.equal(state.stdout, `artifactd (filesystem, auth required) listening on port ${ready}\n`,
    'the pre-v0.4 readiness line is unchanged');
  assert.equal(state.stderr, `${SHARED_ORIGIN_WARNING}\n`, 'exactly the one fixed topology warning');
  assert.equal((await get(ready, '/health')).status, 200, 'the shared origin still serves control');

  state.child.kill('SIGTERM');
  await bounded(state.exit, 'process did not exit after SIGTERM');
  assertSafeDiagnostics(state);
});

// ------------------------------------------------- harness regressions ---
// A readiness wait that never succeeds must fail within its deadline and leave
// no live timer or listener, so the test process can exit and the failure is
// reported instead of the workflow's job timeout. The children here are stubs
// written into the test's own temporary directory, launched through the same
// `launch()` (and therefore the same kill-and-reap cleanup) as the real server.

async function stubEntry(dataDir, name, source) {
  const path = join(dirname(dataDir), name);
  await writeFile(path, source);
  return path;
}

test('7. a readiness wait that hits its deadline leaves no timer behind, and the never-ready child is killed and reaped', async t => {
  const dataDir = await withDataDir(t);
  const entry = await stubEntry(dataDir, 'never-ready.mjs', 'setInterval(() => {}, 1_000_000);\n'); // announces nothing, never exits by itself
  const timersBefore = activeTimers();
  const state = launch(t, baseEnv(dataDir), [], entry);
  // Runs after launch()'s own cleanup (hooks run in registration order): the
  // child must have been SIGKILLed and reaped, not left behind.
  t.after(async () => {
    const { code, signal } = await bounded(state.exit, 'never-ready child was not reaped');
    assert.equal(code, null); assert.equal(signal, 'SIGKILL');
    assert.throws(() => process.kill(state.child.pid, 0), { code: 'ESRCH' }, 'the child pid is gone');
  });
  const started = Date.now();
  await assert.rejects(awaitReadiness(state, () => undefined, 'stub readiness timed out', 300),
    { message: 'stub readiness timed out (child still running)' });
  assert.ok(Date.now() - started < WAIT_MS, 'the wait fails at its own deadline, not at the suite deadline');
  assert.equal(activeTimers(), timersBefore, 'the failed wait left no live timer to keep the process alive');
  assert.equal(state.child.stdout.listenerCount('data'), 1, 'the failed wait removed its stdout listener (only the capture listener remains)');
  assert.equal(state.child.exitCode, null, 'the child is still running here; cleanup must end it');
});

test('8. a readiness wait fails as soon as the child exits without announcing readiness, well before the deadline', async t => {
  const dataDir = await withDataDir(t);
  const entry = await stubEntry(dataDir, 'exit-early.mjs', 'process.exit(1);\n'); // e.g. a listener that failed to bind
  const timersBefore = activeTimers();
  const state = launch(t, baseEnv(dataDir), [], entry);
  const started = Date.now();
  await assert.rejects(awaitReadiness(state, () => undefined, 'stub readiness timed out'),
    { message: 'stub readiness timed out: child exited before readiness (code 1, signal null)' });
  assert.ok(Date.now() - started < WAIT_MS / 3, 'the exit is reported promptly instead of waiting out the deadline');
  assert.equal(activeTimers(), timersBefore, 'no live timer remains');
  assert.equal(state.child.stdout.listenerCount('data'), 1, 'the stdout listener was removed');
  const { code, signal } = await bounded(state.exit, 'exited child was not reaped');
  assert.equal(code, 1); assert.equal(signal, null);
});

test('9. a readiness wait that succeeds resolves with the parsed value and also leaves no timer behind', async t => {
  const dataDir = await withDataDir(t);
  const entry = await stubEntry(dataDir, 'ready.mjs', 'process.stdout.write("stub listening on port 4242\\n"); setInterval(() => {}, 1_000_000);\n');
  const timersBefore = activeTimers();
  const state = launch(t, baseEnv(dataDir), [], entry);
  const port = await awaitReadiness(state, stdout => { const match = /^stub listening on port (\d+)\n/m.exec(stdout); return match ? Number(match[1]) : undefined; }, 'stub readiness timed out');
  assert.equal(port, 4242);
  assert.equal(activeTimers(), timersBefore, 'the successful wait cleared its timer');
  assert.equal(state.child.stdout.listenerCount('data'), 1, 'the successful wait removed its stdout listener');
  state.child.kill('SIGTERM');
  const { signal } = await bounded(state.exit, 'stub did not exit after SIGTERM');
  assert.equal(signal, 'SIGTERM');
});
