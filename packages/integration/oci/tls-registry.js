// Test-only lifecycle of a DISPOSABLE, AUTHENTICATED, HTTPS loopback Zot for the
// authenticated-transport proof (issue #46). Nothing here is production code and
// nothing here is a registry client: ORAS remains the transport.
//
//   - a temporary test CA and a server certificate with the correct SAN
//     (IP:127.0.0.1, DNS:localhost), generated with the host `openssl` CLI into
//     the registry's state directory (EC P-256, valid for two days, never
//     committed, removed with the state directory);
//   - a synthetic htpasswd user. Zot v2.1.21 verifies htpasswd entries with
//     bcrypt only (pkg/api/htpasswd.go: "Currently supports only bcrypt
//     hashes"). Node has no bcrypt, so the entry is produced through the
//     platform's crypt(3) — libxcrypt on the Linux hosts this suite runs on —
//     via Perl's built-in `crypt`, the thinnest standard bridge present on the
//     Ubuntu runner image and on ordinary Linux hosts; the password travels on
//     stdin, the salt in an environment variable, and the result is checked
//     against the bcrypt format before use. Zot accepting the valid password
//     and rejecting a wrong one is the live oracle for the hash;
//   - a Zot configuration that REQUIRES authentication for every repository
//     (`http.auth.htpasswd` plus an `accessControl` policy naming the one user,
//     an empty `defaultPolicy` and no `anonymousPolicy`), TLS on 127.0.0.1 with
//     an ephemeral port, temporary storage, and an info-level session log whose
//     `method`/`path`/`statusCode` fields are the boundary evidence;
//   - bounded subprocesses (kill-and-reap on timeout) and a `stop()` that ends
//     the registry, proves the pid is gone and removes the state directory —
//     keys, certificate, htpasswd file, storage and log alike;
//   - startup that OWNS its failures: from the moment the state directory
//     exists (and from the moment the child is spawned) every rejection of
//     `startTlsRegistry()` — setup failure, spawn failure, early exit, an
//     unexpected authentication challenge, a registry that does not require
//     authentication, or the readiness deadline — stops the child if it is
//     running, awaits its close and verifies it was reaped, removes the state
//     directory, aborts the in-flight probe and clears every timer, and then
//     rejects with the ORIGINAL error (cleanup problems, if any, are appended to
//     its message and recorded on `error.cleanup`). Readiness is an
//     elapsed-time deadline (60 s by default): every HTTPS probe carries an
//     independent elapsed-time timer bounded by the remaining budget that
//     destroys the request regardless of incoming bytes, every retry delay is
//     bounded by the remaining budget, and a completed response is re-checked
//     against the deadline — so a registry that never answers, one that keeps
//     trickling response bytes, or one whose answer completes late cannot be
//     accepted as ready.
//
// Client isolation is the caller's job (an ORAS `--registry-config` file inside
// the test's own temporary directory, a temporary HOME/DOCKER_CONFIG); this
// module never reads or writes the user's Docker/ORAS configuration or the
// system trust store.
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { randomBytes, X509Certificate } from 'node:crypto';
import { access, constants, mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import { request as httpsRequest } from 'node:https';
import { createServer } from 'node:net';
import { delimiter, isAbsolute, join } from 'node:path';

export const TLS_REGISTRY_USER = 'owa-ci-user';
export const TLS_REGISTRY_REALM = 'owa-test-registry';
export const REGISTRY_HOST = '127.0.0.1';
const BCRYPT_ALPHABET = './ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
const BCRYPT_COST = '05';
const OUTPUT_LIMIT = 4 * 1024 * 1024;

/** A fresh synthetic password for one run: random, never committed, never printed. */
export const syntheticPassword = () => randomBytes(18).toString('base64url');

// ---------------------------------------------------------------- processes ---

// Last-resort safety net ONLY: if the test process itself dies with a child
// still registered here, the child is SIGKILLed on the way out. It is not the
// cleanup mechanism — `runBounded`, `startTlsRegistry`'s failure path and
// `stop()` each reap their own child and remove their own state.
const liveChildren = new Set();
process.once('exit', () => { for (const child of liveChildren) { try { child.kill('SIGKILL'); } catch {} } });

/** A cancellable delay: resolves after `ms`, or at once when cancelled; never leaves a live timer behind. */
function cancellableDelay(ms) {
  let timer, settle;
  const promise = new Promise(resolve => { settle = resolve; timer = setTimeout(resolve, ms); });
  return { promise, cancel: () => { clearTimeout(timer); settle(); } };
}

/**
 * Run a command with ARRAY arguments (never a shell string) and an external
 * deadline: on timeout the child is SIGKILLed, awaited to `close` (exit AND
 * stdio closed) and its pid checked gone, so it has been reaped. Optional
 * `input` is written to stdin — how secrets reach a tool without appearing on a
 * command line. Output is captured with a bound so a runaway child cannot grow
 * the test process.
 */
export function runBounded(command, args, { input, env, cwd, timeout = 120_000 } = {}) {
  return new Promise(resolve => {
    const child = spawn(command, args, { cwd, env, stdio: [input === undefined ? 'ignore' : 'pipe', 'pipe', 'pipe'] });
    liveChildren.add(child);
    let stdout = '', stderr = '', timedOut = false, overflow = false;
    const capture = name => chunk => {
      const text = String(chunk);
      if (name === 'stdout') stdout += text; else stderr += text;
      if (stdout.length + stderr.length > OUTPUT_LIMIT) { overflow = true; child.kill('SIGKILL'); }
    };
    child.stdout.setEncoding('utf8'); child.stderr.setEncoding('utf8');
    child.stdout.on('data', capture('stdout')); child.stderr.on('data', capture('stderr'));
    const timer = setTimeout(() => { timedOut = true; child.kill('SIGKILL'); }, timeout);
    const finish = (code, signal, error) => {
      clearTimeout(timer);
      liveChildren.delete(child);
      let gone = true;
      try { process.kill(child.pid, 0); gone = false; } catch (probe) { gone = probe.code === 'ESRCH'; }
      resolve({ code, signal, stdout, stderr: error ? `${stderr}\n${error.message}` : stderr, timedOut, overflow, gone, pid: child.pid });
    };
    child.once('error', error => finish(null, null, error));
    child.once('close', (code, signal) => finish(code, signal));
    if (input !== undefined) { child.stdin.on('error', () => {}); child.stdin.end(input); }
  });
}

/** Resolve an executable on PATH without invoking a shell. */
export async function whichOnPath(name, env = process.env) {
  for (const dir of (env.PATH ?? '').split(delimiter).filter(Boolean)) {
    const candidate = join(dir, name);
    try { await access(candidate, constants.X_OK); return candidate; } catch {}
  }
  return null;
}

async function toolRun(command, args, options, label) {
  const result = await runBounded(command, args, { timeout: 30_000, ...options });
  assert.equal(result.timedOut, false, `${label}: ${command} did not finish within its deadline (killed, reaped=${result.gone})`);
  assert.equal(result.code, 0, `${label}: ${command} exited ${result.code}${result.signal ? ` (${result.signal})` : ''}: ${result.stderr.trim().split('\n').slice(-3).join(' | ').slice(0, 300)}`);
  return result;
}

// ---------------------------------------------------------------------- PKI ---

// Extensions are supplied through config files, the form every OpenSSL 1.1/3.x
// and LibreSSL release accepts (`-addext`/`-copy_extensions` are newer).
const REQ_CONFIG = '[req]\ndistinguished_name = dn\nprompt = no\n[dn]\nCN = placeholder\n';
const CA_EXTENSIONS = '[v3_ca]\nbasicConstraints = critical, CA:TRUE\nkeyUsage = critical, keyCertSign, cRLSign\nsubjectKeyIdentifier = hash\n';
const serverExtensions = ({ ip, dns }) => `basicConstraints = CA:FALSE\nkeyUsage = critical, digitalSignature, keyEncipherment\nextendedKeyUsage = serverAuth\nsubjectAltName = IP:${ip}, DNS:${dns}\n`;

/** Create a temporary test CA (self-signed, EC P-256, 2 days) under `dir`. */
export async function createTestCA(openssl, dir) {
  await mkdir(dir, { recursive: true });
  const cnf = join(dir, 'ca.cnf');
  await writeFile(cnf, REQ_CONFIG + CA_EXTENSIONS);
  const cert = join(dir, 'ca.crt'), key = join(dir, 'ca.key');
  await toolRun(openssl, ['req', '-x509', '-new', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:prime256v1', '-nodes',
    '-keyout', key, '-out', cert, '-days', '2', '-subj', '/CN=OWA test CA (disposable)', '-config', cnf, '-extensions', 'v3_ca'], {}, 'test CA');
  return { cert, key, pem: await readFile(cert, 'utf8') };
}

/** Issue a server certificate for the loopback registry, signed by `ca`, with IP and DNS SANs. */
export async function issueServerCertificate(openssl, dir, ca, { ip = REGISTRY_HOST, dns = 'localhost' } = {}) {
  const cnf = join(dir, 'server.cnf'), ext = join(dir, 'server-ext.cnf');
  await writeFile(cnf, REQ_CONFIG);
  await writeFile(ext, serverExtensions({ ip, dns }));
  const key = join(dir, 'server.key'), csr = join(dir, 'server.csr'), cert = join(dir, 'server.crt');
  await toolRun(openssl, ['req', '-new', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:prime256v1', '-nodes', '-keyout', key, '-out', csr, '-subj', `/CN=${ip}`, '-config', cnf], {}, 'server CSR');
  await toolRun(openssl, ['x509', '-req', '-in', csr, '-CA', ca.cert, '-CAkey', ca.key, '-CAcreateserial', '-out', cert, '-days', '2', '-extfile', ext], {}, 'server certificate');
  const parsed = new X509Certificate(await readFile(cert));
  assert.ok(parsed.checkIP(ip), `server certificate carries the IP SAN ${ip}`);
  assert.ok(parsed.checkHost(dns), `server certificate carries the DNS SAN ${dns}`);
  assert.ok(parsed.checkIssued(new X509Certificate(await readFile(ca.cert))), 'server certificate is issued by the test CA');
  return { cert, key, subjectAltName: parsed.subjectAltName };
}

// ----------------------------------------------------------------- htpasswd ---

/** A bcrypt setting `$2b$05$<22 salt chars>`; the final salt character must carry only its top bits. */
function bcryptSetting() {
  const bytes = randomBytes(21);
  let salt = '';
  for (const byte of bytes) salt += BCRYPT_ALPHABET[byte % 64];
  return `$2b$${BCRYPT_COST}$${salt}.`;
}

/**
 * One htpasswd line `username:$2b$…` produced by the platform crypt(3) through
 * Perl's built-in `crypt`; the password goes to stdin, the salt to the
 * environment. The result must be a complete bcrypt hash or setup fails.
 */
export async function htpasswdEntry(perl, username, password) {
  assert.match(username, /^[a-z0-9][a-z0-9-]{0,63}$/, 'synthetic username stays a plain token');
  assert.ok(typeof password === 'string' && password.length >= 12 && !/[\r\n:]/.test(password), 'password is a single line');
  const setting = bcryptSetting();
  const script = 'my $pw = <STDIN>; chomp $pw; my $h = crypt($pw, $ENV{OWA_TEST_BCRYPT_SETTING}); print defined $h ? $h : "";';
  const result = await runBounded(perl, ['-e', script], { input: `${password}\n`, env: { PATH: process.env.PATH ?? '', OWA_TEST_BCRYPT_SETTING: setting }, timeout: 30_000 });
  assert.equal(result.code, 0, `perl crypt exited ${result.code}: ${result.stderr.trim().slice(0, 200)}`);
  const hash = result.stdout.trim();
  assert.match(hash, /^\$2b\$05\$[./A-Za-z0-9]{53}$/, 'crypt(3) produced a complete bcrypt hash (this host\'s libcrypt must support $2b$)');
  assert.ok(hash.startsWith(setting.slice(0, 28)), 'the hash embeds the requested setting');
  return `${username}:${hash}`;
}

// ------------------------------------------------------------------- config ---

/**
 * Zot configuration requiring authentication everywhere: htpasswd
 * authentication; an access-control policy that grants the ONE synthetic user
 * read/create/update/delete on every repository; an empty default policy for
 * any other authenticated identity; and NO anonymous policy, so unauthenticated
 * requests are challenged with 401. Pure function — unit-checked offline.
 */
export function zotTlsConfig({ stateDir, port, tls, htpasswdPath, username, realm = TLS_REGISTRY_REALM }) {
  return {
    distSpecVersion: '1.1.1',
    storage: { rootDirectory: join(stateDir, 'data'), gc: false, dedupe: true },
    http: {
      address: REGISTRY_HOST,
      port: String(port),
      realm,
      tls: { cert: tls.cert, key: tls.key },
      auth: { htpasswd: { path: htpasswdPath } },
      accessControl: {
        repositories: {
          '**': {
            policies: [{ users: [username], actions: ['read', 'create', 'update', 'delete'] }],
            defaultPolicy: []
          }
        }
      }
    },
    log: { level: 'info', output: join(stateDir, 'zot.log') }
  };
}

/** Docker-style registry configuration file content with one basic credential (used for the WRONG-credential control). */
export const registryConfigWith = (host, username, password) => JSON.stringify({ auths: { [host]: { auth: Buffer.from(`${username}:${password}`, 'utf8').toString('base64') } } });
export const EMPTY_REGISTRY_CONFIG = JSON.stringify({ auths: {} });

// ------------------------------------------------------------------ HTTPS I/O ---

/**
 * Test-only HTTPS request verified against `ca` (never the system store, never
 * insecure); supplemental inspection, not the transport. Three independent ways
 * to end it early, none of which leaves anything pending:
 *   - `timeout`: an INACTIVITY bound (`req.setTimeout`) — destroys the request
 *     when the socket has been idle that long;
 *   - `deadlineMs`: an ELAPSED-TIME bound — a timer that destroys the request
 *     when that much time has passed since it was sent, regardless of incoming
 *     traffic, so a response that keeps sending bytes cannot outlive it;
 *   - `signal`: an aborted AbortSignal destroys it at once.
 * The deadline timer is cleared on every settle path (response complete,
 * request or response error, abort, premature close).
 */
export function httpsGet(origin, path, { method = 'GET', headers = {}, ca, timeout = 15_000, deadlineMs, signal } = {}) {
  const url = new URL(path, origin);
  const label = `${method} ${url.pathname}`;
  return new Promise((resolve, reject) => {
    if (signal?.aborted) { reject(new Error(`${label} aborted before it was sent`)); return; }
    let settled = false, deadlineTimer = null, deadlineError = null;
    const settle = (fn, value) => {
      if (settled) return;
      settled = true;
      clearTimeout(deadlineTimer);
      fn(fn === reject && deadlineError ? deadlineError : value);
    };
    const req = httpsRequest({ hostname: url.hostname, port: url.port, path: `${url.pathname}${url.search}`, method, headers, ca, agent: false, signal }, res => {
      const chunks = [];
      res.on('data', chunk => chunks.push(chunk));
      res.on('error', error => settle(reject, error));
      res.on('aborted', () => settle(reject, new Error(`${label} response aborted before it completed`)));
      res.on('close', () => { if (!settled) settle(reject, new Error(`${label} response closed before it completed`)); });
      res.on('end', () => settle(resolve, { status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks) }));
    });
    req.setTimeout(timeout, () => req.destroy(new Error(`${label} idle for ${timeout} ms`)));
    if (deadlineMs !== undefined) {
      deadlineTimer = setTimeout(() => {
        deadlineError = new Error(`${label} exceeded its ${deadlineMs} ms elapsed deadline while the response was still arriving`);
        req.destroy(deadlineError);
      }, deadlineMs);
    }
    req.on('error', error => settle(reject, error));
    req.on('close', () => { if (!settled) settle(reject, new Error(`${label} closed before a complete response`)); });
    req.end();
  });
}
export const basicAuthorization = (username, password) => `Basic ${Buffer.from(`${username}:${password}`, 'utf8').toString('base64')}`;

function freePort() {
  return new Promise((resolve, reject) => {
    const server = createServer();
    server.once('error', reject);
    server.listen(0, REGISTRY_HOST, () => { const { port } = server.address(); server.close(() => resolve(port)); });
  });
}

// ------------------------------------------------------------------ registry ---

/**
 * Parse the registry's session log into { method, path, statusCode } records —
 * never the headers, so nothing credential-shaped is ever surfaced.
 */
export async function accessLog(logPath) {
  let text = '';
  try { text = await readFile(logPath, 'utf8'); } catch { return []; }
  const entries = [];
  for (const line of text.split('\n')) {
    if (!line.includes('"HTTP API"')) continue;
    try {
      const entry = JSON.parse(line);
      if (entry.message === 'HTTP API') entries.push({ method: entry.method, path: entry.path, statusCode: entry.statusCode });
    } catch {}
  }
  return entries;
}

/** Readiness deadline for the real registry (elapsed time, not attempts) and the bound of one HTTPS probe. */
export const READINESS_MS = 60_000;
export const PROBE_TIMEOUT_MS = 2_000;
const RETRY_DELAY_MS = 250;
/** Grace between SIGTERM and SIGKILL when stopping the registry. */
export const STOP_GRACE_MS = 10_000;

/**
 * Start the disposable authenticated HTTPS registry.
 *
 * Resolves once GET /v2/ over TLS (verified against the test CA only) is
 * answered `401` with exactly the configured Basic challenge — the registry is
 * up AND requires authentication. Rejects, after cleaning up after itself, when:
 *
 *   - setup fails after the state directory was created (PKI, htpasswd, config);
 *   - the child cannot be spawned (its `error` event) or exits before readiness;
 *   - the registry answers without requiring authentication, or with an
 *     unexpected challenge;
 *   - the elapsed-time deadline `readinessMs` (default 60 s) expires. Every
 *     probe carries an independent ELAPSED-TIME timer of
 *     `min(probeTimeoutMs, remaining budget)` that destroys the request
 *     regardless of incoming traffic (plus an inactivity bound of the same
 *     length), every retry delay is bounded by the remaining budget, and a
 *     response that does complete is re-checked against the deadline before it
 *     counts as ready — so neither a registry that accepts connections and
 *     never answers, nor one that keeps trickling response bytes, nor one whose
 *     answer completes after the budget can be accepted.
 *
 * Cleanup on rejection: the in-flight probe is aborted, pending timers are
 * cleared, the child (if any) is SIGTERMed then SIGKILLed after `graceMs` and
 * awaited to `close`, its pid is verified gone, and the state directory (keys,
 * certificate, htpasswd file, storage, log) is removed. The ORIGINAL error is
 * rejected with; cleanup problems are appended to its message and recorded on
 * `error.cleanup` — never swallowed, never allowed to mask the cause.
 * `readinessMs` is the READINESS budget; `graceMs` is the separate SIGTERM →
 * SIGKILL grace used when stopping. `clock(phase)` (default: `Date.now`, phase
 * ignored) exists only so harness tests can prove the late-response check; it
 * is read with phase `start`, `budget` (before each probe and retry delay),
 * `response` (the recheck after a completed response) and `ready`.
 */
export async function startTlsRegistry({ zot, openssl, perl, stateDir, username = TLS_REGISTRY_USER, password, readinessMs = READINESS_MS, probeTimeoutMs = PROBE_TIMEOUT_MS, graceMs = STOP_GRACE_MS, clock = () => Date.now() }) {
  assert.ok(password, 'a synthetic password is required');
  assert.ok(Number.isFinite(readinessMs) && readinessMs > 0, 'readinessMs must be a positive number of milliseconds');
  assert.ok(Number.isFinite(probeTimeoutMs) && probeTimeoutMs > 0, 'probeTimeoutMs must be a positive number of milliseconds');
  const expectedChallenge = `Basic realm="${TLS_REGISTRY_REALM}"`;
  const started = clock('start');
  const deadline = started + readinessMs;

  // Lifecycle state shared by the failure path and the returned handle. `exit`
  // settles on the child's `close` (exited AND stdio closed) or on its `error`
  // event (spawn failure); whichever comes first, exactly once.
  const lifecycle = { child: null, exit: null, exited: null, probe: null };

  async function terminate(grace) {
    const { child } = lifecycle;
    if (!child) return { code: null, signal: null, gone: true };
    if (!lifecycle.exited) {
      try { child.kill('SIGTERM'); } catch {}
      const delay = cancellableDelay(grace);
      const term = await Promise.race([lifecycle.exit, delay.promise.then(() => null)]);
      delay.cancel();
      if (!term) { try { child.kill('SIGKILL'); } catch {} await lifecycle.exit; }
    }
    let gone = true;
    if (child.pid !== undefined) { try { process.kill(child.pid, 0); gone = false; } catch (probe) { gone = probe.code === 'ESRCH'; } }
    return { code: lifecycle.exited?.code ?? null, signal: lifecycle.exited?.signal ?? null, gone };
  }
  async function removeState() {
    await rm(stateDir, { recursive: true, force: true });
    try { await access(stateDir); return false; } catch { return true; }
  }
  /** Own the failure: abort the probe, stop and reap the child, remove the state; return the ORIGINAL error annotated. */
  async function failStart(cause) {
    const error = cause instanceof Error ? cause : new Error(String(cause));
    const cleanup = { probeAborted: false, code: null, signal: null, gone: null, removed: null, problems: [] };
    try { if (lifecycle.probe) { lifecycle.probe.abort(); cleanup.probeAborted = true; lifecycle.probe = null; } } catch (problem) { cleanup.problems.push(`abort probe: ${problem.message}`); }
    try {
      const result = await terminate(graceMs);
      Object.assign(cleanup, { code: result.code, signal: result.signal, gone: result.gone });
      if (!result.gone) cleanup.problems.push(`child pid ${lifecycle.child?.pid} still exists after SIGKILL`);
    } catch (problem) { cleanup.problems.push(`stop child: ${problem.message}`); }
    try {
      cleanup.removed = await removeState();
      if (!cleanup.removed) cleanup.problems.push('state directory still exists after removal');
    } catch (problem) { cleanup.problems.push(`remove state: ${problem.message}`); }
    error.cleanup = cleanup;
    if (cleanup.problems.length) error.message += ` (cleanup after the failed start also had problems: ${cleanup.problems.join('; ')})`;
    return error;
  }
  const exitedEarly = () => {
    const { code, signal, spawnError } = lifecycle.exited;
    return spawnError
      ? new Error(`zot could not be started: ${spawnError.code ?? spawnError.message}`)
      : new Error(`zot exited before becoming ready (code ${code}, signal ${signal}); see ${join(stateDir, 'zot.log')}`);
  };

  try {
    await mkdir(join(stateDir, 'data'), { recursive: true });   // from here on, failure removes the state directory
    const pki = join(stateDir, 'pki');
    const ca = await createTestCA(openssl, pki);
    const tls = await issueServerCertificate(openssl, pki, ca);
    const htpasswdPath = join(stateDir, 'htpasswd');
    await writeFile(htpasswdPath, `${await htpasswdEntry(perl, username, password)}\n`, { mode: 0o600 });
    const port = await freePort();
    const config = zotTlsConfig({ stateDir, port, tls, htpasswdPath, username });
    const configPath = join(stateDir, 'config.json');
    await writeFile(configPath, JSON.stringify(config, null, 2));

    // Spawn: lifecycle ownership begins here, before anything can be awaited.
    const child = spawn(zot, ['serve', configPath], { stdio: 'ignore' });
    lifecycle.child = child;
    liveChildren.add(child);
    lifecycle.exit = new Promise(resolve => {
      const settle = result => { if (lifecycle.exited) return; lifecycle.exited = result; liveChildren.delete(child); resolve(result); };
      child.once('error', spawnError => settle({ code: null, signal: null, spawnError }));   // explicit: ENOENT, EACCES, …
      child.once('close', (code, signal) => settle({ code, signal }));
    });
    const origin = `https://${REGISTRY_HOST}:${port}`;

    let lastProbe = 'no probe sent yet';
    for (;;) {
      if (lifecycle.exited) throw exitedEarly();
      const remaining = deadline - clock('budget');
      if (remaining <= 0) throw new Error(`zot did not answer GET /v2/ with the expected 401 challenge over TLS within ${readinessMs} ms (last probe: ${lastProbe})`);
      // One probe, bounded in ELAPSED time by the remaining budget (a response that keeps
      // sending bytes is destroyed all the same) and aborted at once if the child exits.
      const budget = Math.min(probeTimeoutMs, remaining);
      const probe = new AbortController();
      lifecycle.probe = probe;
      lifecycle.exit.then(() => { if (lifecycle.probe === probe) probe.abort(); });
      let res = null;
      try {
        res = await httpsGet(origin, '/v2/', { ca: ca.pem, timeout: budget, deadlineMs: budget, signal: probe.signal });
      } catch (error) {
        lastProbe = lifecycle.exited ? 'aborted because the process exited' : (error.code ?? error.message);
      } finally {
        if (lifecycle.probe === probe) lifecycle.probe = null;
      }
      if (lifecycle.exited) throw exitedEarly();
      if (res) {
        // A completed response counts only if it completed WITHIN the budget.
        const now = clock('response');
        if (now > deadline) throw new Error(`zot answered GET /v2/ only after the ${readinessMs} ms readiness deadline had passed (${now - started} ms elapsed): a response completed after the budget is not accepted as readiness`);
        if (res.status !== 401) throw new Error(`GET /v2/ answered ${res.status} without authentication: the registry does not require it`);
        const challenge = res.headers['www-authenticate'] ?? '';
        if (challenge !== expectedChallenge) throw new Error(`GET /v2/ answered 401 with an unexpected authentication challenge ${JSON.stringify(challenge)}; expected ${JSON.stringify(expectedChallenge)}`);
        // Ready: up, over verified TLS, requiring exactly the configured authentication, within the budget.
        return {
          origin, host: `${REGISTRY_HOST}:${port}`, port, pid: child.pid, username, ca, tls, configPath, logPath: config.log.output, stateDir,
          readyAfterMs: clock('ready') - started, challenge, readinessMs,
          exited: () => lifecycle.exited,
          requests: () => accessLog(config.log.output),
          /** SIGTERM, wait up to `graceMs`, SIGKILL if needed; prove the pid is gone; remove keys, certificate, htpasswd, storage and log. */
          async stop({ graceMs: grace = graceMs } = {}) {
            const result = await terminate(grace);
            const removed = await removeState();
            return { ...result, removed };
          }
        };
      }
      // Retry after a delay bounded by the remaining budget; wake early if the child exits.
      const wait = Math.min(RETRY_DELAY_MS, deadline - clock('budget'));
      if (wait > 0) {
        const delay = cancellableDelay(wait);
        lifecycle.exit.then(delay.cancel);
        await delay.promise;
      }
    }
  } catch (cause) {
    throw await failStart(cause);
  }
}
