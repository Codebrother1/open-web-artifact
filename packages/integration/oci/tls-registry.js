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
//     keys, certificate, htpasswd file, storage and log alike.
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

const liveChildren = new Set();
process.once('exit', () => { for (const child of liveChildren) { try { child.kill('SIGKILL'); } catch {} } });

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

/** Test-only HTTPS request verified against `ca` (never the system store, never insecure); supplemental inspection, not the transport. */
export function httpsGet(origin, path, { method = 'GET', headers = {}, ca, timeout = 15_000 } = {}) {
  const url = new URL(path, origin);
  return new Promise((resolve, reject) => {
    const req = httpsRequest({ hostname: url.hostname, port: url.port, path: `${url.pathname}${url.search}`, method, headers, ca, agent: false }, res => {
      const chunks = [];
      res.on('data', chunk => chunks.push(chunk));
      res.on('error', reject);
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks) }));
    });
    req.setTimeout(timeout, () => req.destroy(new Error(`${method} ${url.pathname} timed out`)));
    req.on('error', reject);
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

/**
 * Start the disposable authenticated HTTPS registry. Resolves once GET /v2/
 * over TLS (verified against the test CA) is challenged with 401 Basic — the
 * registry is up AND requires authentication. Rejects promptly if the process
 * exits first; the readiness wait is bounded (60 s) and leaves no timer behind.
 */
export async function startTlsRegistry({ zot, openssl, perl, stateDir, username = TLS_REGISTRY_USER, password }) {
  assert.ok(password, 'a synthetic password is required');
  await mkdir(join(stateDir, 'data'), { recursive: true });
  const pki = join(stateDir, 'pki');
  const ca = await createTestCA(openssl, pki);
  const tls = await issueServerCertificate(openssl, pki, ca);
  const htpasswdPath = join(stateDir, 'htpasswd');
  await writeFile(htpasswdPath, `${await htpasswdEntry(perl, username, password)}\n`, { mode: 0o600 });
  const port = await freePort();
  const config = zotTlsConfig({ stateDir, port, tls, htpasswdPath, username });
  const configPath = join(stateDir, 'config.json');
  await writeFile(configPath, JSON.stringify(config, null, 2));

  const child = spawn(zot, ['serve', configPath], { stdio: 'ignore' });
  liveChildren.add(child);
  const exit = new Promise(resolve => child.once('close', (code, signal) => { liveChildren.delete(child); resolve({ code, signal }); }));
  let exited = null;
  exit.then(result => { exited = result; });
  const origin = `https://${REGISTRY_HOST}:${port}`;
  const started = Date.now();
  let challenge = null;
  for (let attempt = 0; attempt < 240 && !challenge; attempt++) {
    if (exited) throw new Error(`zot exited before becoming ready (code ${exited.code}, signal ${exited.signal}); see ${join(stateDir, 'zot.log')}`);
    try {
      const res = await httpsGet(origin, '/v2/', { ca: ca.pem, timeout: 2_000 });
      if (res.status === 401) challenge = res.headers['www-authenticate'] ?? '';
      else throw new Error(`GET /v2/ answered ${res.status} without authentication: the registry does not require it`);
    } catch (error) {
      if (/without authentication/.test(error.message)) { try { child.kill('SIGKILL'); } catch {} await exit; throw error; }
      await new Promise(resolve => setTimeout(resolve, 250));
    }
  }
  if (!challenge) { try { child.kill('SIGKILL'); } catch {} await exit; throw new Error('zot did not challenge GET /v2/ with 401 over TLS within 60 s'); }
  assert.match(challenge, /^Basic realm=/, 'the registry challenges with HTTP Basic');

  return {
    origin, host: `${REGISTRY_HOST}:${port}`, port, pid: child.pid, username, ca, tls, configPath, logPath: config.log.output, stateDir,
    readyAfterMs: Date.now() - started, challenge,
    exited: () => exited,
    requests: () => accessLog(config.log.output),
    /** SIGTERM, wait up to `graceMs`, SIGKILL if needed; prove the pid is gone; remove keys, certificate, htpasswd, storage and log. */
    async stop({ graceMs = 10_000 } = {}) {
      if (!exited) {
        try { child.kill('SIGTERM'); } catch {}
        let grace;
        const term = await Promise.race([exit, new Promise(resolve => { grace = setTimeout(() => resolve(null), graceMs); })]);
        clearTimeout(grace);
        if (!term) { try { child.kill('SIGKILL'); } catch {} await exit; }
      }
      let gone = true;
      try { process.kill(child.pid, 0); gone = false; } catch (probe) { gone = probe.code === 'ESRCH'; }
      await rm(stateDir, { recursive: true, force: true });
      let removed = true;
      try { await access(stateDir); removed = false; } catch {}
      return { ...exited, gone, removed };
    }
  };
}
