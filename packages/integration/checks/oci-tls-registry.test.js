import test from 'node:test';
import assert from 'node:assert/strict';
import { X509Certificate } from 'node:crypto';
import { access, chmod, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { tlsEnvironment } from '../oci/environment.js';
import { EMPTY_REGISTRY_CONFIG, TLS_REGISTRY_REALM, TLS_REGISTRY_USER, createTestCA, htpasswdEntry, issueServerCertificate, registryConfigWith, runBounded, startTlsRegistry, syntheticPassword, whichOnPath, zotTlsConfig } from '../oci/tls-registry.js';

// Offline checks for the authenticated HTTPS registry harness (issue #46): the
// environment contract and required mode, the Zot configuration shape, the test
// PKI and bcrypt htpasswd generation, and the registry lifecycle (readiness,
// early exit, stop/reap/cleanup) against a STUB "zot" — a Node script that
// serves the configured certificate and challenges every request with 401 —
// so setup and cleanup are proven without the real registry. Steps that need
// host tools run only where those tools exist (openssl: Linux/macOS; bcrypt
// through crypt(3): Linux, the platform of the OCI lane) and otherwise skip
// with the reason. No real credential exists anywhere here.

const POSIX = process.platform !== 'win32';
const openssl = POSIX ? await whichOnPath('openssl') : null;
const perl = POSIX ? await whichOnPath('perl') : null;
const scratch = async t => { const dir = await mkdtemp(join(tmpdir(), 'owa-oci-tls-check-')); t.after(() => rm(dir, { recursive: true, force: true })); return dir; };
const executable = async (dir, name, source) => { const path = join(dir, name); await writeFile(path, source); await chmod(path, 0o755); return path; };

test('tlsEnvironment: unconfigured → skip naming both executables; required → fail; tools on PATH are prerequisites', async t => {
  assert.deepEqual(await tlsEnvironment({}), { skip: 'set OWA_TEST_ORAS_BIN, OWA_TEST_ZOT_BIN' });
  assert.deepEqual(await tlsEnvironment({ OWA_TEST_ORAS_BIN: '/x/oras' }), { skip: 'set OWA_TEST_ZOT_BIN' });
  const required = await tlsEnvironment({ OWA_TEST_OCI_REQUIRED: '1' });
  assert.deepEqual(Object.keys(required), ['fail']);
  assert.match(required.fail, /^OWA_TEST_OCI_REQUIRED=1 but set OWA_TEST_ORAS_BIN, OWA_TEST_ZOT_BIN: the authenticated HTTPS OCI suite must run, not skip$/);
  const dir = await scratch(t);
  const oras = await executable(dir, 'oras', '#!/bin/sh\nexit 0\n');
  const zot = await executable(dir, 'zot', '#!/bin/sh\nexit 0\n');
  const emptyPath = join(dir, 'empty-path'); await writeFile(join(dir, 'placeholder'), '');
  // Executables must be absolute and executable; openssl and perl must be on PATH.
  assert.match((await tlsEnvironment({ OWA_TEST_ORAS_BIN: 'oras', OWA_TEST_ZOT_BIN: zot, PATH: process.env.PATH })).skip, /OWA_TEST_ORAS_BIN must be an absolute path/);
  assert.match((await tlsEnvironment({ OWA_TEST_ORAS_BIN: oras, OWA_TEST_ZOT_BIN: join(dir, 'missing'), PATH: process.env.PATH })).skip, /OWA_TEST_ZOT_BIN is not an executable file/);
  const noTools = await tlsEnvironment({ OWA_TEST_ORAS_BIN: oras, OWA_TEST_ZOT_BIN: zot, PATH: emptyPath, OWA_TEST_OCI_REQUIRED: '1' });
  assert.match(noTools.fail, /openssl must be on PATH \(test CA and server certificate\); perl must be on PATH \(bcrypt htpasswd entry through crypt\(3\)\)/, 'missing tools fail in required mode, naming each tool and why');
  assert.match((await tlsEnvironment({ OWA_TEST_ORAS_BIN: oras, OWA_TEST_ZOT_BIN: zot, PATH: emptyPath })).skip, /openssl must be on PATH/, 'and skip when not required');
  if (openssl && perl) {
    const ok = await tlsEnvironment({ OWA_TEST_ORAS_BIN: oras, OWA_TEST_ZOT_BIN: zot, PATH: process.env.PATH, OWA_TEST_OCI_REQUIRED: '1' });
    assert.deepEqual(ok, { required: true, oras, zot, openssl, perl });
  }
});

test('zotTlsConfig requires authentication everywhere: htpasswd auth, one user policy, empty default policy, no anonymous policy, TLS on loopback', () => {
  const config = zotTlsConfig({ stateDir: '/s', port: 4443, tls: { cert: '/s/pki/server.crt', key: '/s/pki/server.key' }, htpasswdPath: '/s/htpasswd', username: TLS_REGISTRY_USER });
  assert.equal(config.http.address, '127.0.0.1'); assert.equal(config.http.port, '4443'); assert.equal(config.http.realm, TLS_REGISTRY_REALM);
  assert.deepEqual(config.http.tls, { cert: '/s/pki/server.crt', key: '/s/pki/server.key' });
  assert.deepEqual(config.http.auth, { htpasswd: { path: '/s/htpasswd' } });
  const everything = config.http.accessControl.repositories['**'];
  assert.deepEqual(everything.policies, [{ users: [TLS_REGISTRY_USER], actions: ['read', 'create', 'update', 'delete'] }]);
  assert.deepEqual(everything.defaultPolicy, [], 'other authenticated identities get nothing');
  assert.ok(!('anonymousPolicy' in everything), 'no anonymous access');
  assert.ok(!('adminPolicy' in config.http.accessControl), 'no admin policy');
  // Paths are built with path.join, so compare against join() too (Windows uses backslashes).
  assert.equal(config.storage.rootDirectory, join('/s', 'data')); assert.equal(config.storage.gc, false);
  assert.equal(config.log.level, 'info'); assert.equal(config.log.output, join('/s', 'zot.log'));
  assert.ok(!('extensions' in config), 'no UI/search/sync/metrics');
  // Client-side configuration files used by the negative controls.
  assert.deepEqual(JSON.parse(EMPTY_REGISTRY_CONFIG), { auths: {} });
  const wrong = JSON.parse(registryConfigWith('127.0.0.1:4443', 'u', 'p'));
  assert.deepEqual(wrong, { auths: { '127.0.0.1:4443': { auth: Buffer.from('u:p').toString('base64') } } });
  assert.match(syntheticPassword(), /^[A-Za-z0-9_-]{24}$/); assert.notEqual(syntheticPassword(), syntheticPassword());
});

test('test PKI: a temporary CA issues a loopback server certificate with IP and DNS SANs that verifies against the CA only', { skip: openssl ? false : 'openssl not on PATH (or Windows)' }, async t => {
  const dir = await scratch(t);
  const ca = await createTestCA(openssl, join(dir, 'pki'));
  const server = await issueServerCertificate(openssl, join(dir, 'pki'), ca);
  assert.match(server.subjectAltName, /IP Address:127\.0\.0\.1/); assert.match(server.subjectAltName, /DNS:localhost/);
  const verify = await runBounded(openssl, ['verify', '-CAfile', ca.cert, server.cert], { timeout: 30_000 });
  assert.equal(verify.code, 0, `openssl verify: ${verify.stderr.trim()}`);
  const caCert = new X509Certificate(ca.pem);
  assert.equal(caCert.ca, true, 'the CA certificate is a CA');
  const serverCert = new X509Certificate(await readFile(server.cert));
  assert.equal(serverCert.ca, false); assert.ok(serverCert.checkIssued(caCert));
  assert.ok(new Date(serverCert.validTo) - Date.now() < 3 * 24 * 3600 * 1000, 'short-lived (2 days)');
  // A second CA does not verify it: trust is specific to the test CA.
  const other = await createTestCA(openssl, join(dir, 'other'));
  assert.notEqual((await runBounded(openssl, ['verify', '-CAfile', other.cert, server.cert], { timeout: 30_000 })).code, 0);
});

test('htpasswd entry: bcrypt through crypt(3), password on stdin, salted per call, format-checked', { skip: process.platform === 'linux' && perl ? false : 'bcrypt via crypt(3) is exercised on Linux (the OCI lane platform)' }, async () => {
  const password = syntheticPassword();
  const entry = await htpasswdEntry(perl, TLS_REGISTRY_USER, password);
  assert.match(entry, new RegExp(`^${TLS_REGISTRY_USER}:\\$2b\\$05\\$[./A-Za-z0-9]{53}$`));
  assert.notEqual(entry, await htpasswdEntry(perl, TLS_REGISTRY_USER, password), 'a fresh random salt each call');
  assert.ok(!entry.includes(password), 'the password never appears in the entry');
  await assert.rejects(htpasswdEntry(perl, 'Bad User', password), /plain token/);
  await assert.rejects(htpasswdEntry(perl, TLS_REGISTRY_USER, 'short'), /single line/);
});

// A stub "zot": honours `serve <config>`, listens with the configured certificate
// on the configured loopback port, and — in its default mode — challenges every
// request with 401 Basic, exactly the readiness signal startTlsRegistry waits
// for. Environment switches turn it into the failure shapes the harness must
// survive:
//   STUB_ZOT_EXIT=<n>           exit with <n> before listening (early exit)
//   STUB_ZOT_MODE=bad-challenge 401 with a nonempty but unexpected challenge
//   STUB_ZOT_MODE=hang          accept the TLS connection and never answer
//   STUB_ZOT_IGNORE_SIGTERM=1   ignore SIGTERM (stop() must escalate to SIGKILL)
const STUB_ZOT = `#!/usr/bin/env node
const fs = require('node:fs'); const https = require('node:https');
const cfg = JSON.parse(fs.readFileSync(process.argv[3], 'utf8'));
if (process.env.STUB_ZOT_EXIT) process.exit(Number(process.env.STUB_ZOT_EXIT));
const mode = process.env.STUB_ZOT_MODE || 'challenge';
const server = https.createServer({ cert: fs.readFileSync(cfg.http.tls.cert), key: fs.readFileSync(cfg.http.tls.key) }, (req, res) => {
  if (mode === 'hang') return; // connection accepted, request read, response never written
  fs.appendFileSync(cfg.log.output, JSON.stringify({ level: 'info', message: 'HTTP API', method: req.method, path: req.url, statusCode: 401 }) + '\\n');
  const challenge = mode === 'bad-challenge' ? 'Bearer realm="https://tokens.invalid/auth",service="not-this-registry"' : 'Basic realm="' + cfg.http.realm + '"';
  res.writeHead(401, { 'www-authenticate': challenge }); res.end();
});
server.listen(Number(cfg.http.port), cfg.http.address);
process.on('SIGTERM', () => { if (process.env.STUB_ZOT_IGNORE_SIGTERM) return; server.close(); process.exit(0); });
`;
const stubZot = (dir, name) => executable(dir, name, STUB_ZOT.replace('#!/usr/bin/env node', `#!${process.execPath}`));
const LINUX_TOOLS = { skip: process.platform === 'linux' && openssl && perl ? false : 'needs openssl and Linux bcrypt' };

test('registry lifecycle against a stub zot: readiness is the exact 401 challenge over verified TLS, stop() reaps the process and removes every secret', LINUX_TOOLS, async t => {
  const dir = await scratch(t);
  const zot = await stubZot(dir, 'zot-stub');
  const stateDir = join(dir, 'state');
  const registry = await startTlsRegistry({ zot, openssl, perl, stateDir, password: syntheticPassword() });
  t.after(async () => { if (!registry.exited()) await registry.stop(); });
  assert.match(registry.origin, /^https:\/\/127\.0\.0\.1:\d+$/);
  assert.equal(registry.challenge, `Basic realm="${TLS_REGISTRY_REALM}"`);
  assert.equal(registry.readinessMs, 60_000, 'the production default deadline is 60 s');
  assert.equal(registry.exited(), null);
  for (const secret of [registry.ca.key, registry.tls.key, join(stateDir, 'htpasswd'), registry.configPath]) await access(secret);
  assert.deepEqual((await registry.requests()).map(r => `${r.method} ${r.path} ${r.statusCode}`), ['GET /v2/ 401'], 'the session log parser surfaces method, path and status only');
  const stopped = await registry.stop();
  assert.equal(stopped.gone, true, 'the stub process is gone');
  assert.equal(stopped.removed, true, 'the state directory is gone');
  assert.equal(stopped.code, 0, 'SIGTERM was honoured');
  for (const secret of [registry.ca.key, registry.tls.key, join(stateDir, 'htpasswd'), registry.logPath]) await assert.rejects(access(secret), `${secret} removed`);
  assert.throws(() => process.kill(registry.pid, 0), { code: 'ESRCH' }, 'pid no longer exists');
});

test('registry lifecycle: a zot that ignores SIGTERM is SIGKILLed, reaped and its state removed', LINUX_TOOLS, async t => {
  const dir = await scratch(t);
  const stubborn = await stubZot(dir, 'zot-stubborn');
  process.env.STUB_ZOT_IGNORE_SIGTERM = '1';
  let registry;
  try { registry = await startTlsRegistry({ zot: stubborn, openssl, perl, stateDir: join(dir, 'state-stubborn'), password: syntheticPassword() }); }
  finally { delete process.env.STUB_ZOT_IGNORE_SIGTERM; }
  const stopped = await registry.stop({ graceMs: 1_000 }); // the real registry gets 10 s; the stub proves the escalation path
  assert.equal(stopped.signal, 'SIGKILL', 'escalated to SIGKILL');
  assert.equal(stopped.gone, true); assert.equal(stopped.removed, true);
  assert.throws(() => process.kill(registry.pid, 0), { code: 'ESRCH' });
});

// ------------------------------------------------ startup-failure ownership ---
// Every failed start must clean up after itself BEFORE rejecting: the child (if
// any) stopped and reaped, the state directory gone, no probe or timer left.
// Each scenario runs in a CHILD test process under an external kill-and-reap
// deadline, so a regression that hangs cannot hang CI, and the child's own
// natural exit (not killed, exit 0) is the proof that no timer or request kept
// its event loop alive. The child reports what it observed right after the
// rejection — before this test's temporary directory is removed — and the
// parent re-checks the state directory independently.
const TLS_REGISTRY_URL = new URL('../oci/tls-registry.js', import.meta.url).href;
const DRIVER = `import { access } from 'node:fs/promises';
import { startTlsRegistry, syntheticPassword } from ${JSON.stringify(TLS_REGISTRY_URL)};
const scenario = JSON.parse(process.argv[1]);
const started = Date.now();
let outcome;
try {
  const registry = await startTlsRegistry({ ...scenario.options, password: syntheticPassword() });
  outcome = { rejected: false, origin: registry.origin };
  await registry.stop({ graceMs: 1000 });
} catch (error) {
  let stateExists = true;
  try { await access(scenario.options.stateDir); } catch { stateExists = false; }
  outcome = { rejected: true, message: error.message, cleanup: error.cleanup ?? null, stateExists, elapsedMs: Date.now() - started };
}
outcome.resources = process.getActiveResourcesInfo().filter(r => r === 'Timeout' || /TCP|TLS/.test(r));
process.stdout.write(JSON.stringify(outcome));`;

async function failedStart(t, label, options, env, { deadlineMs = 30_000 } = {}) {
  const started = Date.now();
  const result = await runBounded(process.execPath, ['--input-type=module', '-e', DRIVER, JSON.stringify({ options })], { env: { ...process.env, ...env }, timeout: deadlineMs });
  const wall = Date.now() - started;
  assert.equal(result.timedOut, false, `${label}: the driver did not exit within ${deadlineMs} ms — something kept it alive (killed ${result.signal}, reaped=${result.gone}). stderr: ${result.stderr.slice(-400)}`);
  assert.equal(result.code, 0, `${label}: the driver exited ${result.code} — an uncaught error escaped: ${result.stderr.slice(-600)}`);
  assert.equal(result.gone, true, `${label}: the driver was reaped`);
  assert.equal(result.stderr.trim(), '', `${label}: nothing on stderr (no unhandled rejection, no warning)`);
  const outcome = JSON.parse(result.stdout);
  assert.equal(outcome.rejected, true, `${label}: startTlsRegistry rejected`);
  assert.equal(outcome.stateExists, false, `${label}: the state directory was already gone when the rejection was observed`);
  assert.deepEqual(outcome.cleanup?.problems, [], `${label}: cleanup reported no problems`);
  assert.equal(outcome.cleanup.gone, true, `${label}: no child process survives`);
  assert.equal(outcome.cleanup.removed, true, `${label}: state removal confirmed`);
  assert.deepEqual(outcome.resources, [], `${label}: no timer or socket remained active in the driver after the rejection`);
  await assert.rejects(access(options.stateDir), `${label}: the parent confirms the state directory is gone`);
  t.diagnostic(`${label}: rejected in ${outcome.elapsedMs} ms (driver wall ${wall} ms): ${outcome.message.slice(0, 160)}`);
  return { ...outcome, wall };
}

test('startup failure: a 401 with an unexpected, nonempty challenge is rejected and leaves no process or state directory', LINUX_TOOLS, async t => {
  const dir = await scratch(t);
  const zot = await stubZot(dir, 'zot-bad-challenge');
  const outcome = await failedStart(t, 'unexpected challenge', { zot, openssl, perl, stateDir: join(dir, 'state') }, { STUB_ZOT_MODE: 'bad-challenge' });
  assert.match(outcome.message, /answered 401 with an unexpected authentication challenge "Bearer realm=.*expected "Basic realm=\\"owa-test-registry\\""/);
  assert.equal(outcome.cleanup.code, 0, 'the stub was stopped with SIGTERM and exited 0');
  assert.ok(outcome.elapsedMs < 10_000, 'rejected long before the 60 s deadline');
});

test('startup failure: a registry that accepts connections but never answers is cut off at the elapsed-time deadline, not at a longer probe timeout', LINUX_TOOLS, async t => {
  const dir = await scratch(t);
  const zot = await stubZot(dir, 'zot-hang');
  const readinessMs = 1_500;
  const outcome = await failedStart(t, 'never answers', { zot, openssl, perl, stateDir: join(dir, 'state'), readinessMs, probeTimeoutMs: 20_000 }, { STUB_ZOT_MODE: 'hang' });
  assert.match(outcome.message, new RegExp(`did not answer GET /v2/ with the expected 401 challenge over TLS within ${readinessMs} ms \\(last probe: GET /v2/ timed out after \\d+ ms\\)`));
  assert.ok(outcome.elapsedMs >= readinessMs, `rejected no earlier than the deadline (${outcome.elapsedMs} ms)`);
  assert.ok(outcome.elapsedMs < readinessMs + 3_000, `rejected close to the deadline, not at the 20 s probe timeout (${outcome.elapsedMs} ms)`);
  assert.equal(outcome.cleanup.probeAborted, false, 'the deadline-bounded probe had already been destroyed by its own timeout');
  assert.equal(outcome.cleanup.code, 0, 'the hanging stub was stopped and exited 0');
});

test('startup failure: a zot that exits before becoming ready is rejected promptly with its exit code and leaves no state', LINUX_TOOLS, async t => {
  const dir = await scratch(t);
  const zot = await stubZot(dir, 'zot-exits');
  const outcome = await failedStart(t, 'early exit', { zot, openssl, perl, stateDir: join(dir, 'state') }, { STUB_ZOT_EXIT: '3' });
  assert.match(outcome.message, /^zot exited before becoming ready \(code 3, signal null\)/);
  assert.equal(outcome.cleanup.code, 3);
  assert.ok(outcome.elapsedMs < 10_000, 'reported well before the 60 s deadline');
});

test('startup failure: a zot executable that cannot be spawned is rejected through the child error event and leaves no state', LINUX_TOOLS, async t => {
  const dir = await scratch(t);
  const outcome = await failedStart(t, 'spawn failure', { zot: join(dir, 'no-such-zot'), openssl, perl, stateDir: join(dir, 'state') }, {});
  assert.match(outcome.message, /^zot could not be started: ENOENT/);
  assert.equal(outcome.cleanup.code, null);
  assert.ok(outcome.elapsedMs < 10_000);
});

test('startup failure: a setup step failing after the state directory exists removes it before rejecting', LINUX_TOOLS, async t => {
  const dir = await scratch(t);
  const zot = await stubZot(dir, 'zot-unused');
  const brokenPerl = await executable(dir, 'perl-broken', '#!/bin/sh\nexit 7\n');
  const outcome = await failedStart(t, 'setup failure', { zot, openssl, perl: brokenPerl, stateDir: join(dir, 'state') }, {});
  assert.match(outcome.message, /^perl crypt exited 7/);
  assert.equal(outcome.cleanup.gone, true, 'no child was ever spawned');
  assert.equal(outcome.cleanup.code, null);
});

test('startup failure in-process: the rejection carries the original error and the cleanup record, and adds no live timer', LINUX_TOOLS, async t => {
  const dir = await scratch(t);
  const zot = await stubZot(dir, 'zot-bad-challenge-inproc');
  const timersBefore = process.getActiveResourcesInfo().filter(r => r === 'Timeout').length;
  process.env.STUB_ZOT_MODE = 'bad-challenge';
  let error;
  try { await startTlsRegistry({ zot, openssl, perl, stateDir: join(dir, 'state'), password: syntheticPassword() }); assert.fail('must reject'); }
  catch (caught) { error = caught; }
  finally { delete process.env.STUB_ZOT_MODE; }
  assert.match(error.message, /unexpected authentication challenge/);
  assert.equal(error.cleanup.gone, true); assert.equal(error.cleanup.removed, true); assert.deepEqual(error.cleanup.problems, []);
  await assert.rejects(access(join(dir, 'state')), 'state directory gone before this test\'s own cleanup runs');
  assert.equal(process.getActiveResourcesInfo().filter(r => r === 'Timeout').length, timersBefore, 'no timer left behind by the failed start');
});
