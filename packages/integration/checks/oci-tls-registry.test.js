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
  assert.equal(config.storage.rootDirectory, '/s/data'); assert.equal(config.storage.gc, false);
  assert.equal(config.log.level, 'info'); assert.equal(config.log.output, '/s/zot.log');
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
// on the configured loopback port, and challenges every request with 401 Basic —
// exactly the readiness signal startTlsRegistry waits for.
const STUB_ZOT = `#!/usr/bin/env node
const fs = require('node:fs'); const https = require('node:https');
const cfg = JSON.parse(fs.readFileSync(process.argv[3], 'utf8'));
if (process.env.STUB_ZOT_EXIT) process.exit(Number(process.env.STUB_ZOT_EXIT));
const server = https.createServer({ cert: fs.readFileSync(cfg.http.tls.cert), key: fs.readFileSync(cfg.http.tls.key) }, (req, res) => {
  fs.appendFileSync(cfg.log.output, JSON.stringify({ level: 'info', message: 'HTTP API', method: req.method, path: req.url, statusCode: 401 }) + '\\n');
  res.writeHead(401, { 'www-authenticate': 'Basic realm="' + cfg.http.realm + '"' }); res.end();
});
server.listen(Number(cfg.http.port), cfg.http.address);
process.on('SIGTERM', () => { server.close(() => process.exit(0)); });
`;

test('registry lifecycle against a stub zot: readiness is the 401 challenge over verified TLS, stop() reaps the process and removes every secret', { skip: process.platform === 'linux' && openssl && perl ? false : 'needs openssl and Linux bcrypt' }, async t => {
  const dir = await scratch(t);
  const zot = await executable(dir, 'zot-stub', STUB_ZOT.replace('#!/usr/bin/env node', `#!${process.execPath}`));
  const stateDir = join(dir, 'state');
  const registry = await startTlsRegistry({ zot, openssl, perl, stateDir, password: syntheticPassword() });
  t.after(async () => { if (!registry.exited()) await registry.stop(); });
  assert.match(registry.origin, /^https:\/\/127\.0\.0\.1:\d+$/);
  assert.match(registry.challenge, new RegExp(`^Basic realm="${TLS_REGISTRY_REALM}"`));
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

test('registry lifecycle: a zot that exits before becoming ready fails promptly and cleans up; a zot that ignores SIGTERM is SIGKILLed and reaped', { skip: process.platform === 'linux' && openssl && perl ? false : 'needs openssl and Linux bcrypt' }, async t => {
  const dir = await scratch(t);
  const exiting = await executable(dir, 'zot-exits', STUB_ZOT.replace('#!/usr/bin/env node', `#!${process.execPath}`));
  const started = Date.now();
  process.env.STUB_ZOT_EXIT = '3';
  try {
    await assert.rejects(startTlsRegistry({ zot: exiting, openssl, perl, stateDir: join(dir, 'state-exits'), password: syntheticPassword() }), /zot exited before becoming ready \(code 3, signal null\)/);
  } finally { delete process.env.STUB_ZOT_EXIT; }
  assert.ok(Date.now() - started < 30_000, 'reported well before the 60 s readiness bound');
  // Ignores SIGTERM: stop() must escalate to SIGKILL and still reap and clean up.
  const stubborn = await executable(dir, 'zot-stubborn', STUB_ZOT.replace('#!/usr/bin/env node', `#!${process.execPath}`).replace("process.on('SIGTERM', () => { server.close(() => process.exit(0)); });", "process.on('SIGTERM', () => {});"));
  const registry = await startTlsRegistry({ zot: stubborn, openssl, perl, stateDir: join(dir, 'state-stubborn'), password: syntheticPassword() });
  const stopped = await registry.stop({ graceMs: 1_000 }); // the real registry gets 10 s; the stub proves the escalation path
  assert.equal(stopped.signal, 'SIGKILL', 'escalated to SIGKILL');
  assert.equal(stopped.gone, true); assert.equal(stopped.removed, true);
});
