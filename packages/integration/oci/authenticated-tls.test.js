import test from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { access, cp, mkdir, readFile, stat, writeFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { canonicalJson, OWA_MEDIA_TYPE, sha256 } from '../../spec/src/index.js';
import { packDirectory } from '../../core/src/index.js';
import { OCI_IMAGE_MANIFEST, PATH_ANNOTATION, readOciLayout, writeOciLayout } from '../../transport-oci/src/index.js';
import { FilesystemMetadataStore } from '../../storage-filesystem/src/index.js';
import { tlsEnvironment } from './environment.js';
import { CLI, notice, record, run, tail, temp } from './helpers.js';
import { EMPTY_REGISTRY_CONFIG, TLS_REGISTRY_USER, basicAuthorization, httpsGet, registryConfigWith, runBounded, startTlsRegistry, syntheticPassword } from './tls-registry.js';

// Authenticated HTTPS transport proof (issue #46), alongside — not replacing —
// the plain-HTTP proofs in registry.test.js (#23) and duplicate-content.test.js
// (#9):
//
//   static corpus anchor -> packDirectory -> writeOciLayout
//     -> REAL ORAS over HTTPS with the test CA trusted and valid credentials
//     -> REAL Zot requiring authentication (TLS, htpasswd, access-control policy)
//     -> REAL ORAS pulls by tag and by digest -> readOciLayout -> CLI import-oci
//
// plus three negative controls, each with a FRESH, isolated client
// configuration: missing credentials, wrong credentials, and valid credentials
// WITHOUT trust in the test CA — never `--insecure`, never plain HTTP. The
// registry's session log (method/path/status only) shows where each failure
// happened. Afterwards the valid configuration must still succeed.
//
// Fixture: pack-cross-language-anchor — the corpus' duplicate-content anchor
// (four paths, two media types, one shared blob) — checked against its
// UNCHANGED static expectations, never against this implementation's output.
// No static OCI manifest digest exists; that digest is compared across
// writeOciLayout, the registry descriptor, the stored bytes and both pulls.
//
// Scope: this proves ORAS-mediated authenticated HTTPS transport preserves OWA
// identity and bytes with ORAS v1.3.4 and Zot v2.1.21. It does not claim tenant
// isolation, authorization-policy coverage, token exchange, compatibility with
// other providers, or production readiness.

const environment = await tlsEnvironment();

const corpus = JSON.parse(await readFile(new URL('../../../docs/conformance/v0.2/pack.json', import.meta.url), 'utf8'));
const anchor = corpus.vectors.find(vector => vector.id === 'pack-cross-language-anchor');
assert.ok(anchor && !anchor.expected.errorCategory, 'the static anchor must exist');
// Documented descriptor mapping (docs/oci.md → "Layer descriptor media types") for the anchor's four OWA media types.
const DESCRIPTOR_MEDIA_TYPE = Object.freeze({
  'text/javascript; charset=utf-8': 'text/javascript',
  'text/plain; charset=utf-8': 'text/plain',
  'text/html; charset=utf-8': 'text/html',
  'text/css; charset=utf-8': 'text/css'
});
const escapeRegExp = value => value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

async function materializeAnchor(root) {
  for (const file of anchor.input.files) {
    await mkdir(dirname(join(root, file.path)), { recursive: true });
    await writeFile(join(root, file.path), Buffer.from(file.contentBase64, 'base64'));
  }
}
/** Everything that identifies a packed/imported artifact, compared against the STATIC anchor. */
function assertMatchesAnchor(label, { manifest, artifactDigest, blobs }) {
  assert.equal(artifactDigest, anchor.expected.artifactDigest, `${label}: OWA artifact digest equals the static anchor`);
  assert.equal(canonicalJson(manifest), anchor.expected.canonicalJson, `${label}: canonical manifest bytes equal the static anchor`);
  assert.deepEqual(manifest, anchor.expected.manifest, `${label}: manifest (ordered entries, per-path media types) equals the static anchor`);
  assert.deepEqual(manifest.files.map(f => f.path), anchor.expected.manifest.files.map(f => f.path), `${label}: file order`);
  assert.deepEqual([...blobs.keys()].sort(), anchor.expected.blobDigests, `${label}: blob digest set equals the static anchor`);
  for (const file of anchor.input.files) {
    const bytes = Buffer.from(file.contentBase64, 'base64');
    assert.ok(Buffer.from(blobs.get(sha256(bytes))).equals(bytes), `${label}: bytes of ${file.path} are present under their digest`);
  }
}
/** Duplicate-content semantics on an OCI manifest: one descriptor per entry, shared digest, per-entry mapped media type. */
function assertDuplicateContentDescriptors(label, layers) {
  assert.equal(layers.length, anchor.expected.manifest.files.length, `${label}: one descriptor per file entry`);
  for (const file of anchor.expected.manifest.files) {
    const layer = layers.find(l => l.annotations?.[PATH_ANNOTATION] === file.path);
    assert.ok(layer, `${label}: descriptor for ${file.path}`);
    assert.equal(layer.digest, file.digest, `${label}: digest for ${file.path}`);
    assert.equal(layer.size, file.size, `${label}: size for ${file.path}`);
    assert.equal(layer.mediaType, DESCRIPTOR_MEDIA_TYPE[file.mediaType], `${label}: documented descriptor media type for ${file.path}`);
  }
  const shared = layers.filter(l => l.digest === SHARED_DIGEST);
  assert.equal(shared.length, SHARED_PATHS.length, `${label}: ${SHARED_PATHS.length} descriptors share one digest`);
  assert.deepEqual(new Set(shared.map(l => l.annotations[PATH_ANNOTATION])), new Set(SHARED_PATHS), `${label}: distinct path annotations over the shared blob`);
  assert.deepEqual(new Set(shared.map(l => l.mediaType)), new Set(['text/javascript', 'text/plain']), `${label}: two descriptor media types over one blob`);
}
const digestGroups = new Map();
for (const file of anchor.expected.manifest.files) digestGroups.set(file.digest, [...(digestGroups.get(file.digest) ?? []), file.path]);
const [SHARED_DIGEST, SHARED_PATHS] = [...digestGroups].find(([, paths]) => paths.length > 1);
assert.equal(SHARED_PATHS.length, 4, 'the anchor has four paths over one blob');

/** Minimal, isolated ORAS process environment: no user Docker/ORAS state can be read or written. */
function clientEnv(home) {
  return { PATH: process.env.PATH ?? '', HOME: home, DOCKER_CONFIG: join(home, '.docker'), ORAS_CACHE: join(home, 'oras-cache') };
}
async function orasOk(env, args, t, { input, home } = {}) {
  t.diagnostic(`oras ${args.join(' ')}${input === undefined ? '' : '   (password on stdin)'}`);
  const result = await runBounded(env.oras, args, { input, env: clientEnv(home) });
  assert.equal(result.timedOut, false, `oras ${args[0]} exceeded its deadline (killed, reaped=${result.gone})`);
  assert.equal(result.code, 0, `oras ${args[0]} exited ${result.code}${result.signal ? ` (${result.signal})` : ''}: ${tail(result.stderr || result.stdout)}`);
  return result;
}
async function orasDenied(env, args, t, { home, secret }) {
  t.diagnostic(`oras ${args.join(' ')}   (expected to fail)`);
  const result = await runBounded(env.oras, args, { env: clientEnv(home) });
  assert.equal(result.timedOut, false, `oras ${args[0]} exceeded its deadline (killed, reaped=${result.gone})`);
  assert.notEqual(result.code, 0, `oras ${args[0]} unexpectedly succeeded: ${tail(result.stdout)}`);
  assert.equal(result.gone, true, 'the failed ORAS process was reaped');
  const output = result.stdout + result.stderr;
  assert.ok(!output.includes(secret), 'ORAS output never contains the password');
  assert.ok(!output.includes(Buffer.from(`${TLS_REGISTRY_USER}:${secret}`).toString('base64')), 'ORAS output never contains the encoded credential');
  return { ...result, output };
}
const requestsTo = (entries, repo) => entries.filter(e => e.path.startsWith(`/v2/${repo}/`));
const statuses = entries => [...new Set(entries.map(e => e.statusCode))].sort();

test('ORAS v1.3.4 + Zot v2.1.21: an OWA artifact round-trips through a disposable AUTHENTICATED HTTPS registry with certificate verification; missing, wrong and untrusted-CA configurations fail at the intended boundary', { skip: environment.skip, timeout: 300_000 }, async t => {
  if (environment.fail) assert.fail(environment.fail);
  const env = environment;
  t.diagnostic(`oras ${env.oras}; zot ${env.zot}; openssl ${env.openssl}; perl ${env.perl}; required=${env.required}; node ${process.version} ${process.platform}`);

  // ---- the user's real client state must never change: snapshot it ---------------
  const userDockerConfig = join(process.env.DOCKER_CONFIG ?? join(process.env.HOME ?? '', '.docker'), 'config.json');
  const userStateBefore = await stat(userDockerConfig).then(s => `${s.size}:${s.mtimeMs}`, () => 'absent');

  // ---- disposable authenticated HTTPS registry ----------------------------------------
  const password = syntheticPassword();
  const stateDir = await temp(t, 'tls-registry');
  const registry = await startTlsRegistry({ zot: env.zot, openssl: env.openssl, perl: env.perl, stateDir, password });
  let stopped = null;
  t.after(async () => {
    stopped = stopped ?? await registry.stop();
    assert.equal(stopped.gone, true, `registry pid ${registry.pid} is gone after stop`);
    assert.equal(stopped.removed, true, 'registry state (keys, certificate, htpasswd, storage, log) was removed');
    const userStateAfter = await stat(userDockerConfig).then(s => `${s.size}:${s.mtimeMs}`, () => 'absent');
    assert.equal(userStateAfter, userStateBefore, 'the user\'s Docker/ORAS configuration is untouched');
  });
  record(t, { registry: `${registry.origin} (loopback, TLS, htpasswd auth required; realm challenge "${registry.challenge}"; ready after ${registry.readyAfterMs} ms; pid ${registry.pid})`, 'server certificate SAN': registry.tls.subjectAltName, user: registry.username });
  assert.equal(registry.exited(), null, 'registry is running');

  // The registry challenges anonymous requests and answers authenticated ones — checked with TLS verified against the test CA only.
  const anonymous = await httpsGet(registry.origin, '/v2/', { ca: registry.ca.pem });
  assert.equal(anonymous.status, 401, 'anonymous GET /v2/ is challenged');
  assert.match(anonymous.headers['www-authenticate'] ?? '', /^Basic realm=/);
  assert.equal((await httpsGet(registry.origin, '/v2/', { ca: registry.ca.pem, headers: { authorization: basicAuthorization(registry.username, password) } })).status, 200, 'authenticated GET /v2/ succeeds');
  assert.equal((await httpsGet(registry.origin, '/v2/', { ca: registry.ca.pem, headers: { authorization: basicAuthorization(registry.username, 'not-the-password') } })).status, 401, 'a wrong password is rejected');
  await assert.rejects(httpsGet(registry.origin, '/v2/'), /certificate|CERT|self.signed|unable to verify/i, 'without the test CA, Node rejects the certificate too (system trust store is not consulted for a private CA)');

  // ---- fixture: the static duplicate-content anchor ------------------------------
  const site = await temp(t, 'tls-site');
  await materializeAnchor(site);
  const packed = await packDirectory(site, anchor.input.entrypoint);
  assertMatchesAnchor('packed fixture', packed);
  const layout = await temp(t, 'tls-layout');
  const written = await writeOciLayout({ manifest: packed.manifest, blobs: packed.blobs, output: layout, ref: 'v1' });
  assert.equal(written.artifactDigest, anchor.expected.artifactDigest);
  const localManifestBytes = await readFile(join(layout, 'blobs', 'sha256', written.ociManifestDigest.slice(7)));
  assertDuplicateContentDescriptors('writeOciLayout', JSON.parse(localManifestBytes.toString('utf8')).layers);
  record(t, { 'OWA artifact digest (static anchor)': anchor.expected.artifactDigest, 'OCI manifest digest (writeOciLayout)': written.ociManifestDigest, 'shared blob': `${SHARED_DIGEST} under ${SHARED_PATHS.join(', ')}` });

  // ---- valid client: isolated registry-config, password on stdin, CA trusted ---------
  const home = await temp(t, 'tls-home');
  const validConfig = join(home, 'registry-config.json');
  const login = await orasOk(env, ['login', '--username', registry.username, '--password-stdin', '--registry-config', validConfig, '--ca-file', registry.ca.cert, registry.host], t, { input: `${password}\n`, home });
  assert.match(login.stdout + login.stderr, /Login Succeeded/);
  const storedConfig = JSON.parse(await readFile(validConfig, 'utf8'));
  assert.deepEqual(Object.keys(storedConfig.auths ?? {}), [registry.host], 'the isolated file holds exactly the test registry credential');
  await assert.rejects(access(join(home, '.docker', 'config.json')), 'ORAS wrote nothing to the (temporary) default Docker config path');

  // ---- push over HTTPS with valid credentials ---------------------------------------
  const repo = `owa-ci/tls-${randomUUID()}`;
  const ref = `${registry.host}/${repo}`;
  const push = await orasOk(env, ['cp', '--from-oci-layout', `${layout}:v1`, `${ref}:v1`, '--to-registry-config', validConfig, '--to-ca-file', registry.ca.cert], t, { home });
  assert.match(push.stdout + push.stderr, new RegExp(escapeRegExp(written.ociManifestDigest)), 'oras reports the pushed OCI manifest digest');
  const descriptor = JSON.parse((await orasOk(env, ['manifest', 'fetch', '--descriptor', '--registry-config', validConfig, '--ca-file', registry.ca.cert, `${ref}:v1`], t, { home })).stdout);
  assert.equal(descriptor.digest, written.ociManifestDigest, 'registry descriptor digest === writeOciLayout OCI manifest digest');
  assert.equal((await orasOk(env, ['resolve', '--registry-config', validConfig, '--ca-file', registry.ca.cert, `${ref}:v1`], t, { home })).stdout.trim(), written.ociManifestDigest);
  // Test-only authenticated HTTPS inspection: the stored manifest bytes, the config blob and the shared blob.
  const authorization = { authorization: basicAuthorization(registry.username, password) };
  const stored = await httpsGet(registry.origin, `/v2/${repo}/manifests/v1`, { ca: registry.ca.pem, headers: { ...authorization, accept: OCI_IMAGE_MANIFEST } });
  assert.equal(stored.status, 200);
  assert.equal(stored.headers['docker-content-digest'], written.ociManifestDigest);
  assert.ok(stored.body.equals(localManifestBytes), 'Zot stored the exact OCI manifest bytes');
  const remote = JSON.parse(stored.body.toString('utf8'));
  assert.equal(remote.artifactType, OWA_MEDIA_TYPE); assert.equal(remote.config.digest, anchor.expected.artifactDigest);
  assertDuplicateContentDescriptors('registry-stored manifest', remote.layers);
  const sharedHead = await httpsGet(registry.origin, `/v2/${repo}/blobs/${SHARED_DIGEST}`, { method: 'HEAD', ca: registry.ca.pem, headers: authorization });
  assert.equal(sharedHead.status, 200, 'the shared blob is addressable once by its digest');
  const config = await httpsGet(registry.origin, `/v2/${repo}/blobs/${anchor.expected.artifactDigest}`, { ca: registry.ca.pem, headers: authorization });
  assert.equal(config.body.toString('utf8'), anchor.expected.canonicalJson, 'the registry-held config blob is the static canonical manifest');
  assert.equal((await httpsGet(registry.origin, `/v2/${repo}/manifests/v1`, { ca: registry.ca.pem, headers: { accept: OCI_IMAGE_MANIFEST } })).status, 401, 'the pushed manifest is NOT readable anonymously');
  record(t, { 'registry descriptor digest': descriptor.digest, 'Docker-Content-Digest': stored.headers['docker-content-digest'] });

  // ---- pull by tag and by immutable digest; identity against the static anchor ------
  const pulledTag = await temp(t, 'tls-pulled-tag');
  await orasOk(env, ['cp', '--from-registry-config', validConfig, '--from-ca-file', registry.ca.cert, '--to-oci-layout', `${ref}:v1`, `${pulledTag}:v1`], t, { home });
  const pulledDigest = await temp(t, 'tls-pulled-digest');
  await orasOk(env, ['cp', '--from-registry-config', validConfig, '--from-ca-file', registry.ca.cert, '--to-oci-layout', `${ref}@${written.ociManifestDigest}`, `${pulledDigest}:by-digest`], t, { home });
  const byTag = await readOciLayout({ input: pulledTag, ref: 'v1' });
  const byDigest = await readOciLayout({ input: pulledDigest, ref: 'by-digest' });
  for (const [label, imported] of [['tag pull', byTag], ['digest pull', byDigest]]) {
    assertMatchesAnchor(label, imported);
    assert.equal(imported.ociManifestDigest, written.ociManifestDigest, `${label}: OCI manifest digest preserved`);
    assertDuplicateContentDescriptors(label, imported.ociManifest.layers);
    assert.equal(imported.blobs.size, anchor.expected.blobDigests.length, `${label}: one returned blob per distinct digest`);
  }
  record(t, { 'tag-pulled OCI manifest digest': byTag.ociManifestDigest, 'digest-pulled OCI manifest digest': byDigest.ociManifestDigest });

  // ---- import through the real CLI and compare with the original -----------------------
  const data = await temp(t, 'tls-data');
  const slug = `tls-${randomUUID().slice(0, 8)}`;
  const imported = await run(process.execPath, [CLI, 'import-oci', pulledTag, '--ref', 'v1', '--site', slug, '--data', data]);
  assert.equal(imported.code, 0, `import-oci exited ${imported.code}: ${tail(imported.stderr)}`);
  assert.match(imported.stdout, new RegExp(`Stored ${anchor.expected.blobDigests.length} blob\\(s\\), reused 0`), 'one stored blob per distinct digest, four entries over the shared one');
  const metadata = new FilesystemMetadataStore(data);
  const siteRecord = await metadata.getSite(slug);
  const release = await metadata.getRelease(siteRecord.id, siteRecord.activeReleaseId);
  assert.equal(release.artifactDigest, anchor.expected.artifactDigest, 'imported release carries the original OWA artifact digest');
  assert.deepEqual(release.manifest, anchor.expected.manifest, 'imported release manifest equals the static anchor');
  record(t, { 'imported release': `${release.id} ${release.artifactDigest}` });

  // ================================================================ negative controls ===
  // The protected artifact exists (checked through the valid configuration right before).
  assert.equal(JSON.parse((await orasOk(env, ['manifest', 'fetch', '--descriptor', '--registry-config', validConfig, '--ca-file', registry.ca.cert, `${ref}:v1`], t, { home })).stdout).digest, written.ociManifestDigest);
  const matrix = {};
  const controls = [
    // label, fresh registry-config content (null → no --registry-config file is usable at all), CA trusted?, expected boundary
    ['missing credentials', EMPTY_REGISTRY_CONFIG, true, { stderr: /basic credential not found|401/, registryStatus: 401 }],
    ['wrong credentials', registryConfigWith(registry.host, registry.username, `${password}-wrong`), true, { stderr: /response status code 401/, registryStatus: 401 }],
    ['valid credentials, test CA not trusted', registryConfigWith(registry.host, registry.username, password), false, { stderr: /tls: failed to verify certificate: x509: certificate signed by unknown authority/, registryStatus: null }]
  ];
  for (const [label, configContent, trustCA, expected] of controls) {
    const freshHome = await temp(t, 'tls-fresh-client');           // fresh HOME/DOCKER_CONFIG/ORAS_CACHE: no cached credential or trust
    const freshConfig = join(freshHome, 'registry-config.json');
    await writeFile(freshConfig, configContent);
    const caArgs = side => trustCA ? [`--${side}-ca-file`, registry.ca.cert] : [];
    const before = await registry.requests();
    // pull the protected artifact
    const pullDir = await temp(t, 'tls-denied-pull');
    const pull = await orasDenied(env, ['cp', '--from-registry-config', freshConfig, ...caArgs('from'), '--to-oci-layout', `${ref}:v1`, `${pullDir}:v1`], t, { home: freshHome, secret: password });
    assert.match(pull.output, expected.stderr, `${label}: pull failed at the intended boundary`);
    // ORAS may initialise the destination layout before the denied fetch; what matters is that no manifest or artifact arrived.
    await assert.rejects(access(join(pullDir, 'blobs', 'sha256', written.ociManifestDigest.slice(7))), `${label}: the OCI manifest was not pulled`);
    await assert.rejects(readOciLayout({ input: pullDir, ref: 'v1' }), `${label}: nothing importable was pulled`);
    // push a second copy to a NEW repository
    const deniedRepo = `${repo}-denied-${randomUUID().slice(0, 8)}`;
    const pushAttempt = await orasDenied(env, ['cp', '--from-oci-layout', `${layout}:v1`, `${registry.host}/${deniedRepo}:v1`, '--to-registry-config', freshConfig, ...caArgs('to')], t, { home: freshHome, secret: password });
    assert.match(pushAttempt.output, expected.stderr, `${label}: push failed at the intended boundary`);
    const after = await registry.requests();
    const during = after.slice(before.length);
    const touched = [...requestsTo(during, repo), ...requestsTo(during, deniedRepo)];
    if (expected.registryStatus === null) {
      assert.ok(!/401|Unauthorized/.test(pull.output + pushAttempt.output), `${label}: the failure is TLS verification, not an HTTP status`);
      assert.equal(during.length, 0, `${label}: no request reached the registry (TLS verification failed before HTTP)`);
    } else {
      assert.ok(touched.length > 0, `${label}: the registry saw the attempts`);
      assert.deepEqual(statuses(touched), [expected.registryStatus], `${label}: every request for these repositories was answered ${expected.registryStatus}`);
    }
    // the denied push created nothing: the new repository does not resolve even with valid credentials
    const probe = await runBounded(env.oras, ['manifest', 'fetch', '--descriptor', '--registry-config', validConfig, '--ca-file', registry.ca.cert, `${registry.host}/${deniedRepo}:v1`], { env: clientEnv(home) });
    assert.notEqual(probe.code, 0, `${label}: the denied push created no artifact`);
    matrix[label] = { pull: 'denied', push: 'denied', registry: expected.registryStatus === null ? 'no request received' : `${touched.length} request(s), all ${expected.registryStatus}` };
    t.diagnostic(`${label}: pull denied (${tail(pull.stderr).slice(0, 160)}); push denied; registry: ${matrix[label].registry}`);
  }

  // ---- the valid configuration still succeeds after the negative controls -------------
  const again = await temp(t, 'tls-pulled-again');
  await orasOk(env, ['cp', '--from-registry-config', validConfig, '--from-ca-file', registry.ca.cert, '--to-oci-layout', `${ref}@${written.ociManifestDigest}`, `${again}:again`], t, { home });
  const stillGood = await readOciLayout({ input: again, ref: 'again' });
  assertMatchesAnchor('pull after the negative controls', stillGood);
  assert.equal(stillGood.ociManifestDigest, written.ociManifestDigest);
  assert.equal(registry.exited(), null, 'registry still running after the controls');
  const summary = await registry.requests();
  record(t, { 'registry session log': `${summary.length} requests; statuses ${statuses(summary).join(',')}`, 'negative controls': matrix });

  // ---- controlled shutdown and cleanup evidence (also asserted in the after hook) -----
  stopped = await registry.stop();
  assert.equal(stopped.gone, true, 'registry process gone');
  assert.equal(stopped.removed, true, 'state directory removed');
  await assert.rejects(access(registry.ca.key), 'the test CA private key was removed');
  await assert.rejects(access(registry.tls.key), 'the server private key was removed');
  await assert.rejects(access(join(stateDir, 'htpasswd')), 'the htpasswd file was removed');
  const untouched = await temp(t, 'tls-untouched'); await cp(pulledTag, untouched, { recursive: true });
  assertMatchesAnchor('untouched copy of the tag pull (control)', await readOciLayout({ input: untouched, ref: 'v1' }));
  notice('oci authenticated https', `ORAS+Zot authenticated HTTPS round trip OK: OWA ${anchor.expected.artifactDigest}; OCI manifest ${written.ociManifestDigest} (registry ${descriptor.digest}; tag pull ${byTag.ociManifestDigest}; digest pull ${byDigest.ociManifestDigest}); import ${release.id}; negative controls: ${Object.entries(matrix).map(([k, v]) => `${k} -> pull ${v.pull}, push ${v.push}, registry ${v.registry}`).join('; ')}; registry stopped pid gone=${stopped.gone} state removed=${stopped.removed}`);
});
