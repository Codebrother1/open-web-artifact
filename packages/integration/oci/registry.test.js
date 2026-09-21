import test from 'node:test';
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { createHash, randomUUID } from 'node:crypto';
import { once } from 'node:events';
import { request as httpRequest } from 'node:http';
import { chmod, cp, mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { artifactDigest, canonicalJson, OWA_MEDIA_TYPE, sha256 } from '../../spec/src/index.js';
import { packDirectory } from '../../core/src/index.js';
import { OCI_IMAGE_MANIFEST, ociLayerMediaType, readOciLayout, writeOciLayout } from '../../transport-oci/src/index.js';
import { FilesystemBlobStore, FilesystemMetadataStore } from '../../storage-filesystem/src/index.js';
import { createContentServer } from '../../server/src/index.js';
import { ociEnvironment } from './environment.js';

// Live OCI registry interoperability (issue #23):
//
//   OWA directory -> packDirectory -> writeOciLayout -> REAL ORAS -> REAL Zot
//                 -> REAL ORAS -> fresh OCI layout -> readOciLayout -> CLI import -> serve
//
// OWA owns the layout encoding; ORAS owns registry transport; Zot is the real
// registry. Test-only HTTP requests to the registry are supplemental inspection,
// never the transport under test. The registry is loopback, plain HTTP and
// disposable: this proves content-addressed transport interoperability with the
// pinned ORAS/Zot versions, not TLS, auth, signing or remote deployment.
//
// Fixture contents have DISTINCT digests on purpose: duplicate-content path
// semantics are issue #9 and stay out of scope here.

const CLI = fileURLToPath(new URL('../../cli/src/index.js', import.meta.url));
const environment = await ociEnvironment();

/** Run an external command with array arguments; never a shell string. */
function run(command, args, { timeout = 120_000 } = {}) {
  return new Promise(resolve => {
    execFile(command, args, { timeout, maxBuffer: 8 * 1024 * 1024, env: { ...process.env, ORAS_CACHE: undefined } }, (error, stdout, stderr) => {
      resolve({ code: error ? (error.code ?? 1) : 0, stdout: String(stdout ?? ''), stderr: String(stderr ?? ''), signal: error?.signal ?? null });
    });
  });
}
const tail = text => text.trim().split('\n').slice(-4).join(' | ').slice(0, 400);
/** ORAS must succeed; a non-zero exit is a failure with safe diagnostics (command, code, stderr tail). */
async function oras(env, args, t) {
  t?.diagnostic(`oras ${args.join(' ')}`);
  const result = await run(env.oras, args);
  assert.equal(result.code, 0, `oras ${args[0]} exited ${result.code}${result.signal ? ` (${result.signal})` : ''}: ${tail(result.stderr || result.stdout)}`);
  return result;
}
/** ORAS must FAIL (non-zero exit); a zero exit is the failure. */
async function orasMustFail(env, args, t) {
  t?.diagnostic(`oras ${args.join(' ')}   (expected to fail)`);
  const result = await run(env.oras, args);
  assert.notEqual(result.code, 0, `oras ${args[0]} unexpectedly succeeded: ${tail(result.stdout)}`);
  return result;
}
/** Test-only registry inspection over plain HTTP; returns status, headers and body bytes. */
async function registryGet(url, { method = 'GET', accept } = {}) {
  const res = await fetch(url, { method, headers: accept ? { accept } : {}, signal: AbortSignal.timeout(15_000) });
  return { status: res.status, headers: Object.fromEntries(res.headers), body: Buffer.from(await res.arrayBuffer()) };
}
/** GET through the real content listener with an explicit Host (node:http, so Host is not rewritten). */
function serve(port, host, path) {
  return new Promise((resolve, reject) => {
    const req = httpRequest({ hostname: '127.0.0.1', port, path, method: 'GET', headers: { host, connection: 'close' } }, res => {
      const chunks = []; res.on('data', c => chunks.push(c)); res.on('error', reject);
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks) }));
    });
    req.on('error', reject); req.end();
  });
}
async function ociManifestOf(layout) {
  const index = JSON.parse(await readFile(join(layout, 'index.json'), 'utf8'));
  return { index, descriptors: index.manifests ?? [] };
}
const temp = async (t, name) => { const dir = await mkdtemp(join(tmpdir(), `owa-oci-${name}-`)); t.after(() => rm(dir, { recursive: true, force: true })); return dir; };
const record = (t, facts) => { for (const [k, v] of Object.entries(facts)) t.diagnostic(`${k}: ${typeof v === 'string' ? v : JSON.stringify(v)}`); };

/** Deterministic fixture: ordinary parameterized web types, a nested path, a binary file and an empty file. */
async function writeFixture(dir, { version = 1 } = {}) {
  await mkdir(join(dir, 'assets'), { recursive: true });
  await writeFile(join(dir, 'index.html'), `<!doctype html><html><head><meta charset="utf-8"><title>OWA OCI interop v${version}</title></head><body><h1>interop v${version}</h1></body></html>`);
  await writeFile(join(dir, 'assets', 'app.js'), 'document.documentElement.dataset.interop = "ready";\n');
  await writeFile(join(dir, 'assets', 'style.css'), 'body { color: rgb(1, 2, 3); }\n');
  await writeFile(join(dir, 'assets', 'blob.bin'), Buffer.from([0x00, 0x01, 0x7f, 0x80, 0xfe, 0xff, 0x0a, 0x0d]));
  await writeFile(join(dir, 'empty.txt'), '');
}

test('ORAS v1.3.4 + Zot: OWA layout -> registry -> fresh layout round trip preserves OWA identity, bytes and OCI descriptors', { skip: environment.skip, timeout: 300_000 }, async t => {
  if (environment.fail) assert.fail(environment.fail);
  const env = environment;
  t.diagnostic(`registry ${env.registry} (loopback, plain HTTP); oras ${env.oras}; required=${env.required}; node ${process.version}`);
  const versions = await run(env.oras, ['version']);
  assert.equal(versions.code, 0, 'oras version must run');
  t.diagnostic(`oras version: ${versions.stdout.split('\n').map(l => l.trim()).filter(Boolean).join('; ')}`);

  // ---- registry is a real OCI Distribution endpoint ----------------------------
  const v2 = await registryGet(`${env.registry}/v2/`);
  assert.equal(v2.status, 200, 'GET /v2/ must succeed');
  record(t, { 'GET /v2/': `${v2.status} ${v2.headers['docker-distribution-api-version'] ?? ''} ${v2.headers['content-type'] ?? ''}`.trim() });

  // ---- fixture: distinct digests, ordinary parameterized media types ------------
  const site = await temp(t, 'site');
  await writeFixture(site);
  const packed = await packDirectory(site);
  assert.equal(new Set(packed.manifest.files.map(f => f.digest)).size, packed.manifest.files.length, 'every fixture file has a distinct digest (issue #9 out of scope)');
  assert.deepEqual(packed.manifest.files.map(f => f.path), ['/assets/app.js', '/assets/blob.bin', '/assets/style.css', '/empty.txt', '/index.html']);
  const types = Object.fromEntries(packed.manifest.files.map(f => [f.path, f.mediaType]));
  assert.equal(types['/index.html'], 'text/html; charset=utf-8'); assert.equal(types['/assets/app.js'], 'text/javascript; charset=utf-8');
  assert.equal(types['/assets/style.css'], 'text/css; charset=utf-8'); assert.equal(types['/assets/blob.bin'], 'application/octet-stream');
  assert.equal(types['/empty.txt'], 'text/plain; charset=utf-8');
  const canonical = canonicalJson(packed.manifest);
  record(t, { 'OWA artifact digest': packed.artifactDigest, files: packed.manifest.files.map(f => `${f.path} ${f.digest.slice(0, 19)}… ${f.size}B ${f.mediaType}`) });

  // ---- export: writeOciLayout, then a local control read ------------------------
  const layout = await temp(t, 'layout');
  const written = await writeOciLayout({ manifest: packed.manifest, blobs: packed.blobs, output: layout, ref: 'v1' });
  assert.equal(written.artifactDigest, packed.artifactDigest);
  const control = await readOciLayout({ input: layout, ref: 'v1' });
  assert.equal(control.artifactDigest, packed.artifactDigest);
  for (const [digest, bytes] of packed.blobs) assert.ok(Buffer.from(control.blobs.get(digest)).equals(Buffer.from(bytes)));
  const localManifestBytes = await readFile(join(layout, 'blobs', 'sha256', written.ociManifestDigest.slice(7)));
  const localManifest = JSON.parse(localManifestBytes.toString('utf8'));
  record(t, { 'OCI manifest digest (writeOciLayout)': written.ociManifestDigest, 'OCI layer descriptors': localManifest.layers.map(l => `${l.annotations['dev.openwebartifact.path']} ${l.mediaType}`) });

  // ---- push: OWA layout -> Zot through the REAL ORAS CLI --------------------------
  const repo = `owa-ci/${randomUUID()}`;
  const ref = `${env.registryHost}/${repo}`;
  const push = await oras(env, ['cp', '--from-oci-layout', `${layout}:v1`, `${ref}:v1`, '--to-plain-http'], t);
  assert.match(push.stdout + push.stderr, new RegExp(written.ociManifestDigest.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')), 'oras reports the pushed OCI manifest digest');

  // ---- registry descriptor proof (ORAS, then test-only Distribution HTTP) --------
  const descriptor = JSON.parse((await oras(env, ['manifest', 'fetch', '--descriptor', '--plain-http', `${ref}:v1`], t)).stdout);
  assert.equal(descriptor.digest, written.ociManifestDigest, 'registry descriptor digest === writeOciLayout OCI manifest digest');
  assert.equal(descriptor.mediaType, OCI_IMAGE_MANIFEST); assert.equal(descriptor.size, localManifestBytes.byteLength);
  const resolved = (await oras(env, ['resolve', '--plain-http', `${ref}:v1`], t)).stdout.trim();
  assert.equal(resolved, written.ociManifestDigest);

  const stored = await registryGet(`${env.registry}/v2/${repo}/manifests/v1`, { accept: OCI_IMAGE_MANIFEST });
  assert.equal(stored.status, 200);
  assert.equal(stored.headers['content-type'], OCI_IMAGE_MANIFEST);
  assert.equal(stored.headers['docker-content-digest'], written.ociManifestDigest, 'Docker-Content-Digest === OCI manifest digest');
  assert.equal(`sha256:${createHash('sha256').update(stored.body).digest('hex')}`, written.ociManifestDigest, 'stored manifest bytes hash to the digest');
  assert.ok(stored.body.equals(localManifestBytes), 'Zot stored the exact OCI manifest bytes OWA wrote');
  const remote = JSON.parse(stored.body.toString('utf8'));
  assert.equal(remote.schemaVersion, 2); assert.equal(remote.mediaType, OCI_IMAGE_MANIFEST); assert.equal(remote.artifactType, OWA_MEDIA_TYPE);
  assert.equal(remote.config.mediaType, OWA_MEDIA_TYPE); assert.equal(remote.config.digest, packed.artifactDigest);
  assert.equal(remote.annotations['dev.openwebartifact.artifact.digest'], packed.artifactDigest);
  assert.equal(remote.layers.length, packed.manifest.files.length);
  for (const file of packed.manifest.files) {
    const layer = remote.layers.find(l => l.digest === file.digest);
    assert.ok(layer, `layer for ${file.path}`);
    assert.equal(layer.size, file.size);
    assert.equal(layer.mediaType, ociLayerMediaType(file.mediaType), `descriptor media type for ${file.path} is the mapped OCI value`);
    assert.match(layer.mediaType, /^[A-Za-z0-9][A-Za-z0-9!#$&^_.+-]{0,126}\/[A-Za-z0-9][A-Za-z0-9!#$&^_.+-]{0,126}$/);
    assert.equal(layer.annotations['dev.openwebartifact.path'], file.path);
    assert.equal(layer.annotations['org.opencontainers.image.title'], file.path.slice(1));
    const head = await registryGet(`${env.registry}/v2/${repo}/blobs/${file.digest}`, { method: 'HEAD' });
    assert.equal(head.status, 200, `blob ${file.path} exists in the registry`);
    assert.equal(Number(head.headers['content-length']), file.size);
  }
  const config = await registryGet(`${env.registry}/v2/${repo}/blobs/${packed.artifactDigest}`);
  assert.equal(config.status, 200);
  assert.equal(config.body.toString('utf8'), canonical, 'the registry-held config blob IS the canonical OWA manifest, full media types included');
  record(t, { 'registry descriptor digest': descriptor.digest, 'Docker-Content-Digest': stored.headers['docker-content-digest'], 'stored descriptor media types': remote.layers.map(l => l.mediaType) });

  // ---- pull by TAG into a NEW empty layout, through ORAS --------------------------
  const pulledTag = await temp(t, 'pulled-tag');
  await oras(env, ['cp', '--from-plain-http', '--to-oci-layout', `${ref}:v1`, `${pulledTag}:v1`], t);
  const tagLayout = await ociManifestOf(pulledTag);
  assert.equal(JSON.parse(await readFile(join(pulledTag, 'oci-layout'), 'utf8')).imageLayoutVersion, '1.0.0');
  assert.equal(tagLayout.descriptors.length, 1); assert.equal(tagLayout.descriptors[0].digest, written.ociManifestDigest);
  assert.ok((await readFile(join(pulledTag, 'blobs', 'sha256', written.ociManifestDigest.slice(7)))).equals(localManifestBytes), 'pulled OCI manifest bytes are identical');
  const byTag = await readOciLayout({ input: pulledTag, ref: 'v1' });
  const assertRoundTrip = (imported, label) => {
    assert.equal(imported.artifactDigest, packed.artifactDigest, `${label}: OWA artifact digest preserved`);
    assert.equal(canonicalJson(imported.manifest), canonical, `${label}: canonical OWA manifest bytes identical`);
    assert.deepEqual(imported.manifest, packed.manifest);
    assert.equal(imported.ociManifestDigest, written.ociManifestDigest, `${label}: OCI manifest digest preserved`);
    assert.equal(imported.blobs.size, packed.blobs.size);
    for (const file of packed.manifest.files) {
      const bytes = Buffer.from(imported.blobs.get(file.digest));
      assert.ok(bytes.equals(Buffer.from(packed.blobs.get(file.digest))), `${label}: ${file.path} bytes identical`);
      assert.equal(sha256(bytes), file.digest); assert.equal(bytes.byteLength, file.size);
    }
    assert.deepEqual(imported.manifest.files.map(f => f.mediaType), packed.manifest.files.map(f => f.mediaType), `${label}: full OWA media types recovered from the config`);
  };
  assertRoundTrip(byTag, 'tag pull');

  // ---- pull by immutable DIGEST into another NEW layout ---------------------------
  const pulledDigest = await temp(t, 'pulled-digest');
  await oras(env, ['cp', '--from-plain-http', '--to-oci-layout', `${ref}@${written.ociManifestDigest}`, `${pulledDigest}:by-digest`], t);
  assertRoundTrip(await readOciLayout({ input: pulledDigest, ref: 'by-digest' }), 'digest pull');
  record(t, { 'tag-pulled OCI manifest digest': byTag.ociManifestDigest, 'digest-pulled OCI manifest digest': (await ociManifestOf(pulledDigest)).descriptors[0].digest });

  // ---- local OWA import through the REAL CLI, then serve through the real gateway --
  const data = await temp(t, 'data');
  const slug = `interop-${randomUUID().slice(0, 8)}`;
  t.diagnostic(`node packages/cli/src/index.js import-oci <pulled-tag-layout> --ref v1 --site ${slug} --data <fresh data dir>`);
  const imported = await run(process.execPath, [CLI, 'import-oci', pulledTag, '--ref', 'v1', '--site', slug, '--data', data]);
  assert.equal(imported.code, 0, `import-oci exited ${imported.code}: ${tail(imported.stderr)}`);
  const reported = /Artifact (sha256:[0-9a-f]{64})/.exec(imported.stdout)?.[1];
  if (reported) assert.equal(reported, packed.artifactDigest, 'the CLI-reported artifact digest agrees');
  const metadata = new FilesystemMetadataStore(data), blobs = new FilesystemBlobStore(data);
  const siteRecord = await metadata.getSite(slug);
  assert.ok(siteRecord?.activeReleaseId, 'the import created an active release');
  const release = await metadata.getRelease(siteRecord.id, siteRecord.activeReleaseId);
  assert.equal(release.artifactDigest, packed.artifactDigest, 'imported release artifact digest === original');
  assert.deepEqual(release.manifest, packed.manifest);
  for (const file of packed.manifest.files) assert.ok(Buffer.from(await blobs.get(file.digest)).equals(Buffer.from(packed.blobs.get(file.digest))));

  const server = createContentServer({ blobs, metadata, content: { baseDomain: 'localhost', scheme: 'http' } });
  server.listen(0, '127.0.0.1'); await once(server, 'listening');
  t.after(() => new Promise(resolve => { server.closeAllConnections(); server.close(() => resolve()); }));
  const host = `${slug}.localhost:${server.address().port}`;
  for (const [path, file] of [['/', '/index.html'], ['/assets/app.js', '/assets/app.js'], ['/assets/style.css', '/assets/style.css'], ['/assets/blob.bin', '/assets/blob.bin'], ['/empty.txt', '/empty.txt']]) {
    const entry = packed.manifest.files.find(f => f.path === file);
    const res = await serve(server.address().port, host, path);
    assert.equal(res.status, 200, `GET ${path}`);
    assert.ok(res.body.equals(Buffer.from(packed.blobs.get(entry.digest))), `GET ${path} serves the exact original bytes`);
    assert.equal(res.headers.etag, `"${entry.digest}"`);
    assert.equal(res.headers['content-type'], entry.mediaType === 'application/octet-stream' ? 'application/octet-stream' : entry.mediaType, `GET ${path} carries the FULL original OWA media type`);
  }
  record(t, { 'imported release': `${release.id} ${release.artifactDigest}`, served: ['/', '/assets/app.js', '/assets/style.css', '/assets/blob.bin', '/empty.txt'] });

  // ---- negatives: transport failures are failures, and OWA's reader stays the integrity boundary --
  const neg1 = await temp(t, 'neg-tag'); await orasMustFail(env, ['cp', '--from-plain-http', '--to-oci-layout', `${ref}:not-there`, `${neg1}:x`], t);
  await assert.rejects(readOciLayout({ input: neg1, ref: 'x' }), 'a failed pull leaves nothing importable');
  const neg2 = await temp(t, 'neg-digest'); await orasMustFail(env, ['cp', '--from-plain-http', '--to-oci-layout', `${ref}@sha256:${'a'.repeat(64)}`, `${neg2}:x`], t);
  const neg3 = await temp(t, 'neg-repo'); await orasMustFail(env, ['cp', '--from-plain-http', '--to-oci-layout', `${env.registryHost}/owa-ci/never-created-${randomUUID().slice(0, 8)}:v1`, `${neg3}:x`], t);
  const missingRepo = await registryGet(`${env.registry}/v2/owa-ci/never-created-${randomUUID().slice(0, 8)}/manifests/v1`, { accept: OCI_IMAGE_MANIFEST });
  assert.equal(missingRepo.status, 404);

  // Adversarial copies of the pulled layout. ORAS writes layout blobs read-only
  // (0444) and the recursive copy preserves that mode, so on the GitHub runner a
  // plain writeFile() gets EACCES before the reader is ever exercised. The
  // deliberately corrupted file in the TEMP COPY is made owner-writable first;
  // the ORAS-pulled source layout is never touched and the reader is unchanged.
  const tampered = await temp(t, 'tampered');
  await cp(pulledTag, tampered, { recursive: true });
  const victim = packed.manifest.files.find(f => f.path === '/assets/app.js');
  const victimPath = join(tampered, 'blobs', 'sha256', victim.digest.slice(7));
  await chmod(victimPath, 0o600);
  const original = await readFile(victimPath);
  const flipped = Buffer.from(original); flipped[0] ^= 0x01; // same length, different bytes
  await writeFile(victimPath, flipped);
  await assert.rejects(readOciLayout({ input: tampered, ref: 'v1' }), error => error.code === 'OWA_CONTENT_DIGEST_MISMATCH', 'tampered pulled blob is rejected by digest');
  await rm(victimPath);
  await assert.rejects(readOciLayout({ input: tampered, ref: 'v1' }), 'deleted pulled blob is rejected');
  const truncated = await temp(t, 'truncated');
  await cp(pulledTag, truncated, { recursive: true });
  const shortVictim = packed.manifest.files.find(f => f.path === '/index.html');
  const shortVictimPath = join(truncated, 'blobs', 'sha256', shortVictim.digest.slice(7));
  await chmod(shortVictimPath, 0o600);
  await writeFile(shortVictimPath, (await readFile(shortVictimPath)).subarray(0, 5));
  await assert.rejects(readOciLayout({ input: truncated, ref: 'v1' }), error => error.code === 'OWA_CONTENT_DIGEST_MISMATCH' || error.code === 'OWA_CONTENT_SIZE_MISMATCH');

  // ---- optional tag move: `latest` is mutable transport state, digests are not ----
  const site2 = await temp(t, 'site2'); await writeFixture(site2, { version: 2 });
  const packed2 = await packDirectory(site2);
  assert.notEqual(packed2.artifactDigest, packed.artifactDigest);
  const layout2 = await temp(t, 'layout2');
  const written2 = await writeOciLayout({ manifest: packed2.manifest, blobs: packed2.blobs, output: layout2, ref: 'v2' });
  await oras(env, ['cp', '--from-oci-layout', `${layout}:v1`, `${ref}:latest`, '--to-plain-http'], t);
  assert.equal((await oras(env, ['resolve', '--plain-http', `${ref}:latest`], t)).stdout.trim(), written.ociManifestDigest, 'latest → v1 first');
  await oras(env, ['cp', '--from-oci-layout', `${layout2}:v2`, `${ref}:latest`, '--to-plain-http'], t);
  assert.equal((await oras(env, ['resolve', '--plain-http', `${ref}:latest`], t)).stdout.trim(), written2.ociManifestDigest, 'latest now → v2');
  const oldByDigest = await temp(t, 'old-by-digest');
  await oras(env, ['cp', '--from-plain-http', '--to-oci-layout', `${ref}@${written.ociManifestDigest}`, `${oldByDigest}:v1-again`], t);
  assertRoundTrip(await readOciLayout({ input: oldByDigest, ref: 'v1-again' }), 'old manifest by digest after the tag moved');
  const newLatest = await temp(t, 'new-latest');
  await oras(env, ['cp', '--from-plain-http', '--to-oci-layout', `${ref}:latest`, `${newLatest}:latest`], t);
  const latestNow = await readOciLayout({ input: newLatest, ref: 'latest' });
  assert.equal(latestNow.artifactDigest, packed2.artifactDigest); assert.equal(latestNow.ociManifestDigest, written2.ociManifestDigest);
  record(t, { 'v2 OWA artifact digest': packed2.artifactDigest, 'v2 OCI manifest digest': written2.ociManifestDigest, 'tag semantics': 'registry tag mutable; OCI manifest digest immutable; OWA artifact digest immutable; not an OWA release/activation operation' });

  // Registry still answering after everything: the transport under test stayed up.
  assert.equal((await registryGet(`${env.registry}/v2/`)).status, 200);

  if (process.env.GITHUB_ACTIONS === 'true') {
    const escape = value => String(value).replace(/%/g, '%25').replace(/\r/g, '%0D').replace(/\n/g, '%0A');
    process.stdout.write(`::notice title=oci interop::${escape(`ORAS+Zot round trip OK: OWA ${packed.artifactDigest}; OCI manifest ${written.ociManifestDigest} (registry descriptor ${descriptor.digest}; tag pull ${byTag.ociManifestDigest}); descriptors ${remote.layers.map(l => l.mediaType).join(',')}; import ${release.id}; served 5 files; negatives 3 pulls failed + 2 tamper rejections; latest moved to ${written2.ociManifestDigest}`)}\n`);
  }
});
