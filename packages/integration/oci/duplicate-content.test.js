import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash, randomUUID } from 'node:crypto';
import { once } from 'node:events';
import { chmod, cp, mkdir, readFile, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { canonicalJson, OWA_MEDIA_TYPE, sha256 } from '../../spec/src/index.js';
import { packDirectory } from '../../core/src/index.js';
import { OCI_IMAGE_MANIFEST, PATH_ANNOTATION, ociLayerMediaType, readOciLayout, writeOciLayout } from '../../transport-oci/src/index.js';
import { FilesystemBlobStore, FilesystemMetadataStore } from '../../storage-filesystem/src/index.js';
import { createContentServer } from '../../server/src/index.js';
import { ociEnvironment } from './environment.js';
import { CLI, notice, ociManifestOf, oras, record, registryGet, run, serve, tail, temp } from './helpers.js';

// Live duplicate-content proof (issue #9), alongside — not replacing — the #23
// suite in registry.test.js:
//
//   several OWA paths with IDENTICAL bytes (one content digest, two media types)
//   -> packDirectory -> writeOciLayout (one descriptor PER FILE ENTRY, one blob)
//   -> REAL ORAS -> REAL Zot -> REAL ORAS (by tag, by digest) -> readOciLayout
//   -> CLI import-oci -> the content server serves every duplicate path with its
//      OWN file entry's media type.
//
// The registry must preserve the repeated descriptors with their distinct
// dev.openwebartifact.path annotations while addressing the shared blob once by
// digest (content-addressed identity, not a claim about Zot's storage layout).

const environment = await ociEnvironment();
const SHARED = 'shared bytes for issue #9: identical content under three paths\n';

/** Copy a pulled layout, then rewrite ITS OCI manifest through `mutate` (re-hashed, index repointed) so only the mutated aspect can fail. */
async function mutatedCopy(t, source, name, mutate) {
  const copy = await temp(t, name);
  await cp(source, copy, { recursive: true });
  // ORAS writes read-only entries; the adversarial TEMP COPY is made writable.
  await chmod(join(copy, 'blobs', 'sha256'), 0o700);
  await chmod(join(copy, 'index.json'), 0o600);
  const index = JSON.parse(await readFile(join(copy, 'index.json'), 'utf8'));
  const original = index.manifests[0];
  const oci = JSON.parse(await readFile(join(copy, 'blobs', 'sha256', original.digest.slice(7)), 'utf8'));
  mutate(oci);
  const bytes = Buffer.from(canonicalJson(oci), 'utf8'), digest = sha256(bytes);
  await writeFile(join(copy, 'blobs', 'sha256', digest.slice(7)), bytes);
  index.manifests[0] = { ...original, digest, size: bytes.byteLength };
  await writeFile(join(copy, 'index.json'), JSON.stringify(index));
  return copy;
}

test('ORAS v1.3.4 + Zot: duplicate-content file entries (one descriptor per path, one shared blob) survive push, pull, import and serving', { skip: environment.skip, timeout: 300_000 }, async t => {
  if (environment.fail) assert.fail(environment.fail);
  const env = environment;
  t.diagnostic(`registry ${env.registry} (loopback, plain HTTP); oras ${env.oras}; required=${env.required}; node ${process.version}`);
  assert.equal((await registryGet(`${env.registry}/v2/`)).status, 200, 'GET /v2/ must succeed');

  // ---- fixture: three paths with identical bytes (.js and .txt), plus one unique file
  const site = await temp(t, 'dup-site');
  await mkdir(join(site, 'copy'), { recursive: true });
  await writeFile(join(site, 'index.html'), '<!doctype html><html><head><meta charset="utf-8"><title>OWA duplicate content</title></head><body><h1>issue #9</h1></body></html>');
  for (const path of ['shared.js', 'shared.txt', join('copy', 'shared.txt')]) await writeFile(join(site, path), SHARED);
  const packed = await packDirectory(site);
  const sharedDigest = sha256(Buffer.from(SHARED, 'utf8'));
  const group = packed.manifest.files.filter(f => f.digest === sharedDigest);
  assert.deepEqual(group.map(f => f.path), ['/copy/shared.txt', '/shared.js', '/shared.txt'], 'three file entries share one digest');
  assert.ok(group.length >= 2);
  assert.equal(packed.manifest.files.length, 4); assert.equal(packed.blobs.size, 2, 'the packer deduplicates the shared bytes');
  const types = Object.fromEntries(packed.manifest.files.map(f => [f.path, f.mediaType]));
  assert.equal(types['/shared.js'], 'text/javascript; charset=utf-8');
  assert.equal(types['/shared.txt'], 'text/plain; charset=utf-8'); assert.equal(types['/copy/shared.txt'], 'text/plain; charset=utf-8');
  const canonical = canonicalJson(packed.manifest);
  record(t, { 'OWA artifact digest': packed.artifactDigest, 'shared digest': sharedDigest, 'duplicate paths': group.map(f => `${f.path} ${f.mediaType}`) });

  // ---- export: one descriptor per file entry; the shared blob is written once ----
  const layout = await temp(t, 'dup-layout');
  const written = await writeOciLayout({ manifest: packed.manifest, blobs: packed.blobs, output: layout, ref: 'v1' });
  assert.equal(written.artifactDigest, packed.artifactDigest);
  const localManifestBytes = await readFile(join(layout, 'blobs', 'sha256', written.ociManifestDigest.slice(7)));
  const localManifest = JSON.parse(localManifestBytes.toString('utf8'));
  const assertDescriptors = (layers, label) => {
    assert.equal(layers.length, packed.manifest.files.length, `${label}: one descriptor per file entry`);
    const repeated = layers.filter(l => l.digest === sharedDigest);
    assert.equal(repeated.length, group.length, `${label}: descriptor count === duplicate file-entry count`);
    assert.deepEqual(new Set(repeated.map(l => l.annotations[PATH_ANNOTATION])), new Set(group.map(f => f.path)), `${label}: distinct path annotations`);
    for (const file of packed.manifest.files) {
      const layer = layers.find(l => l.annotations[PATH_ANNOTATION] === file.path);
      assert.ok(layer, `${label}: descriptor for ${file.path}`);
      assert.equal(layer.digest, file.digest); assert.equal(layer.size, file.size);
      assert.equal(layer.mediaType, ociLayerMediaType(file.mediaType), `${label}: per-file mapped media type for ${file.path}`);
      assert.equal(layer.annotations['org.opencontainers.image.title'], file.path.slice(1));
    }
    assert.equal(layers.find(l => l.annotations[PATH_ANNOTATION] === '/shared.js').mediaType, 'text/javascript');
    assert.equal(layers.find(l => l.annotations[PATH_ANNOTATION] === '/shared.txt').mediaType, 'text/plain');
  };
  assertDescriptors(localManifest.layers, 'writeOciLayout');
  const control = await readOciLayout({ input: layout, ref: 'v1' });
  assert.deepEqual(control.manifest, packed.manifest); assert.equal(control.blobs.size, 2);
  record(t, { 'OCI manifest digest (writeOciLayout)': written.ociManifestDigest, 'OCI layer descriptors': localManifest.layers.map(l => `${l.annotations[PATH_ANNOTATION]} ${l.mediaType} ${l.digest.slice(0, 19)}…`) });

  // ---- push through the REAL ORAS CLI to the REAL registry -------------------------
  const repo = `owa-ci/dup-${randomUUID()}`;
  const ref = `${env.registryHost}/${repo}`;
  const push = await oras(env, ['cp', '--from-oci-layout', `${layout}:v1`, `${ref}:v1`, '--to-plain-http'], t);
  assert.match(push.stdout + push.stderr, new RegExp(written.ociManifestDigest.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')), 'oras reports the pushed OCI manifest digest');
  const descriptor = JSON.parse((await oras(env, ['manifest', 'fetch', '--descriptor', '--plain-http', `${ref}:v1`], t)).stdout);
  assert.equal(descriptor.digest, written.ociManifestDigest, 'registry descriptor digest === writeOciLayout OCI manifest digest');
  assert.equal((await oras(env, ['resolve', '--plain-http', `${ref}:v1`], t)).stdout.trim(), written.ociManifestDigest);

  // ---- the registry preserved the REPEATED descriptors and addresses the blob once by digest
  const stored = await registryGet(`${env.registry}/v2/${repo}/manifests/v1`, { accept: OCI_IMAGE_MANIFEST });
  assert.equal(stored.status, 200); assert.equal(stored.headers['content-type'], OCI_IMAGE_MANIFEST);
  assert.equal(stored.headers['docker-content-digest'], written.ociManifestDigest);
  assert.equal(`sha256:${createHash('sha256').update(stored.body).digest('hex')}`, written.ociManifestDigest);
  assert.ok(stored.body.equals(localManifestBytes), 'Zot stored the exact OCI manifest bytes, repeated descriptors included');
  const remote = JSON.parse(stored.body.toString('utf8'));
  assert.equal(remote.artifactType, OWA_MEDIA_TYPE); assert.equal(remote.config.digest, packed.artifactDigest);
  assertDescriptors(remote.layers, 'registry-stored manifest');
  const head = await registryGet(`${env.registry}/v2/${repo}/blobs/${sharedDigest}`, { method: 'HEAD' });
  assert.equal(head.status, 200, 'the shared blob is addressable once by its digest');
  assert.equal(Number(head.headers['content-length']), Buffer.byteLength(SHARED));
  const config = await registryGet(`${env.registry}/v2/${repo}/blobs/${packed.artifactDigest}`);
  assert.equal(config.body.toString('utf8'), canonical, 'the registry-held config is the canonical OWA manifest with both full media types');
  record(t, { 'registry descriptor digest': descriptor.digest, 'Docker-Content-Digest': stored.headers['docker-content-digest'], 'registry repeated descriptors': remote.layers.filter(l => l.digest === sharedDigest).map(l => `${l.annotations[PATH_ANNOTATION]} ${l.mediaType}`) });

  // ---- pull by TAG and by immutable DIGEST into fresh layouts; read both ------------
  const pulledTag = await temp(t, 'dup-pulled-tag');
  await oras(env, ['cp', '--from-plain-http', '--to-oci-layout', `${ref}:v1`, `${pulledTag}:v1`], t);
  const pulledDigest = await temp(t, 'dup-pulled-digest');
  await oras(env, ['cp', '--from-plain-http', '--to-oci-layout', `${ref}@${written.ociManifestDigest}`, `${pulledDigest}:by-digest`], t);
  const assertRoundTrip = (imported, label) => {
    assert.equal(imported.artifactDigest, packed.artifactDigest, `${label}: OWA artifact digest identical`);
    assert.equal(canonicalJson(imported.manifest), canonical, `${label}: canonical manifest bytes identical`);
    assert.deepEqual(imported.manifest, packed.manifest, `${label}: every original file entry present, duplicate paths preserved`);
    assert.deepEqual(imported.manifest.files.map(f => f.mediaType), packed.manifest.files.map(f => f.mediaType), `${label}: full media types preserved`);
    assert.equal(imported.ociManifestDigest, written.ociManifestDigest, `${label}: OCI manifest digest preserved`);
    assert.equal(imported.blobs.size, 2, `${label}: returned blobs Map has ONE entry for the shared digest`);
    assert.equal(Buffer.from(imported.blobs.get(sharedDigest)).toString('utf8'), SHARED, `${label}: shared bytes exact`);
    assertDescriptors(imported.ociManifest.layers, label);
  };
  const byTag = await readOciLayout({ input: pulledTag, ref: 'v1' });
  assertRoundTrip(byTag, 'tag pull');
  const byDigest = await readOciLayout({ input: pulledDigest, ref: 'by-digest' });
  assertRoundTrip(byDigest, 'digest pull');
  record(t, { 'tag-pulled OCI manifest digest': byTag.ociManifestDigest, 'digest-pulled OCI manifest digest': byDigest.ociManifestDigest, 'imported blobs (unique digests)': byTag.blobs.size });

  // ---- REAL CLI import, then the real content server serves EVERY duplicate path ----
  const data = await temp(t, 'dup-data');
  const slug = `dup-${randomUUID().slice(0, 8)}`;
  t.diagnostic(`node packages/cli/src/index.js import-oci <pulled-tag-layout> --ref v1 --site ${slug} --data <fresh data dir>`);
  const imported = await run(process.execPath, [CLI, 'import-oci', pulledTag, '--ref', 'v1', '--site', slug, '--data', data]);
  assert.equal(imported.code, 0, `import-oci exited ${imported.code}: ${tail(imported.stderr)}`);
  assert.match(imported.stdout, /Stored 2 blob\(s\), reused 0/, 'two distinct blobs stored for four file entries');
  const metadata = new FilesystemMetadataStore(data), blobs = new FilesystemBlobStore(data);
  const siteRecord = await metadata.getSite(slug);
  const release = await metadata.getRelease(siteRecord.id, siteRecord.activeReleaseId);
  assert.equal(release.artifactDigest, packed.artifactDigest); assert.deepEqual(release.manifest, packed.manifest);
  const server = createContentServer({ blobs, metadata, content: { baseDomain: 'localhost', scheme: 'http' } });
  server.listen(0, '127.0.0.1'); await once(server, 'listening');
  t.after(() => new Promise(resolve => { server.closeAllConnections(); server.close(() => resolve()); }));
  const host = `${slug}.localhost:${server.address().port}`;
  const served = {};
  for (const [path, contentType] of [['/shared.js', 'text/javascript; charset=utf-8'], ['/shared.txt', 'text/plain; charset=utf-8'], ['/copy/shared.txt', 'text/plain; charset=utf-8']]) {
    const res = await serve(server.address().port, host, path);
    assert.equal(res.status, 200, `GET ${path}`);
    assert.equal(res.body.toString('utf8'), SHARED, `GET ${path} serves the same original bytes`);
    assert.equal(res.headers['content-type'], contentType, `GET ${path} uses ITS OWN file entry's media type`);
    assert.equal(res.headers.etag, `"${sharedDigest}"`, `GET ${path} ETag is the shared content digest`);
    served[path] = `${res.status} ${res.headers['content-type']}`;
  }
  assert.notEqual(served['/shared.js'], served['/shared.txt'], 'same bytes, different Content-Type per path');
  record(t, { 'imported release': `${release.id} ${release.artifactDigest}`, served });

  // ---- malformed pulled layouts (local mutations of COPIES of the real pull) --------
  const untouched = await temp(t, 'dup-untouched'); await cp(pulledTag, untouched, { recursive: true });
  assertRoundTrip(await readOciLayout({ input: untouched, ref: 'v1' }), 'untouched copy (control)');
  const pathLost = await mutatedCopy(t, pulledTag, 'dup-path-lost', oci => { delete oci.layers.find(l => l.annotations[PATH_ANNOTATION] === '/shared.txt').annotations[PATH_ANNOTATION]; });
  await assert.rejects(readOciLayout({ input: pathLost, ref: 'v1' }), /OCI layer for \/shared\.txt cannot be selected/, 'a repeated descriptor without its path annotation is rejected, never guessed');
  const samePath = await mutatedCopy(t, pulledTag, 'dup-same-path', oci => { oci.layers.find(l => l.annotations[PATH_ANNOTATION] === '/copy/shared.txt').annotations[PATH_ANNOTATION] = '/shared.txt'; });
  await assert.rejects(readOciLayout({ input: samePath, ref: 'v1' }), /Ambiguous OCI layout: multiple layers claim dev\.openwebartifact\.path \/shared\.txt/, 'two descriptors claiming one path are rejected');
  const swapped = await mutatedCopy(t, pulledTag, 'dup-swapped', oci => {
    const js = oci.layers.find(l => l.annotations[PATH_ANNOTATION] === '/shared.js'), txt = oci.layers.find(l => l.annotations[PATH_ANNOTATION] === '/shared.txt');
    js.annotations[PATH_ANNOTATION] = '/shared.txt'; txt.annotations[PATH_ANNOTATION] = '/shared.js';
  });
  await assert.rejects(readOciLayout({ input: swapped, ref: 'v1' }), /OCI layer media type mismatch for \/shared\.js/, 'swapped path annotations no longer match each entry\'s media type');

  assert.equal((await registryGet(`${env.registry}/v2/`)).status, 200, 'registry still answering');
  notice('oci duplicate-content', `ORAS+Zot duplicate-content round trip OK: OWA ${packed.artifactDigest}; OCI manifest ${written.ociManifestDigest} (registry descriptor ${descriptor.digest}; tag pull ${byTag.ociManifestDigest}; digest pull ${byDigest.ociManifestDigest}); shared digest ${sharedDigest} referenced by ${group.length} descriptors ${group.map(f => f.path).join(',')} with descriptor media types ${remote.layers.filter(l => l.digest === sharedDigest).map(l => l.mediaType).join(',')}; imported blobs ${byTag.blobs.size}; import ${release.id}; served ${Object.entries(served).map(([p, v]) => `${p} -> ${v}`).join('; ')}; 3 malformed pulled-layout copies rejected`);
});
