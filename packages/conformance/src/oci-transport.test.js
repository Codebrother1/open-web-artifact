import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdir, mkdtemp, readdir, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { artifactDigest, canonicalJson, OWA_MEDIA_TYPE, sha256, validateManifest } from '../../spec/src/index.js';
import { packDirectory } from '../../core/src/index.js';
import { OCI_FALLBACK_MEDIA_TYPE, OCI_IMAGE_INDEX, OCI_IMAGE_MANIFEST, PATH_ANNOTATION, ociLayerMediaType, readOciLayout, writeOciLayout } from '../../transport-oci/src/index.js';

// OCI transport representation (issue #23): an OWA `file.mediaType` is an arbitrary
// nonempty string and may carry parameters; an OCI layer DESCRIPTOR mediaType must
// be a bare RFC 6838 type/subtype (the image-spec schema pattern registries such
// as Zot enforce). The transport maps one to the other; the canonical OWA manifest
// in the OCI config blob stays the only source of the full original value.

const b = text => Buffer.from(text, 'utf8');
function manifestFor(files) {
  const blobs = new Map();
  const manifest = {
    specVersion: 'owa.dev/v1', artifactType: OWA_MEDIA_TYPE, entrypoint: files[0].path,
    files: files.map(file => { const bytes = file.bytes ?? b(file.text); const digest = sha256(bytes); blobs.set(digest, bytes); return { path: file.path, digest, size: bytes.length, mediaType: file.mediaType }; }),
    access: { visibility: 'public' }, lifecycle: { expiresAt: null }
  };
  validateManifest(manifest);
  return { manifest, blobs };
}
async function tmp(t, prefix) { const dir = await mkdtemp(join(tmpdir(), prefix)); t.after(() => rm(dir, { recursive: true, force: true })); return dir; }
async function ociManifestOf(root) {
  const index = JSON.parse(await readFile(join(root, 'index.json'), 'utf8'));
  const digest = index.manifests[0].digest;
  return { descriptor: index.manifests[0], manifest: JSON.parse(await readFile(join(root, 'blobs', 'sha256', digest.slice(7)), 'utf8')), digest };
}

test('ociLayerMediaType maps OWA media types to OCI descriptor media types deterministically', () => {
  // 1–5: parameterized web types lose their parameters, nothing else.
  assert.equal(ociLayerMediaType('text/html; charset=utf-8'), 'text/html');
  assert.equal(ociLayerMediaType('text/javascript; charset=utf-8'), 'text/javascript');
  assert.equal(ociLayerMediaType('text/css; charset=utf-8'), 'text/css');
  assert.equal(ociLayerMediaType('application/json; charset=utf-8'), 'application/json');
  assert.equal(ociLayerMediaType('text/plain; charset=utf-8'), 'text/plain');
  // Only the FIRST semicolon splits; SP/HTAB around the candidate are trimmed; nothing is lowercased or repaired.
  assert.equal(ociLayerMediaType('text/plain ; note="a;b"; charset=utf-8'), 'text/plain');
  assert.equal(ociLayerMediaType(' \tText/HTML\t ;charset=x'), 'Text/HTML');
  // 6–7: already-valid values are preserved verbatim, including vendor trees and structured suffixes.
  assert.equal(ociLayerMediaType('image/png'), 'image/png');
  assert.equal(ociLayerMediaType('application/vnd.example.foo+json'), 'application/vnd.example.foo+json');
  assert.equal(ociLayerMediaType('application/vnd.openwebartifact.site.v1+json'), 'application/vnd.openwebartifact.site.v1+json');
  assert.equal(ociLayerMediaType('font/woff2'), 'font/woff2');
  // 8–10: structurally valid OWA strings that are not OCI descriptor media types fall back.
  assert.equal(ociLayerMediaType('not actually mime'), OCI_FALLBACK_MEDIA_TYPE);
  assert.equal(ociLayerMediaType('   '), OCI_FALLBACK_MEDIA_TYPE);
  assert.equal(ociLayerMediaType('; charset=utf-8'), OCI_FALLBACK_MEDIA_TYPE);
  assert.equal(ociLayerMediaType('text/'), OCI_FALLBACK_MEDIA_TYPE);
  assert.equal(ociLayerMediaType('/html'), OCI_FALLBACK_MEDIA_TYPE);
  assert.equal(ociLayerMediaType('text/html/extra'), OCI_FALLBACK_MEDIA_TYPE);
  assert.equal(ociLayerMediaType('text/ht ml'), OCI_FALLBACK_MEDIA_TYPE);
  assert.equal(ociLayerMediaType('text/htmlé'), OCI_FALLBACK_MEDIA_TYPE);
  assert.equal(ociLayerMediaType(`${'a'.repeat(128)}/plain`), OCI_FALLBACK_MEDIA_TYPE, 'type longer than 127 characters');
  assert.equal(ociLayerMediaType(`text/${'a'.repeat(128)}`), OCI_FALLBACK_MEDIA_TYPE, 'subtype longer than 127 characters');
  assert.equal(ociLayerMediaType(`${'a'.repeat(127)}/${'b'.repeat(127)}`), `${'a'.repeat(127)}/${'b'.repeat(127)}`, 'the 127-character maximum is accepted');
  assert.equal(ociLayerMediaType(''), OCI_FALLBACK_MEDIA_TYPE);
  assert.equal(ociLayerMediaType(undefined), OCI_FALLBACK_MEDIA_TYPE);
  // The fallback itself is a valid descriptor media type, so mapping is idempotent.
  assert.equal(ociLayerMediaType(OCI_FALLBACK_MEDIA_TYPE), OCI_FALLBACK_MEDIA_TYPE);
});

test('writeOciLayout emits mapped descriptor media types while the config keeps every full OWA value; identity is unchanged across the round trip', async t => {
  const { manifest, blobs } = manifestFor([
    { path: '/index.html', text: '<!doctype html><h1>oci</h1>', mediaType: 'text/html; charset=utf-8' },
    { path: '/assets/app.js', text: 'console.log(1)', mediaType: 'text/javascript; charset=utf-8' },
    { path: '/assets/style.css', text: 'body{}', mediaType: 'text/css; charset=utf-8' },
    { path: '/data.json', text: '{"a":1}', mediaType: 'application/json; charset=utf-8' },
    { path: '/notes.txt', text: 'notes', mediaType: 'text/plain; charset=utf-8' },
    { path: '/img.png', bytes: Buffer.from([0x89, 0x50, 0x4e, 0x47]), mediaType: 'image/png' },
    { path: '/vendor.bin', bytes: Buffer.from([1, 2, 3]), mediaType: 'application/vnd.example.foo+json' },
    { path: '/odd.dat', bytes: Buffer.from([4, 5]), mediaType: 'not actually mime' },
    { path: '/blank.dat', bytes: Buffer.from([6]), mediaType: '   ' }
  ]);
  assert.equal(new Set(manifest.files.map(f => f.digest)).size, manifest.files.length, 'this fixture has unique digests; duplicate content is covered by the issue #9 tests below');
  const layout = await tmp(t, 'owa-oci-map-');
  const written = await writeOciLayout({ manifest, blobs, output: layout, ref: 'v1' });
  assert.equal(written.artifactDigest, artifactDigest(manifest));

  const { manifest: oci, descriptor } = await ociManifestOf(layout);
  assert.equal(oci.mediaType, OCI_IMAGE_MANIFEST); assert.equal(oci.artifactType, OWA_MEDIA_TYPE);
  assert.equal(oci.config.mediaType, OWA_MEDIA_TYPE); assert.equal(oci.config.digest, written.artifactDigest);
  assert.equal(descriptor.digest, written.ociManifestDigest);
  const descriptorTypes = Object.fromEntries(oci.layers.map(l => [l.annotations['dev.openwebartifact.path'], l.mediaType]));
  assert.deepEqual(descriptorTypes, {
    '/index.html': 'text/html', '/assets/app.js': 'text/javascript', '/assets/style.css': 'text/css', '/data.json': 'application/json',
    '/notes.txt': 'text/plain', '/img.png': 'image/png', '/vendor.bin': 'application/vnd.example.foo+json',
    '/odd.dat': OCI_FALLBACK_MEDIA_TYPE, '/blank.dat': OCI_FALLBACK_MEDIA_TYPE
  });
  // Every descriptor media type satisfies the image-spec grammar; no descriptor carries a parameter.
  for (const layer of oci.layers) assert.match(layer.mediaType, /^[A-Za-z0-9][A-Za-z0-9!#$&^_.+-]{0,126}\/[A-Za-z0-9][A-Za-z0-9!#$&^_.+-]{0,126}$/);
  // Digest, size and path annotations are untouched by the mapping.
  for (const file of manifest.files) {
    const layer = oci.layers.find(l => l.digest === file.digest);
    assert.equal(layer.size, file.size); assert.equal(layer.annotations['dev.openwebartifact.path'], file.path);
    assert.equal(layer.annotations['org.opencontainers.image.title'], file.path.slice(1));
  }
  // 11: the config blob IS the canonical OWA manifest, full media types included.
  const configBytes = await readFile(join(layout, 'blobs', 'sha256', oci.config.digest.slice(7)));
  assert.equal(configBytes.toString('utf8'), canonicalJson(manifest));
  assert.deepEqual(JSON.parse(configBytes.toString('utf8')).files.map(f => f.mediaType), manifest.files.map(f => f.mediaType));
  assert.equal(`sha256:${createHash('sha256').update(configBytes).digest('hex')}`, written.artifactDigest);

  // 12–13, 15: the reader accepts the mapped descriptors and returns the FULL original media types from the config.
  const imported = await readOciLayout({ input: layout, ref: 'v1' });
  assert.equal(imported.artifactDigest, written.artifactDigest);
  assert.equal(canonicalJson(imported.manifest), canonicalJson(manifest));
  assert.deepEqual(imported.manifest, manifest);
  assert.deepEqual(imported.manifest.files.map(f => f.mediaType), manifest.files.map(f => f.mediaType));
  assert.equal(imported.manifest.files.find(f => f.path === '/odd.dat').mediaType, 'not actually mime', 'fallback descriptor did not alter the OWA value');
  assert.equal(imported.manifest.files.find(f => f.path === '/blank.dat').mediaType, '   ');
  assert.equal(imported.ociManifestDigest, written.ociManifestDigest);
  for (const [digest, bytes] of blobs) assert.ok(Buffer.from(imported.blobs.get(digest)).equals(bytes));
});

test('the OCI manifest digest changes with the mapping while the OWA artifact digest does not', async t => {
  // Two manifests that differ only in a parameter are DIFFERENT OWA artifacts
  // (different canonical bytes) but produce the same descriptor media type.
  const a = manifestFor([{ path: '/index.html', text: '<h1>same</h1>', mediaType: 'text/html; charset=utf-8' }]);
  const c = manifestFor([{ path: '/index.html', text: '<h1>same</h1>', mediaType: 'text/html' }]);
  assert.notEqual(artifactDigest(a.manifest), artifactDigest(c.manifest));
  const la = await tmp(t, 'owa-oci-a-'), lc = await tmp(t, 'owa-oci-c-');
  const wa = await writeOciLayout({ manifest: a.manifest, blobs: a.blobs, output: la, ref: 'v1' });
  const wc = await writeOciLayout({ manifest: c.manifest, blobs: c.blobs, output: lc, ref: 'v1' });
  assert.equal((await ociManifestOf(la)).manifest.layers[0].mediaType, 'text/html');
  assert.equal((await ociManifestOf(lc)).manifest.layers[0].mediaType, 'text/html');
  assert.notEqual(wa.ociManifestDigest, wc.ociManifestDigest, 'different configs → different OCI manifests');
  assert.equal(wa.artifactDigest, artifactDigest(a.manifest)); assert.equal(wc.artifactDigest, artifactDigest(c.manifest));
});

test('readOciLayout rejects a descriptor whose media type is not the mapped value (14; malformed representation)', async t => {
  const { manifest, blobs } = manifestFor([
    { path: '/index.html', text: '<h1>x</h1>', mediaType: 'text/html; charset=utf-8' },
    { path: '/odd.dat', bytes: Buffer.from([9]), mediaType: 'not actually mime' }
  ]);
  const layout = await tmp(t, 'owa-oci-bad-');
  const written = await writeOciLayout({ manifest, blobs, output: layout, ref: 'v1' });
  // Rewrite the OCI manifest with a different descriptor media type, re-hash it and
  // point the index at the new blob, so ONLY the media-type check can fail.
  async function withLayerType(path, mediaType) {
    const { manifest: oci } = await ociManifestOf(layout);
    const tampered = structuredClone(oci);
    tampered.layers.find(l => l.annotations['dev.openwebartifact.path'] === path).mediaType = mediaType;
    const bytes = Buffer.from(canonicalJson(tampered), 'utf8'), digest = sha256(bytes);
    await writeFile(join(layout, 'blobs', 'sha256', digest.slice(7)), bytes);
    const index = JSON.parse(await readFile(join(layout, 'index.json'), 'utf8'));
    index.manifests = [{ ...index.manifests[0], digest, size: bytes.length }];
    await writeFile(join(layout, 'index.json'), JSON.stringify(index));
    return digest;
  }
  // The maintainer's malformed-representation case: config says text/html; charset=utf-8,
  // descriptor says application/octet-stream — rejected, because text/html is representable.
  await withLayerType('/index.html', OCI_FALLBACK_MEDIA_TYPE);
  await assert.rejects(readOciLayout({ input: layout, ref: 'v1' }), /OCI layer media type mismatch for \/index\.html/);
  // The pre-fix (non-conformant) representation with the parameter still present is rejected too.
  await withLayerType('/index.html', 'text/html; charset=utf-8');
  await assert.rejects(readOciLayout({ input: layout, ref: 'v1' }), /OCI layer media type mismatch for \/index\.html/);
  // A fallback file whose descriptor claims a concrete type is rejected as well.
  await withLayerType('/index.html', 'text/html');
  await withLayerType('/odd.dat', 'text/plain');
  await assert.rejects(readOciLayout({ input: layout, ref: 'v1' }), /OCI layer media type mismatch for \/odd\.dat/);
  // Restoring the exact mapped values restores acceptance and the original OCI manifest digest.
  const restored = await withLayerType('/odd.dat', OCI_FALLBACK_MEDIA_TYPE);
  assert.equal(restored, written.ociManifestDigest);
  const imported = await readOciLayout({ input: layout, ref: 'v1' });
  assert.equal(imported.artifactDigest, written.artifactDigest);
  assert.equal(imported.manifest.files[0].mediaType, 'text/html; charset=utf-8');
});

test('existing reader checks are preserved: wrong digest, wrong size, missing layer and wrong path still fail', async t => {
  const { manifest, blobs } = manifestFor([{ path: '/index.html', text: '<h1>x</h1>', mediaType: 'text/html; charset=utf-8' }]);
  const layout = await tmp(t, 'owa-oci-keep-');
  await writeOciLayout({ manifest, blobs, output: layout, ref: 'v1' });
  const file = manifest.files[0];
  await writeFile(join(layout, 'blobs', 'sha256', file.digest.slice(7)), b('<h1>X</h1>')); // same length, wrong bytes
  await assert.rejects(readOciLayout({ input: layout, ref: 'v1' }), error => error.code === 'OWA_CONTENT_DIGEST_MISMATCH');
  await rm(join(layout, 'blobs', 'sha256', file.digest.slice(7)));
  await assert.rejects(readOciLayout({ input: layout, ref: 'v1' }), error => error.code === 'ENOENT');
});

// ---------------------------------------------------------------------------
// Issue #9 — duplicate-content path semantics. One OCI layer descriptor per OWA
// FILE ENTRY (identified by dev.openwebartifact.path); several descriptors may
// reference the SAME content-addressed blob digest; blob bytes are stored and
// returned once. The reader selects descriptors by path, falls back to a digest
// match only for an unambiguous annotation-less legacy layout, and never guesses.
// ---------------------------------------------------------------------------

const layerFor = (oci, path) => oci.layers.find(l => l.annotations?.[PATH_ANNOTATION] === path);
/** Rewrite a layout's OCI manifest through `mutate` (applied to a clone of `base`, default: the current manifest), re-hash it and repoint index.json, so ONLY the mutated aspect can fail. */
async function rewriteOciManifest(layout, mutate, base) {
  const oci = base ?? (await ociManifestOf(layout)).manifest;
  const changed = structuredClone(oci);
  mutate(changed);
  const bytes = Buffer.from(canonicalJson(changed), 'utf8'), digest = sha256(bytes);
  await writeFile(join(layout, 'blobs', 'sha256', digest.slice(7)), bytes);
  const index = JSON.parse(await readFile(join(layout, 'index.json'), 'utf8'));
  index.manifests = [{ ...index.manifests[0], digest, size: bytes.length }];
  await writeFile(join(layout, 'index.json'), JSON.stringify(index));
  return digest;
}
/** Hand-author a complete OCI layout from an OWA manifest, explicit layer descriptors and blob bytes (no writeOciLayout involved). */
async function authorLayout(root, { manifest, layers, blobs, ref = 'v1' }) {
  await mkdir(join(root, 'blobs', 'sha256'), { recursive: true });
  await writeFile(join(root, 'oci-layout'), JSON.stringify({ imageLayoutVersion: '1.0.0' }));
  const config = Buffer.from(canonicalJson(manifest), 'utf8'), configDigest = sha256(config);
  await writeFile(join(root, 'blobs', 'sha256', configDigest.slice(7)), config);
  for (const [digest, bytes] of blobs) await writeFile(join(root, 'blobs', 'sha256', digest.slice(7)), bytes);
  const oci = { schemaVersion: 2, mediaType: OCI_IMAGE_MANIFEST, artifactType: OWA_MEDIA_TYPE, config: { mediaType: OWA_MEDIA_TYPE, digest: configDigest, size: config.length }, layers, annotations: { 'dev.openwebartifact.artifact.digest': configDigest } };
  const bytes = Buffer.from(canonicalJson(oci), 'utf8'), digest = sha256(bytes);
  await writeFile(join(root, 'blobs', 'sha256', digest.slice(7)), bytes);
  await writeFile(join(root, 'index.json'), JSON.stringify({ schemaVersion: 2, mediaType: OCI_IMAGE_INDEX, manifests: [{ mediaType: OCI_IMAGE_MANIFEST, digest, size: bytes.length, annotations: { 'org.opencontainers.image.ref.name': ref } }] }));
  return digest;
}
function assertRoundTrip(imported, { manifest, blobs }, written) {
  assert.deepEqual(imported.manifest, manifest, 'structurally identical OWA manifest (file order = config order)');
  assert.equal(imported.artifactDigest, artifactDigest(manifest));
  assert.equal(canonicalJson(imported.manifest), canonicalJson(manifest), 'identical canonical bytes');
  if (written) { assert.equal(imported.artifactDigest, written.artifactDigest); assert.equal(imported.ociManifestDigest, written.ociManifestDigest); }
  assert.equal(imported.blobs.size, blobs.size, 'one returned blob per distinct digest');
  for (const [digest, bytes] of blobs) assert.ok(Buffer.from(imported.blobs.get(digest)).equals(bytes), `bytes of ${digest}`);
  assert.deepEqual(imported.manifest.files.map(f => f.mediaType), manifest.files.map(f => f.mediaType), 'full OWA media types come from the config');
}
const shared = b('shared bytes: identical content under several paths\n');

test('#9: writeOciLayout emits ONE layer descriptor per file entry even when digests repeat, and stores the shared blob once', async t => {
  const fixture = manifestFor([
    { path: '/index.html', text: '<h1>dup</h1>', mediaType: 'text/html; charset=utf-8' },
    { path: '/a.txt', bytes: shared, mediaType: 'text/plain; charset=utf-8' },
    { path: '/b.txt', bytes: shared, mediaType: 'text/plain; charset=utf-8' }
  ]);
  const { manifest, blobs } = fixture;
  assert.equal(manifest.files.length, 3); assert.equal(blobs.size, 2, 'the fixture itself deduplicates by digest');
  const layout = await tmp(t, 'owa-oci-dup-write-');
  const written = await writeOciLayout({ manifest, blobs, output: layout, ref: 'v1' });
  const { manifest: oci } = await ociManifestOf(layout);
  assert.equal(oci.layers.length, 3, 'one descriptor per file entry, not per digest');
  const [a, bLayer] = [layerFor(oci, '/a.txt'), layerFor(oci, '/b.txt')];
  assert.ok(a && bLayer); assert.equal(a.digest, bLayer.digest); assert.equal(a.digest, sha256(shared));
  assert.equal(a.size, shared.length); assert.equal(bLayer.size, shared.length);
  assert.equal(a.annotations['org.opencontainers.image.title'], 'a.txt'); assert.equal(bLayer.annotations['org.opencontainers.image.title'], 'b.txt');
  assert.deepEqual(oci.layers.map(l => l.annotations[PATH_ANNOTATION]), manifest.files.map(f => f.path), 'writer keeps manifest.files order');
  // Physical blobs: config + OCI manifest + exactly one blob per DISTINCT content digest.
  const stored = (await readdir(join(layout, 'blobs', 'sha256'))).sort();
  assert.deepEqual(stored, [written.artifactDigest, written.ociManifestDigest, ...blobs.keys()].map(d => d.slice(7)).sort());
  assert.equal(stored.length, 4);
});

test('#9: two paths with identical bytes and the same media type round-trip through OCI', async t => {
  const fixture = manifestFor([
    { path: '/a.txt', bytes: shared, mediaType: 'text/plain; charset=utf-8' },
    { path: '/b.txt', bytes: shared, mediaType: 'text/plain; charset=utf-8' }
  ]);
  const layout = await tmp(t, 'owa-oci-dup-same-');
  const written = await writeOciLayout({ ...fixture, output: layout, ref: 'v1' });
  const imported = await readOciLayout({ input: layout, ref: 'v1' });
  assertRoundTrip(imported, fixture, written);
  assert.equal(imported.manifest.files.length, 2, 'two file entries remain');
  assert.equal(imported.blobs.size, 1, 'one returned blob for the shared digest');
  assert.equal(imported.ociManifest.layers.length, 2, 'two OCI layer descriptors remain');
  assert.deepEqual(new Set(imported.ociManifest.layers.map(l => l.annotations[PATH_ANNOTATION])), new Set(['/a.txt', '/b.txt']), 'distinct path annotations remain');
  assert.equal(new Set(imported.ociManifest.layers.map(l => l.digest)).size, 1);
});

test('#9: identical bytes under DIFFERENT media types: descriptor metadata belongs to file entries, not blobs', async t => {
  const fixture = manifestFor([
    { path: '/same.js', bytes: shared, mediaType: 'text/javascript; charset=utf-8' },
    { path: '/same.txt', bytes: shared, mediaType: 'text/plain; charset=utf-8' }
  ]);
  assert.equal(fixture.blobs.size, 1);
  const layout = await tmp(t, 'owa-oci-dup-types-');
  const written = await writeOciLayout({ ...fixture, output: layout, ref: 'v1' });
  const { manifest: oci } = await ociManifestOf(layout);
  assert.equal(layerFor(oci, '/same.js').mediaType, 'text/javascript');
  assert.equal(layerFor(oci, '/same.txt').mediaType, 'text/plain');
  assert.equal(layerFor(oci, '/same.js').digest, layerFor(oci, '/same.txt').digest, 'same digest');
  const imported = await readOciLayout({ input: layout, ref: 'v1' });
  assertRoundTrip(imported, fixture, written);
  assert.equal(imported.manifest.files.find(f => f.path === '/same.js').mediaType, 'text/javascript; charset=utf-8');
  assert.equal(imported.manifest.files.find(f => f.path === '/same.txt').mediaType, 'text/plain; charset=utf-8');
  assert.equal(imported.blobs.size, 1);
});

test('#9: three or more paths sharing one digest, mixed with unique files, round-trip', async t => {
  const fixture = manifestFor([
    { path: '/index.html', text: '<h1>many</h1>', mediaType: 'text/html; charset=utf-8' },
    { path: '/x/1.txt', bytes: shared, mediaType: 'text/plain; charset=utf-8' },
    { path: '/x/2.txt', bytes: shared, mediaType: 'text/plain; charset=utf-8' },
    { path: '/y/3.txt', bytes: shared, mediaType: 'text/plain; charset=utf-8' },
    { path: '/z/4.js', bytes: shared, mediaType: 'text/javascript; charset=utf-8' },
    { path: '/unique.css', text: 'body{}', mediaType: 'text/css; charset=utf-8' }
  ]);
  assert.equal(fixture.manifest.files.length, 6); assert.equal(fixture.blobs.size, 3);
  const layout = await tmp(t, 'owa-oci-dup-many-');
  const written = await writeOciLayout({ ...fixture, output: layout, ref: 'v1' });
  const { manifest: oci } = await ociManifestOf(layout);
  assert.equal(oci.layers.length, 6);
  assert.equal(oci.layers.filter(l => l.digest === sha256(shared)).length, 4, 'four descriptors share one digest');
  const imported = await readOciLayout({ input: layout, ref: 'v1' });
  assertRoundTrip(imported, fixture, written);
  assert.equal(imported.blobs.size, 3);
});

test('#9: layer order is not file identity — reordered descriptors import the unchanged config manifest', async t => {
  const fixture = manifestFor([
    { path: '/index.html', text: '<h1>order</h1>', mediaType: 'text/html; charset=utf-8' },
    { path: '/same.js', bytes: shared, mediaType: 'text/javascript; charset=utf-8' },
    { path: '/same.txt', bytes: shared, mediaType: 'text/plain; charset=utf-8' },
    { path: '/other.txt', text: 'other', mediaType: 'text/plain; charset=utf-8' }
  ]);
  const layout = await tmp(t, 'owa-oci-dup-order-');
  const written = await writeOciLayout({ ...fixture, output: layout, ref: 'v1' });
  for (const reorder of [layers => layers.reverse(), layers => [layers[2], layers[0], layers[3], layers[1]]]) {
    const digest = await rewriteOciManifest(layout, oci => { oci.layers = reorder([...oci.layers]); });
    assert.notEqual(digest, written.ociManifestDigest, 'a reordered OCI manifest is a different OCI representation');
    const imported = await readOciLayout({ input: layout, ref: 'v1' });
    assertRoundTrip(imported, fixture);
    assert.deepEqual(imported.manifest.files.map(f => f.path), fixture.manifest.files.map(f => f.path), 'config order wins');
    assert.notDeepEqual(imported.ociManifest.layers.map(l => l.annotations[PATH_ANNOTATION]), fixture.manifest.files.map(f => f.path), 'layers really were reordered');
  }
});

test('#9: legacy annotation-less layout with a unique digest still imports; a PRESENT wrong or non-string path annotation never falls back by digest', async t => {
  const fixture = manifestFor([{ path: '/index.html', text: '<h1>legacy</h1>', mediaType: 'text/html; charset=utf-8' }]);
  const layout = await tmp(t, 'owa-oci-legacy-');
  const written = await writeOciLayout({ ...fixture, output: layout, ref: 'v1' });
  // No annotations at all → digest, size and mapped media type match uniquely → accepted.
  await rewriteOciManifest(layout, oci => { delete oci.layers[0].annotations; });
  assertRoundTrip(await readOciLayout({ input: layout, ref: 'v1' }), fixture);
  // Annotations without the path KEY (title only) → still the legacy shape → accepted.
  await rewriteOciManifest(layout, oci => { oci.layers[0].annotations = { 'org.opencontainers.image.title': 'index.html' }; });
  assertRoundTrip(await readOciLayout({ input: layout, ref: 'v1' }), fixture);
  // A present, conflicting path annotation is authoritative: reject, no digest fallback.
  await rewriteOciManifest(layout, oci => { oci.layers[0].annotations = { [PATH_ANNOTATION]: '/wrong.html' }; });
  await assert.rejects(readOciLayout({ input: layout, ref: 'v1' }), /cannot be selected/);
  // Presence is not truthiness: null, empty string and a number are PRESENT (and wrong).
  for (const value of [null, '', 0, false]) {
    await rewriteOciManifest(layout, oci => { oci.layers[0].annotations = { [PATH_ANNOTATION]: value }; });
    await assert.rejects(readOciLayout({ input: layout, ref: 'v1' }), /cannot be selected/, `present ${JSON.stringify(value)} path annotation is not "absent"`);
  }
  // Restoring the exact original descriptor restores the original OCI digest and acceptance.
  const restored = await rewriteOciManifest(layout, oci => { oci.layers[0].annotations = { 'org.opencontainers.image.title': 'index.html', [PATH_ANNOTATION]: '/index.html' }; });
  assert.equal(restored, written.ociManifestDigest);
  assertRoundTrip(await readOciLayout({ input: layout, ref: 'v1' }), fixture, written);
});

test('#9: malformed duplicate-content representations are rejected, never guessed', async t => {
  const fixture = manifestFor([
    { path: '/a.txt', bytes: shared, mediaType: 'text/plain; charset=utf-8' },
    { path: '/b.txt', bytes: shared, mediaType: 'text/plain; charset=utf-8' },
    { path: '/c.txt', text: 'unique c', mediaType: 'text/plain; charset=utf-8' }
  ]);
  const layout = await tmp(t, 'owa-oci-dup-bad-');
  const written = await writeOciLayout({ ...fixture, output: layout, ref: 'v1' });
  const { manifest: original } = await ociManifestOf(layout);
  // Every case mutates a clone of the ORIGINAL manifest, so each rejection isolates one defect.
  const reject = async (mutate, pattern, label) => {
    await rewriteOciManifest(layout, mutate, original);
    await assert.rejects(readOciLayout({ input: layout, ref: 'v1' }), pattern, label);
  };
  // 1. duplicate-digest manifest, one repeated layer lost its path annotation → no digest-only guessing for that group.
  await reject(oci => { delete layerFor(oci, '/b.txt').annotations[PATH_ANNOTATION]; }, /OCI layer for \/b\.txt cannot be selected/, 'one repeated descriptor without a path');
  // 2. all repeated layers lost their path annotations.
  await reject(oci => { for (const l of oci.layers) if (l.digest === sha256(shared)) delete l.annotations[PATH_ANNOTATION]; }, /OCI layer for \/a\.txt cannot be selected/, 'all repeated descriptors without paths');
  // 3. two descriptors claim the same path → ambiguous, neither first nor last is chosen.
  await reject(oci => { layerFor(oci, '/b.txt').annotations[PATH_ANNOTATION] = '/a.txt'; }, /Ambiguous OCI layout: multiple layers claim dev\.openwebartifact\.path \/a\.txt/, 'duplicate path claims');
  // 4. the path-selected descriptor's digest is not the config file's digest (size kept consistent so ONLY the digest check trips).
  await reject(oci => { const c = layerFor(oci, '/c.txt'); c.digest = sha256(shared); c.size = shared.length; }, /OCI layer digest mismatch for \/c\.txt/, 'descriptor digest mismatch');
  // 7. path correct, descriptor media type wrong → the #23 media-type check still fires.
  await reject(oci => { layerFor(oci, '/a.txt').mediaType = OCI_FALLBACK_MEDIA_TYPE; }, /OCI layer media type mismatch for \/a\.txt/, 'descriptor media type mismatch');
  // 9. one descriptor cannot satisfy two file entries: a single shared-digest descriptor for /a.txt and /b.txt.
  await reject(oci => { oci.layers = oci.layers.filter(l => l.annotations[PATH_ANNOTATION] !== '/b.txt'); }, /OCI layer for \/b\.txt cannot be selected/, 'a descriptor is used at most once');
  // A repeated descriptor whose digest matches but whose path is unknown is not a substitute for /b.txt either.
  await reject(oci => { layerFor(oci, '/b.txt').annotations[PATH_ANNOTATION] = '/elsewhere.txt'; }, /OCI layer for \/b\.txt cannot be selected/, 'conflicting path on a repeated descriptor');
  // The unique-digest file is not rescued by digest fallback through a conflicting path either.
  await reject(oci => { layerFor(oci, '/c.txt').annotations[PATH_ANNOTATION] = '/wrong.txt'; }, /OCI layer for \/c\.txt cannot be selected/, 'conflicting path on a unique-digest descriptor');
  // Re-encoding the ORIGINAL descriptors restores acceptance and the original OCI digest.
  const restored = await rewriteOciManifest(layout, () => {}, original);
  assert.equal(restored, written.ociManifestDigest);
  assertRoundTrip(await readOciLayout({ input: layout, ref: 'v1' }), fixture, written);
});

test('#9: identical bytes under different media types — swapping the two path annotations is rejected', async t => {
  const fixture = manifestFor([
    { path: '/same.js', bytes: shared, mediaType: 'text/javascript; charset=utf-8' },
    { path: '/same.txt', bytes: shared, mediaType: 'text/plain; charset=utf-8' }
  ]);
  const layout = await tmp(t, 'owa-oci-dup-swap-');
  await writeOciLayout({ ...fixture, output: layout, ref: 'v1' });
  await rewriteOciManifest(layout, oci => {
    const js = layerFor(oci, '/same.js'), txt = layerFor(oci, '/same.txt');
    js.annotations[PATH_ANNOTATION] = '/same.txt'; txt.annotations[PATH_ANNOTATION] = '/same.js';
  });
  // Same digest, same size — but the descriptor now selected for /same.js says text/plain.
  await assert.rejects(readOciLayout({ input: layout, ref: 'v1' }), /OCI layer media type mismatch for \/same\.js/);
});

test('#9: a shared digest cannot carry two declared sizes — the blob cache re-checks every file entry', async t => {
  // Structurally valid OWA manifest (validateManifest does not read bytes): one digest, two sizes.
  const digest = sha256(b('abc'));
  const manifest = {
    specVersion: 'owa.dev/v1', artifactType: OWA_MEDIA_TYPE, entrypoint: '/a.txt',
    files: [{ path: '/a.txt', digest, size: 3, mediaType: 'text/plain' }, { path: '/b.txt', digest, size: 4, mediaType: 'text/plain' }],
    access: { visibility: 'public' }, lifecycle: { expiresAt: null }
  };
  validateManifest(manifest);
  const layers = manifest.files.map(f => ({ mediaType: 'text/plain', digest, size: f.size, annotations: { [PATH_ANNOTATION]: f.path } }));
  for (const order of [layers, [...layers].reverse()]) {
    const root = await tmp(t, 'owa-oci-dup-size-');
    await authorLayout(root, { manifest, layers: order, blobs: new Map([[digest, b('abc')]]) });
    await assert.rejects(readOciLayout({ input: root, ref: 'v1' }), error => error.code === 'OWA_CONTENT_SIZE_MISMATCH', 'the second size for a cached digest is rejected');
  }
  // The same layout with consistent sizes is accepted through the hand-authored path too.
  const good = { ...manifest, files: manifest.files.map(f => ({ ...f, size: 3 })) };
  const root = await tmp(t, 'owa-oci-dup-size-ok-');
  await authorLayout(root, { manifest: good, layers: good.files.map(f => ({ mediaType: 'text/plain', digest, size: 3, annotations: { [PATH_ANNOTATION]: f.path } })), blobs: new Map([[digest, b('abc')]]) });
  const imported = await readOciLayout({ input: root, ref: 'v1' });
  assert.deepEqual(imported.manifest, good); assert.equal(imported.blobs.size, 1);
});

test('#9: packDirectory keeps deduplicating identical files, and the OCI export/import preserves both entries', async t => {
  const site = await tmp(t, 'owa-oci-dup-site-');
  await writeFile(join(site, 'index.html'), '<!doctype html><h1>pack</h1>');
  await writeFile(join(site, 'a.txt'), shared); await writeFile(join(site, 'b.txt'), shared);
  const packed = await packDirectory(site);
  assert.equal(packed.manifest.files.length, 3); assert.equal(packed.blobs.size, 2, 'packer returns one blob for identical bytes');
  assert.equal(packed.manifest.files.find(f => f.path === '/a.txt').digest, packed.manifest.files.find(f => f.path === '/b.txt').digest);
  const layout = await tmp(t, 'owa-oci-dup-pack-');
  const written = await writeOciLayout({ ...packed, output: layout, ref: 'v1' });
  const imported = await readOciLayout({ input: layout, ref: 'v1' });
  assertRoundTrip(imported, { manifest: packed.manifest, blobs: packed.blobs }, written);
  assert.equal(imported.ociManifest.layers.length, 3); assert.equal(imported.blobs.size, 2);
});
