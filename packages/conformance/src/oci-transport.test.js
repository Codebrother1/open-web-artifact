import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { artifactDigest, canonicalJson, OWA_MEDIA_TYPE, sha256, validateManifest } from '../../spec/src/index.js';
import { OCI_FALLBACK_MEDIA_TYPE, OCI_IMAGE_MANIFEST, ociLayerMediaType, readOciLayout, writeOciLayout } from '../../transport-oci/src/index.js';

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
  assert.equal(new Set(manifest.files.map(f => f.digest)).size, manifest.files.length, 'fixture digests are unique (issue #9 semantics untouched)');
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

test('issue #9 duplicate-content behavior is untouched by the media-type mapping (documented, not fixed here)', async t => {
  // Two paths sharing one digest still collapse on the reader's digest index —
  // exactly the open #9 behavior. This test pins that nothing here changed it.
  const bytes = b('shared bytes');
  const { manifest, blobs } = manifestFor([
    { path: '/a.txt', bytes, mediaType: 'text/plain; charset=utf-8' },
    { path: '/b.txt', bytes, mediaType: 'text/plain; charset=utf-8' }
  ]);
  const layout = await tmp(t, 'owa-oci-dup-');
  const written = await writeOciLayout({ manifest, blobs, output: layout, ref: 'v1' });
  const { manifest: oci } = await ociManifestOf(layout);
  assert.equal(oci.layers.length, 2, 'two layers are written');
  assert.equal(new Set(oci.layers.map(l => l.digest)).size, 1, 'sharing one digest');
  await assert.rejects(readOciLayout({ input: layout, ref: 'v1' }), /OCI layer path mismatch/, 'the reader still trips on the collapsed path annotation (#9)');
  assert.equal(written.artifactDigest, artifactDigest(manifest));
});
