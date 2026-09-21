import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { OWA_MEDIA_TYPE, artifactDigest, sha256, validateManifest } from '../../spec/src/index.js';
import { OCI_IMAGE_INDEX, OCI_IMAGE_MANIFEST, REF_NAME_ANNOTATION, readOciLayout, selectIndexDescriptor, writeOciLayout } from '../../transport-oci/src/index.js';

// Index reference selection (issue #36; docs/oci.md "Index reference selection").
// EXACTLY ONE EXACT MATCH OR FAIL: the requested ref is the only selector; a
// descriptor matches when its `annotations` object carries the key
// org.opencontainers.image.ref.name with a STRING value exactly equal to the
// ref; zero matches and duplicate matches both fail; descriptor order never
// breaks a tie; there is no `latest` → manifests[0] fallback (the previous
// reference behaviour). These failures are transport-local layout errors with
// no portable OWA error category, which is why they are pinned here and in the
// Go anchors rather than by negative corpus vectors. The portable SUCCESS
// anchor is blob-read-index-exact-ref-selection in docs/conformance/v0.2/blob.json.

const REF = REF_NAME_ANNOTATION;
const NOT_FOUND = /OCI reference not found: /;
const AMBIGUOUS = /Ambiguous OCI index: \d+ descriptors carry org\.opencontainers\.image\.ref\.name /;
const b = text => Buffer.from(text, 'utf8');

function artifact(files) {
  const blobs = new Map();
  const manifest = {
    specVersion: 'owa.dev/v1', artifactType: OWA_MEDIA_TYPE, entrypoint: files[0].path,
    files: files.map(file => { const bytes = b(file.text); const digest = sha256(bytes); blobs.set(digest, bytes); return { path: file.path, digest, size: bytes.length, mediaType: file.mediaType }; }),
    access: { visibility: 'unlisted' }, lifecycle: { expiresAt: null }
  };
  validateManifest(manifest);
  return { manifest, blobs };
}
async function tmp(t) { const dir = await mkdtemp(join(tmpdir(), 'owa-oci-ref-')); t.after(() => rm(dir, { recursive: true, force: true })); return dir; }
const indexOf = async layout => JSON.parse(await readFile(join(layout, 'index.json'), 'utf8'));
const setIndex = (layout, index) => writeFile(join(layout, 'index.json'), JSON.stringify(index));
const setManifests = (layout, manifests) => setIndex(layout, { schemaVersion: 2, mediaType: OCI_IMAGE_INDEX, manifests });
const withRef = (descriptor, value) => ({ ...descriptor, annotations: { ...descriptor.annotations, [REF]: value } });
const withoutRef = descriptor => { const annotations = { ...descriptor.annotations }; delete annotations[REF]; return { ...descriptor, annotations }; };
const withoutAnnotations = descriptor => { const { annotations, ...rest } = descriptor; return rest; };

/** One layout directory holding TWO complete, importable artifacts (blobs accumulate; the index is composed by hand). */
async function twoArtifacts(t) {
  const layout = await tmp(t);
  const decoy = artifact([{ path: '/index.html', text: '<h1>v1: the decoy</h1>', mediaType: 'text/html; charset=utf-8' }]);
  const target = artifact([
    { path: '/index.html', text: '<h1>latest: the target</h1>', mediaType: 'text/html; charset=utf-8' },
    { path: '/notes.txt', text: 'selected by ref.name, not by position', mediaType: 'text/plain; charset=utf-8' }
  ]);
  assert.notEqual(artifactDigest(decoy.manifest), artifactDigest(target.manifest));
  const decoyWritten = await writeOciLayout({ ...decoy, output: layout, ref: 'v1' });
  const decoyDescriptor = (await indexOf(layout)).manifests[0];
  const targetWritten = await writeOciLayout({ ...target, output: layout, ref: 'latest' });
  const targetDescriptor = (await indexOf(layout)).manifests[0];
  assert.equal(decoyDescriptor.annotations[REF], 'v1'); assert.equal(targetDescriptor.annotations[REF], 'latest');
  assert.notEqual(decoyDescriptor.digest, targetDescriptor.digest);
  return { layout, decoy, target, decoyWritten, targetWritten, decoyDescriptor, targetDescriptor };
}
function assertTarget(imported, { target, targetWritten, decoyWritten }) {
  assert.equal(imported.artifactDigest, targetWritten.artifactDigest, 'the uniquely matching descriptor was selected');
  assert.notEqual(imported.artifactDigest, decoyWritten.artifactDigest, 'the first descriptor was NOT selected');
  assert.equal(imported.ociManifestDigest, targetWritten.ociManifestDigest);
  assert.deepEqual(imported.manifest, target.manifest);
  assert.equal(imported.blobs.size, 2);
  for (const [digest, bytes] of target.blobs) assert.ok(Buffer.from(imported.blobs.get(digest)).equals(bytes));
}

test('selectIndexDescriptor: exactly one exact string match, or fail — every rule of the selector', () => {
  const d = (ref, extra = {}) => ({ mediaType: OCI_IMAGE_MANIFEST, digest: `sha256:${'0'.repeat(64)}`, size: 1, annotations: { [REF]: ref }, ...extra });
  const latest = d('latest'), v1 = d('v1');
  // 1. manifests MUST be an array.
  for (const index of [undefined, null, {}, { manifests: null }, { manifests: {} }, { manifests: 'latest' }, { manifests: latest }]) {
    assert.throws(() => selectIndexDescriptor(index, 'latest'), /OCI index has no manifests array/, JSON.stringify(index));
  }
  // The requested ref is the selector and must itself be a nonempty string.
  for (const ref of ['', undefined, null, 0, true, ['latest']]) assert.throws(() => selectIndexDescriptor({ manifests: [latest] }, ref), /OCI reference must be a nonempty string/);
  // 4. exactly one match: the very same descriptor object is returned.
  assert.equal(selectIndexDescriptor({ manifests: [latest] }, 'latest'), latest);
  assert.equal(selectIndexDescriptor({ manifests: [v1, latest] }, 'latest'), latest, 'matching descriptor is second');
  assert.equal(selectIndexDescriptor({ manifests: [latest, v1] }, 'v1'), v1, 'the other ref selects the other descriptor');
  assert.equal(selectIndexDescriptor({ manifests: [d('v2'), v1, latest, d('v3')] }, 'latest'), latest, 'third of four');
  // 2. only OBJECT descriptors are considered; other entries are ignored, never matched.
  assert.equal(selectIndexDescriptor({ manifests: [null, 'latest', 42, true, ['latest'], latest] }, 'latest'), latest);
  assert.throws(() => selectIndexDescriptor({ manifests: [null, 'latest', 42, ['latest']] }, 'latest'), NOT_FOUND);
  // 5, 8–14. zero matches → reference not found; nothing below matches "latest".
  for (const descriptor of [
    withoutAnnotations(latest),                       // missing annotations
    { ...latest, annotations: null },                 // annotations null
    { ...latest, annotations: 'latest' },             // annotations not an object
    { ...latest, annotations: ['latest'] },           // annotations an array
    { ...latest, annotations: {} },                   // missing ref.name key
    { ...latest, annotations: { 'org.opencontainers.image.title': 'latest' } }, // a different key
    withRef(latest, null),                            // ref.name null
    withRef(latest, 0), withRef(latest, 1),           // number
    withRef(latest, true), withRef(latest, false),    // boolean
    withRef(latest, ''),                              // empty string when a nonempty ref was requested
    withRef(latest, ['latest']), withRef(latest, { name: 'latest' }), // array / object
    v1, d('Latest'), d('LATEST'), d(' latest'), d('latest '), d('latest\u00a0'), d('lätest') // different strings: exact equality, no folding or trimming
  ]) {
    assert.throws(() => selectIndexDescriptor({ manifests: [descriptor] }, 'latest'), NOT_FOUND, JSON.stringify(descriptor));
    assert.throws(() => selectIndexDescriptor({ manifests: [descriptor, v1] }, 'latest'), NOT_FOUND, 'nor does another descriptor rescue it');
  }
  // 15. requesting `latest` MUST NOT fall back to manifests[0].
  assert.throws(() => selectIndexDescriptor({ manifests: [v1] }, 'latest'), /OCI reference not found: latest$/);
  assert.throws(() => selectIndexDescriptor({ manifests: [withoutRef(latest)] }, 'latest'), /OCI reference not found: latest$/);
  assert.throws(() => selectIndexDescriptor({ manifests: [{ mediaType: OCI_IMAGE_MANIFEST, digest: latest.digest, size: 1 }] }, 'latest'), /OCI reference not found: latest$/);
  // 6–7. more than one exact match → ambiguous, whatever the order and however alike or different the descriptors are.
  const other = d('latest', { digest: `sha256:${'f'.repeat(64)}`, size: 2 });
  assert.throws(() => selectIndexDescriptor({ manifests: [latest, latest] }, 'latest'), /Ambiguous OCI index: 2 descriptors carry org\.opencontainers\.image\.ref\.name latest$/);
  assert.throws(() => selectIndexDescriptor({ manifests: [latest, other] }, 'latest'), AMBIGUOUS);
  assert.throws(() => selectIndexDescriptor({ manifests: [other, latest] }, 'latest'), AMBIGUOUS, 'reversed order is still ambiguous');
  assert.throws(() => selectIndexDescriptor({ manifests: [v1, latest, d('v2'), other] }, 'latest'), AMBIGUOUS, 'non-matching descriptors do not disambiguate');
  assert.throws(() => selectIndexDescriptor({ manifests: [latest, latest, other] }, 'latest'), /3 descriptors carry/);
  // 16. nothing else selects: same digest, same artifact annotation or same media type under another ref is not a match.
  assert.throws(() => selectIndexDescriptor({ manifests: [withRef(latest, 'v1')] }, 'latest'), NOT_FOUND);
});

test('the undocumented `latest` → manifests[0] fallback is gone: a layout written under another ref no longer imports as `latest`', async t => {
  const layout = await tmp(t);
  const { manifest, blobs } = artifact([{ path: '/index.html', text: '<h1>v1 only</h1>', mediaType: 'text/html; charset=utf-8' }]);
  const written = await writeOciLayout({ manifest, blobs, output: layout, ref: 'v1' });
  const index = await indexOf(layout);
  assert.equal(index.manifests.length, 1); assert.equal(index.manifests[0].annotations[REF], 'v1', 'the writer still names the descriptor by the requested ref (unchanged)');
  await assert.rejects(readOciLayout({ input: layout }), /OCI reference not found: latest$/, 'default ref latest, single v1 descriptor: no fallback');
  await assert.rejects(readOciLayout({ input: layout, ref: 'latest' }), /OCI reference not found: latest$/);
  await assert.rejects(readOciLayout({ input: layout, ref: 'v2' }), /OCI reference not found: v2$/, 'no matching ref');
  await assert.rejects(readOciLayout({ input: layout, ref: '' }), /OCI reference must be a nonempty string/);
  const imported = await readOciLayout({ input: layout, ref: 'v1' });
  assert.equal(imported.artifactDigest, written.artifactDigest); assert.equal(imported.ociManifestDigest, written.ociManifestDigest); assert.equal(imported.ref, 'v1');
});

test('one descriptor with a missing, malformed, empty or different ref.name never matches `latest` — no fallback of any kind', async t => {
  const layout = await tmp(t);
  const { manifest, blobs } = artifact([{ path: '/index.html', text: '<h1>one</h1>', mediaType: 'text/html; charset=utf-8' }]);
  await writeOciLayout({ manifest, blobs, output: layout, ref: 'latest' });
  const [descriptor] = (await indexOf(layout)).manifests;
  assertTargetless(await readOciLayout({ input: layout, ref: 'latest' }), manifest);
  const cases = [
    ['no annotations object', withoutAnnotations(descriptor)],
    ['annotations null', { ...descriptor, annotations: null }],
    ['annotations without the ref.name key', withoutRef(descriptor)],
    ['ref.name null', withRef(descriptor, null)],
    ['ref.name number', withRef(descriptor, 1)],
    ['ref.name boolean true', withRef(descriptor, true)],
    ['ref.name boolean false', withRef(descriptor, false)],
    ['ref.name empty string', withRef(descriptor, '')],
    ['ref.name another ref', withRef(descriptor, 'v1')],
    ['ref.name differing only in case', withRef(descriptor, 'Latest')]
  ];
  for (const [label, mutated] of cases) {
    await setManifests(layout, [mutated]);
    await assert.rejects(readOciLayout({ input: layout, ref: 'latest' }), /OCI reference not found: latest$/, label);
  }
  await setIndex(layout, { schemaVersion: 2, mediaType: OCI_IMAGE_INDEX });
  await assert.rejects(readOciLayout({ input: layout, ref: 'latest' }), /OCI index has no manifests array/, 'manifests missing');
  await setIndex(layout, { schemaVersion: 2, mediaType: OCI_IMAGE_INDEX, manifests: descriptor });
  await assert.rejects(readOciLayout({ input: layout, ref: 'latest' }), /OCI index has no manifests array/, 'manifests not an array');
  // Restoring the exact original descriptor restores acceptance.
  await setManifests(layout, [descriptor]);
  assertTargetless(await readOciLayout({ input: layout, ref: 'latest' }), manifest);
  function assertTargetless(imported, expected) { assert.deepEqual(imported.manifest, expected); assert.equal(imported.artifactDigest, artifactDigest(expected)); }
});

test('two descriptors carrying the same requested ref are ambiguous — in either order, identical or different, with or without bystanders', async t => {
  const fixture = await twoArtifacts(t);
  const { layout, decoyDescriptor, targetDescriptor } = fixture;
  // Identical duplicates of one importable descriptor.
  await setManifests(layout, [targetDescriptor, targetDescriptor]);
  await assert.rejects(readOciLayout({ input: layout, ref: 'latest' }), /Ambiguous OCI index: 2 descriptors carry org\.opencontainers\.image\.ref\.name latest$/);
  // Two DIFFERENT complete artifacts both claiming `latest`: neither first nor last wins.
  const decoyAsLatest = withRef(decoyDescriptor, 'latest');
  await setManifests(layout, [decoyAsLatest, targetDescriptor]);
  await assert.rejects(readOciLayout({ input: layout, ref: 'latest' }), AMBIGUOUS, 'decoy first');
  await setManifests(layout, [targetDescriptor, decoyAsLatest]);
  await assert.rejects(readOciLayout({ input: layout, ref: 'latest' }), AMBIGUOUS, 'reversed duplicate order still fails');
  await setManifests(layout, [withRef(decoyDescriptor, 'v0'), decoyAsLatest, withRef(targetDescriptor, 'v2'), targetDescriptor]);
  await assert.rejects(readOciLayout({ input: layout, ref: 'latest' }), AMBIGUOUS, 'non-matching bystanders do not disambiguate');
  // The SAME layout is fine for a ref that is unique in it.
  await setManifests(layout, [decoyAsLatest, targetDescriptor, withRef(targetDescriptor, 'v2')]);
  const v2 = await readOciLayout({ input: layout, ref: 'v2' });
  assert.equal(v2.artifactDigest, fixture.targetWritten.artifactDigest);
  await assert.rejects(readOciLayout({ input: layout, ref: 'latest' }), AMBIGUOUS);
});

test('exact match beats array position: the uniquely matching descriptor is selected wherever it sits, and the first descriptor is never a fallback', async t => {
  const fixture = await twoArtifacts(t);
  const { layout, decoyDescriptor, targetDescriptor } = fixture;
  // 10–11. decoy (v1) first, target (latest) second — the shape of the corpus anchor.
  await setManifests(layout, [decoyDescriptor, targetDescriptor]);
  assertTarget(await readOciLayout({ input: layout, ref: 'latest' }), fixture);
  const decoy = await readOciLayout({ input: layout, ref: 'v1' });
  assert.equal(decoy.artifactDigest, fixture.decoyWritten.artifactDigest, 'the other ref selects the decoy: both are importable, only the ref decides');
  assert.deepEqual(decoy.manifest, fixture.decoy.manifest);
  // Order-independence: reversed, the same ref selects the same artifact.
  await setManifests(layout, [targetDescriptor, decoyDescriptor]);
  assertTarget(await readOciLayout({ input: layout, ref: 'latest' }), fixture);
  // Buried among non-object entries and unrelated descriptors (missing/other/malformed refs), still selected.
  await setManifests(layout, [null, 'latest', withRef(decoyDescriptor, 'v0'), decoyDescriptor, withoutRef(decoyDescriptor), withRef(decoyDescriptor, null), targetDescriptor, withRef(decoyDescriptor, 'v2'), 42]);
  assertTarget(await readOciLayout({ input: layout, ref: 'latest' }), fixture);
  // Remove the only match: no positional, digest or media-type guessing rescues `latest`.
  await setManifests(layout, [decoyDescriptor, withRef(targetDescriptor, 'v2')]);
  await assert.rejects(readOciLayout({ input: layout, ref: 'latest' }), /OCI reference not found: latest$/);
});

test('everything after selection is unchanged: the uniquely selected descriptor is still fully verified', async t => {
  const fixture = await twoArtifacts(t);
  const { layout, decoyDescriptor, targetDescriptor } = fixture;
  await setManifests(layout, [decoyDescriptor, { ...targetDescriptor, size: targetDescriptor.size + 1 }]);
  await assert.rejects(readOciLayout({ input: layout, ref: 'latest' }), error => error.code === 'OWA_CONTENT_SIZE_MISMATCH', 'selected descriptor size is still checked');
  // The ref only SELECTS a descriptor; the descriptor's digest decides the content. A self-consistent
  // `latest` descriptor that points at the decoy's OCI manifest imports the decoy — every post-selection
  // check (OCI manifest hash/size, config hash, artifact digest, layers, blobs) still applies to it.
  await setManifests(layout, [decoyDescriptor, { ...targetDescriptor, digest: decoyDescriptor.digest, size: decoyDescriptor.size }]);
  const repointed = await readOciLayout({ input: layout, ref: 'latest' });
  assert.equal(repointed.artifactDigest, fixture.decoyWritten.artifactDigest); assert.equal(repointed.ociManifestDigest, fixture.decoyWritten.ociManifestDigest);
  // A selected descriptor whose digest names no blob is rejected (nothing is guessed from the other descriptor).
  await setManifests(layout, [decoyDescriptor, { ...targetDescriptor, digest: `sha256:${'e'.repeat(64)}` }]);
  await assert.rejects(readOciLayout({ input: layout, ref: 'latest' }), error => error.code === 'ENOENT', 'selected descriptor must name an existing blob');
  await setManifests(layout, [decoyDescriptor, { ...targetDescriptor, mediaType: OCI_IMAGE_INDEX }]);
  await assert.rejects(readOciLayout({ input: layout, ref: 'latest' }), /Unsupported OCI manifest media type/, 'selected descriptor media type is still checked');
  await setManifests(layout, [decoyDescriptor, targetDescriptor]);
  assertTarget(await readOciLayout({ input: layout, ref: 'latest' }), fixture);
});
