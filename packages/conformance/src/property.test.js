import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdir, mkdtemp, readFile, rm, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { inspect } from 'node:util';
import { packDirectory, resolveRequestPath } from '../../core/src/index.js';
import {
  OWA_MEDIA_TYPE, OWA_SPEC_VERSION, artifactDigest, canonicalJson,
  validateArtifactPath, validateManifest
} from '../../spec/src/index.js';
import { PATH_ANNOTATION, ociLayerMediaType, readOciLayout, writeOciLayout } from '../../transport-oci/src/index.js';

const SEED = 0x4f574132;
const SEED_HEX = `0x${SEED.toString(16)}`;
const ITERATIONS = Object.freeze({ canonical: 128, paths: 128, digests: 128, enumeration: 16, symlink: 16, oci: 8 });

// Each property starts the same reproducible stream; filtering tests does not
// change its inputs. mkdtemp randomness isolates resources, never test data.
function generator() {
  let state = SEED;
  return {
    next() {
      state ^= state << 13;
      state ^= state >>> 17;
      state ^= state << 5;
      return state >>> 0;
    },
    int(bound) { return this.next() % bound; },
    bytes(length) { return Buffer.from(Array.from({ length }, () => this.int(256))); },
    word() { return Array.from({ length: 3 + this.int(8) }, () => String.fromCharCode(97 + this.int(26))).join(''); }
  };
}

function shuffle(values, rng) {
  const result = [...values];
  for (let i = result.length - 1; i > 0; i--) {
    const j = rng.int(i + 1);
    [result[i], result[j]] = [result[j], result[i]];
  }
  return result;
}

function permuteObjects(value, rng) {
  if (Array.isArray(value)) return value.map(item => permuteObjects(item, rng));
  if (value !== null && typeof value === 'object') {
    return Object.fromEntries(shuffle(Object.entries(value), rng).map(([key, item]) => [key, permuteObjects(item, rng)]));
  }
  return value;
}

function hash(bytes) {
  // Independent of the production digest helper, using the actual encoded bytes.
  return `sha256:${createHash('sha256').update(bytes).digest('hex')}`;
}

function manifestFor(data = Buffer.from('index'), path = '/index.html') {
  return {
    specVersion: OWA_SPEC_VERSION,
    artifactType: OWA_MEDIA_TYPE,
    entrypoint: path,
    files: [{ path, digest: hash(data), size: data.byteLength, mediaType: 'text/html; charset=utf-8' }]
  };
}

function detail(value) {
  return inspect(value, { depth: null, maxArrayLength: null, maxStringLength: null, compact: true });
}

async function property(name, run) {
  const rng = generator();
  for (let iteration = 0; iteration < ITERATIONS[name]; iteration++) {
    let operation = 'generate input';
    let input;
    const context = (nextOperation, nextInput) => { operation = nextOperation; input = nextInput; };
    try {
      // false is used only for a documented unsupported-symlink skip.
      if (await run(rng, iteration, context) === false) return;
    } catch (cause) {
      throw new Error(
        `${name} seed=${SEED_HEX} iteration=${iteration} operation=${operation} input=${detail(input)}\n${cause.message}`,
        { cause }
      );
    }
  }
}

async function withTemp(run) {
  const root = await mkdtemp(join(tmpdir(), 'owa-property-'));
  try { return await run(root); }
  finally { await rm(root, { recursive: true, force: true }); }
}

const unicodeStrings = [
  '', 'plain', '\u0000\b\t\n\f\r\u001f', '"\\/',
  '\u00e9', 'e\u0301', '\u03a9\u4e2d', '\ue000', '\uffff', '\u{10000}', '\u{1f331}', '\u{10ffff}'
];

// Hand-ordered code-point keys, including the UTF-16/code-point boundary and
// integer-like keys that ordinary object enumeration would put in numeric order.
const orderedKeys = ['\u0000', '01', '10', '2', 'a', 'e\u0301', '\u00e9', '\u03a9', '\ue000', '\uffff', '\u{10000}', '\u{1f331}'];

test(`seeded canonical object permutations and ordered arrays (${ITERATIONS.canonical}; ${SEED_HEX})`, async () => {
  await property('canonical', async (rng, iteration, context) => {
    const scalarValues = [
      ...unicodeStrings, null, false, true, 0, -0, 1, -1, Number.MIN_VALUE,
      Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, (rng.int(20001) - 10000) / 8
    ];
    const values = orderedKeys.map((_, index) => scalarValues[(iteration + index) % scalarValues.length]);
    const entries = orderedKeys.map((key, index) => [key, values[index]]);
    const a = Object.fromEntries(entries);
    const b = Object.fromEntries(shuffle(entries, rng));
    const expected = `{${orderedKeys.map((key, index) => `${JSON.stringify(key)}:${JSON.stringify(values[index])}`).join(',')}}`;
    context('canonical key order and scalar escaping', { entries, permutation: Object.keys(b) });
    assert.equal(canonicalJson(a), expected);
    assert.equal(canonicalJson(b), expected);
    assert.equal(artifactDigest(b), hash(Buffer.from(expected, 'utf8')));

    const array = [3, 2, 1, ...shuffle(scalarValues, rng)];
    context('array order is preserved, not sorted', array);
    assert.equal(canonicalJson(array), JSON.stringify(array));
    assert.deepEqual(JSON.parse(canonicalJson({ array })).array, JSON.parse(JSON.stringify(array)));
    assert.notEqual(canonicalJson(array), canonicalJson([...array].reverse()));

    const manifest = manifestFor(rng.bytes(rng.int(65)));
    manifest.annotations = Object.fromEntries(scalarValues.map((value, index) => [`annotation-${index}`, value]));
    const extra = { path: '/asset.txt', digest: hash(Buffer.from(`asset-${iteration}`)), size: Buffer.byteLength(`asset-${iteration}`), mediaType: 'text/plain' };
    // Keep a deliberately non-sorted file array; object permutations must not reorder it.
    manifest.files.push(extra);
    const permuted = permuteObjects(manifest, rng);
    context('manifest permutation and finite annotation scalar types', permuted);
    assert.equal(validateManifest(manifest), manifest);
    assert.equal(validateManifest(permuted), permuted);
    assert.equal(canonicalJson(permuted), canonicalJson(manifest));
    assert.deepEqual(JSON.parse(canonicalJson(permuted)).files.map(file => file.path), ['/index.html', '/asset.txt']);
    assert.equal(artifactDigest(permuted), hash(Buffer.from(canonicalJson(manifest), 'utf8')));
    const reversed = { ...manifest, files: [...manifest.files].reverse() };
    assert.notEqual(artifactDigest(reversed), artifactDigest(manifest));

    const nonFinite = [NaN, Infinity, -Infinity][iteration % 3];
    context('non-finite annotation rejects canonicalization and validation', nonFinite);
    assert.throws(() => canonicalJson({ value: nonFinite }), /non-finite/);
    assert.throws(() => validateManifest({ ...manifest, annotations: { bad: nonFinite } }), /non-finite/);
    context('composed and decomposed strings retain their original encoding', ['\u00e9', 'e\u0301']);
    assert.notEqual(canonicalJson('\u00e9'), canonicalJson('e\u0301'));
  });
});

test(`seeded safe paths and invalid path mutations (${ITERATIONS.paths}; ${SEED_HEX})`, async () => {
  await property('paths', async (rng, iteration, context) => {
    const suffix = ['ascii', '\u00e9', 'e\u0301', '\u4e2d', '\u{1f331}'][iteration % 5];
    const name = `${rng.word()}-${suffix}.txt`;
    const directory = rng.word();
    const path = `/${directory}/${name}`;
    const manifest = manifestFor(rng.bytes(1 + rng.int(32)), path);
    context('safe path validation and request resolution remain stable', path);
    assert.equal(validateArtifactPath(path), path);
    assert.equal(validateManifest(manifest), manifest);
    assert.equal(resolveRequestPath(manifest, path), manifest.files[0]);
    const encoded = path.split('/').map(segment => encodeURIComponent(segment)).join('/');
    assert.equal(resolveRequestPath(manifest, encoded), manifest.files[0]);
    assert.equal(resolveRequestPath(manifest, '/'), manifest.files[0]);
    assert.equal(validateArtifactPath(validateArtifactPath(path)), path);

    const badPaths = [
      '', '/', path.slice(1), `${path}/`, `//${directory}/${name}`,
      `/${directory}//${name}`, `/./${directory}/${name}`, `/${directory}/./${name}`,
      `/${directory}/.`, `/../${directory}/${name}`, `/${directory}/../${name}`,
      `/${directory}/..`, `/${directory}\\${name}`, `${path}\0`, null, 17, { toString: null }, [{ toString: null }]
    ];
    for (const badPath of shuffle(badPaths, rng)) {
      context('reject invalid path directly', badPath);
      assert.throws(() => validateArtifactPath(badPath), { code: 'OWA_INVALID_PATH' });
      context('reject mutated manifest file path', { ...manifest.files[0], path: badPath });
      assert.throws(() => validateManifest({ ...manifest, files: [{ ...manifest.files[0], path: badPath }] }), { code: 'OWA_INVALID_PATH' });
      context('reject mutated entrypoint', badPath);
      assert.throws(() => validateManifest({ ...manifest, entrypoint: badPath }), { code: 'OWA_INVALID_PATH' });
    }
    // Requests have separate normalization semantics: dots/repeated slashes may
    // normalize, but traversal, backslashes, NUL and malformed escapes cannot.
    for (const request of [`/../${name}`, `/%2e%2e/${name}`, `/${directory}/%2E%2E/${name}`, `/${directory}%5c${name}`, `${path}%00`, `${path}\0`, '/%zz']) {
      context('gateway rejects unsafe request even with SPA fallback', request);
      assert.equal(resolveRequestPath({ ...manifest, routing: { spaFallback: path } }, request), null);
    }
  });
});

test(`seeded duplicate entries, digest mutations, and sizes (${ITERATIONS.digests}; ${SEED_HEX})`, async () => {
  await property('digests', async (rng, iteration, context) => {
    const bytes = rng.bytes(iteration % 3 === 0 ? 0 : 1 + rng.int(128));
    const manifest = manifestFor(bytes);
    const file = manifest.files[0];
    context('valid digest and byte size', file);
    assert.equal(validateManifest(manifest), manifest);

    const duplicate = { ...file, digest: hash(Buffer.from(`different-${iteration}`)), size: Buffer.byteLength(`different-${iteration}`) };
    context('duplicate paths reject even if their bytes/digests differ', [file, duplicate]);
    assert.throws(() => validateManifest({ ...manifest, files: shuffle([file, duplicate], rng) }), { code: 'OWA_DUPLICATE_PATH' });
    context('duplicate content at different paths is a valid manifest', file);
    assert.doesNotThrow(() => validateManifest({ ...manifest, files: [file, { ...file, path: '/copy.html' }] }));

    const hex = file.digest.slice(7);
    const invalidDigests = [
      `sha256:${hex.slice(1)}`, `sha256:${hex}0`, `sha256:g${hex.slice(1)}`,
      `sha256:A${hex.slice(1)}`, `SHA256:${hex}`, `sha512:${hex}`, hex,
      `${file.digest} `, ` ${file.digest}`, `${file.digest}\0`, '', null, 42
    ];
    for (const digest of shuffle(invalidDigests, rng)) {
      context('reject mutated digest', { ...file, digest });
      assert.throws(() => validateManifest({ ...manifest, files: [{ ...file, digest }] }), { code: 'OWA_INVALID_DIGEST' });
    }
    for (const size of shuffle([-1, -1 - rng.int(1000), rng.int(1000) + 0.5, NaN, Infinity, -Infinity, Number.MAX_SAFE_INTEGER + 1, '0', null, undefined, true], rng)) {
      context('reject invalid size', { ...file, size });
      assert.throws(() => validateManifest({ ...manifest, files: [{ ...file, size }] }), { code: 'OWA_INVALID_SIZE' });
    }
    // Structural validation does not have content bytes; nonnegative safe
    // integer sizes are valid here. Actual byte sizes are checked below in OCI.
    for (const size of [0, 1, rng.int(100000), Number.MAX_SAFE_INTEGER]) {
      context('accept valid size boundaries', { ...file, size });
      assert.doesNotThrow(() => validateManifest({ ...manifest, files: [{ ...file, size }] }));
    }
  });
});

function generatedFiles(rng, iteration) {
  const paths = ['index.html', 'assets/app.js', 'assets/deep/data.txt'];
  for (let i = 0, count = 2 + rng.int(4); i < count; i++) paths.push(`dir${i}/${rng.word()}.txt`);
  return paths.map((path, index) => ({
    path,
    // An index-specific prefix guarantees unique bytes even if PRNG tails collide.
    data: Buffer.concat([Buffer.from(`iteration=${iteration};file=${index};`), rng.bytes(rng.int(65))])
  }));
}

async function createFiles(root, files) {
  await mkdir(root, { recursive: true });
  for (const file of files) {
    const filename = join(root, file.path);
    await mkdir(dirname(filename), { recursive: true });
    await writeFile(filename, file.data);
  }
}

function assertPackedBytes(packed, files) {
  const expected = new Map(files.map(file => [`/${file.path}`, file.data]));
  assert.equal(packed.manifest.files.length, expected.size);
  assert.deepEqual([...packed.manifest.files.map(file => file.path)].sort(), [...expected.keys()].sort());
  for (const file of packed.manifest.files) {
    const original = expected.get(file.path);
    assert.equal(file.digest, hash(original), file.path);
    assert.equal(file.size, original.byteLength, file.path);
    assert.deepEqual(Buffer.from(packed.blobs.get(file.digest)), original, file.path);
  }
  assert.equal(packed.artifactDigest, hash(Buffer.from(canonicalJson(packed.manifest), 'utf8')));
}

// Fixed Unicode ordering set (issue #8) added to every enumeration iteration under
// a collision-safe directory: Greek, CJK, BMP private-use, and two supplementary
// code points. Names are portable on Linux/macOS/Windows (no case-only pairs, no
// canonically-equivalent pairs, no forbidden characters). Deterministic bytes.
const unicodeOrderingFiles = [
  { path: 'unicode-order/\u{1F331}.txt', data: Buffer.from('U+1F331 seedling\n') },
  { path: 'unicode-order/Ω.txt', data: Buffer.from('U+03A9 omega\n') },
  { path: 'unicode-order/\u{10000}.txt', data: Buffer.from('U+10000 linear b\n') },
  { path: 'unicode-order/.txt', data: Buffer.from('U+E000 private use\n') },
  { path: 'unicode-order/中.txt', data: Buffer.from('U+4E2D cjk\n') }
];
// STATIC anchor for the specified rule, hand-ordered by code point: U+03A9 <
// U+4E2D < U+E000 < U+10000 < U+1F331. Written literally so a refactor to
// default .sort() (UTF-16 code units: U+10000's lead surrogate U+D800 < U+E000)
// or to locale collation fails here regardless of host.
const expectedUnicodeOrder = ['/unicode-order/Ω.txt', '/unicode-order/中.txt', '/unicode-order/.txt', '/unicode-order/\u{10000}.txt', '/unicode-order/\u{1F331}.txt'];
// Test-local code-point comparator (independent of packages/spec) for the
// generated ASCII part of each expected list.
function codePointOrder(a, b) {
  const x = Array.from(a, c => c.codePointAt(0)), y = Array.from(b, c => c.codePointAt(0));
  for (let i = 0; i < Math.min(x.length, y.length); i++) if (x[i] !== y[i]) return x[i] - y[i];
  return x.length - y.length;
}

test(`seeded packing ignores filesystem creation order and sorts complete paths by Unicode code point (${ITERATIONS.enumeration}; ${SEED_HEX})`, async () => {
  await property('enumeration', async (rng, iteration, context) => {
    const files = [...generatedFiles(rng, iteration), ...unicodeOrderingFiles];
    const first = shuffle(files, rng);
    // A reverse of a shuffled order is guaranteed to be different (unique paths).
    const second = [...first].reverse();
    const expectedPaths = files.map(file => `/${file.path}`).sort(codePointOrder);
    context('pack equal Unicode-capable trees created in different orders', {
      files: files.map(file => file.path), first: first.map(file => file.path), second: second.map(file => file.path), expectedPaths
    });
    await withTemp(async root => {
      const aRoot = join(root, 'first'), bRoot = join(root, 'second');
      await createFiles(aRoot, first);
      await createFiles(bRoot, second);
      const a = await packDirectory(aRoot), b = await packDirectory(bRoot);
      assertPackedBytes(a, files);
      assertPackedBytes(b, files);
      assert.deepEqual(a.manifest, b.manifest, 'structurally equal manifests');
      assert.equal(canonicalJson(a.manifest), canonicalJson(b.manifest));
      assert.equal(a.artifactDigest, b.artifactDigest);
      // Not merely A == B (both could be deterministically wrong): the exact
      // specified order, independently computed, and the literal Unicode anchor.
      assert.deepEqual(a.manifest.files.map(file => file.path), expectedPaths, 'complete artifact paths in Unicode code-point order');
      assert.deepEqual(a.manifest.files.slice(-expectedUnicodeOrder.length).map(file => file.path), expectedUnicodeOrder, 'U+03A9 < U+4E2D < U+E000 < U+10000 < U+1F331');
      // No normalization or folding happened: the exact strings created on disk came back.
      for (const file of unicodeOrderingFiles) assert.ok(a.manifest.files.some(entry => entry.path === `/${file.path}`), `${file.path} preserved exactly`);
    });
  });
});

function unsupportedSymlink(error) {
  // ENOSYS/ENOTSUP/EOPNOTSUPP report an unsupported OS/filesystem operation.
  // Windows can additionally require an unavailable symlink privilege (EPERM).
  // Other permission, missing-path and IO errors are failures, not portable skips.
  return ['ENOSYS', 'ENOTSUP', 'EOPNOTSUPP'].includes(error.code)
    || (process.platform === 'win32' && error.code === 'EPERM');
}

test(`seeded packing rejects file, directory, dangling, and external symlinks (${ITERATIONS.symlink}; ${SEED_HEX})`, async t => {
  await property('symlink', async (rng, iteration, context) => {
    return withTemp(async root => {
      const site = join(root, 'site');
      const bytes = rng.bytes(1 + rng.int(32));
      await createFiles(site, [{ path: 'index.html', data: bytes }, { path: 'nested/inside.txt', data: bytes }]);
      const outside = join(root, 'outside.txt');
      await writeFile(outside, Buffer.from(`outside-${iteration}`));
      const kind = ['file', 'directory', 'dangling', 'external'][iteration % 4];
      const target = {
        file: join(site, 'index.html'), directory: join(site, 'nested'),
        dangling: join(site, `missing-${rng.word()}`), external: outside
      }[kind];
      const link = join(site, `link-${rng.word()}`);
      context('create symlink then reject packing', { kind, target, link });
      try { await symlink(target, link, kind === 'directory' ? 'dir' : 'file'); }
      catch (error) {
        if (!unsupportedSymlink(error)) throw error;
        t.skip(`symlinks unsupported: ${error.code}; seed=${SEED_HEX}; iteration=${iteration}; kind=${kind}`);
        return false;
      }
      await assert.rejects(packDirectory(site), { code: 'OWA_SYMLINK' });
    });
  });
});

function blobPath(root, digest) {
  return join(root, 'blobs', 'sha256', digest.slice(7));
}

// Duplicate content (issue #9): every fourth iteration keeps unique bytes; the
// other three add paths whose bytes are identical to an existing file's — a pair
// with one media type, several duplicates mixed with unique files, and identical
// bytes under DIFFERENT media types (.js vs .txt). Paths stay lowercase ASCII.
function withDuplicateContent(files, rng, iteration) {
  const copy = (index, path) => ({ path, data: files[index].data });
  switch (iteration % 4) {
    case 1: return [...files, copy(2, `dup/${rng.word()}.txt`)];
    case 2: return [...files, copy(1, 'mirror/app.js'), copy(1, `mirror/${rng.word()}.txt`), copy(0, 'mirror/index.html')];
    case 3: return [...files, copy(2, 'same.js'), copy(2, 'same.txt'), copy(2, 'deeper/same.txt')];
    default: return files;
  }
}
const uniqueDigests = files => new Set(files.map(file => hash(file.data))).size;

test(`seeded OCI round-trips actual bytes, duplicate-content entries and reordered descriptors, and rejects tampering (${ITERATIONS.oci}; ${SEED_HEX})`, async () => {
  await property('oci', async (rng, iteration, context) => {
    const files = withDuplicateContent(generatedFiles(rng, iteration), rng, iteration);
    await withTemp(async root => {
      const site = join(root, 'site'), layout = join(root, 'layout');
      context('pack files for OCI (duplicate content on 3 of 4 iterations)', files);
      await createFiles(site, shuffle(files, rng));
      const packed = await packDirectory(site);
      assertPackedBytes(packed, files);
      assert.equal(packed.blobs.size, uniqueDigests(files), 'the packer returns one blob per distinct digest');
      if (iteration % 4 !== 0) assert.ok(packed.blobs.size < files.length, 'this iteration really has duplicate content');
      const ref = `seeded-${iteration}`;
      const written = await writeOciLayout({ ...packed, output: layout, ref });
      const ociManifest = JSON.parse((await readFile(blobPath(layout, written.ociManifestDigest))).toString('utf8'));
      context('one OCI descriptor per file entry; repeated digests keep distinct path annotations and per-file media types', ociManifest.layers);
      assert.equal(ociManifest.layers.length, packed.manifest.files.length);
      assert.deepEqual(ociManifest.layers.map(layer => layer.annotations[PATH_ANNOTATION]), packed.manifest.files.map(file => file.path));
      for (const file of packed.manifest.files) {
        const layer = ociManifest.layers.find(item => item.annotations[PATH_ANNOTATION] === file.path);
        assert.equal(layer.digest, file.digest); assert.equal(layer.size, file.size);
        assert.equal(layer.mediaType, ociLayerMediaType(file.mediaType));
      }
      context('read OCI and compare the original manifest, digests, and bytes', { ref, files });
      const imported = await readOciLayout({ input: layout, ref });
      assert.equal(written.artifactDigest, packed.artifactDigest);
      assert.equal(imported.artifactDigest, packed.artifactDigest);
      assert.deepEqual(imported.manifest, packed.manifest);
      assert.equal(imported.blobs.size, uniqueDigests(files), 'repeated descriptors still yield one returned blob per digest');
      assertPackedBytes(imported, files);
      const config = await readFile(blobPath(layout, packed.artifactDigest));
      assert.equal(config.toString('utf8'), canonicalJson(packed.manifest));
      assert.equal(hash(config), packed.artifactDigest);
      assert.equal(hash(await readFile(blobPath(layout, written.ociManifestDigest))), written.ociManifestDigest);

      // Descriptor ORDER is not OWA file identity: a shuffled layer list (same
      // path/digest/size/mediaType per descriptor) imports the identical config.
      const indexFile = join(layout, 'index.json');
      const originalIndex = await readFile(indexFile);
      const reordered = { ...ociManifest, layers: shuffle(ociManifest.layers, rng) };
      const reorderedBytes = Buffer.from(canonicalJson(reordered), 'utf8');
      context('reader ignores OCI layer order', reordered.layers.map(layer => layer.annotations[PATH_ANNOTATION]));
      await writeFile(blobPath(layout, hash(reorderedBytes)), reorderedBytes);
      const reorderedIndex = JSON.parse(originalIndex.toString('utf8'));
      reorderedIndex.manifests[0] = { ...reorderedIndex.manifests[0], digest: hash(reorderedBytes), size: reorderedBytes.byteLength };
      await writeFile(indexFile, JSON.stringify(reorderedIndex));
      try {
        const fromReordered = await readOciLayout({ input: layout, ref });
        assert.deepEqual(fromReordered.manifest, packed.manifest);
        assert.equal(fromReordered.artifactDigest, packed.artifactDigest);
        assertPackedBytes(fromReordered, files);
      } finally { await writeFile(indexFile, originalIndex); }

      const victim = packed.manifest.files[rng.int(packed.manifest.files.length)];
      const original = Buffer.from(packed.blobs.get(victim.digest));
      const corrupt = Buffer.from(original);
      corrupt[rng.int(corrupt.length)] ^= 1;
      context('writer rejects same-size corrupt source bytes', { victim, corrupt });
      const corruptSource = new Map(packed.blobs);
      corruptSource.set(victim.digest, corrupt);
      await assert.rejects(writeOciLayout({ manifest: packed.manifest, blobs: corruptSource, output: join(root, 'bad-digest') }), { code: 'OWA_CONTENT_DIGEST_MISMATCH' });
      const wrongSize = Buffer.concat([original, Buffer.from([0])]);
      context('writer rejects wrong source byte size', { victim, wrongSize });
      corruptSource.set(victim.digest, wrongSize);
      await assert.rejects(writeOciLayout({ manifest: packed.manifest, blobs: corruptSource, output: join(root, 'bad-size') }), { code: 'OWA_CONTENT_SIZE_MISMATCH' });

      // Mutate one verified layer, config, or OCI manifest at a time, preserving
      // length so that rejection exercises the digest check, not JSON parsing.
      for (const [kind, digest] of [['layer', victim.digest], ['config', packed.artifactDigest], ['oci-manifest', written.ociManifestDigest]]) {
        const path = blobPath(layout, digest);
        const before = await readFile(path);
        const changed = Buffer.from(before);
        changed[rng.int(changed.length)] ^= 1;
        context('reader rejects same-size tampered blob', { kind, digest, before, changed });
        await writeFile(path, changed);
        try { await assert.rejects(readOciLayout({ input: layout, ref }), { code: 'OWA_CONTENT_DIGEST_MISMATCH' }); }
        finally { await writeFile(path, before); }
      }

      // Keep the correct bytes and digest, but lie about descriptor size; this
      // reaches the size check rather than failing the preceding hash check.
      const indexPath = join(layout, 'index.json');
      const indexBytes = await readFile(indexPath);
      const index = JSON.parse(indexBytes.toString('utf8'));
      index.manifests[0].size++;
      context('reader rejects wrong OCI descriptor size', index.manifests[0]);
      await writeFile(indexPath, JSON.stringify(index));
      try { await assert.rejects(readOciLayout({ input: layout, ref }), { code: 'OWA_CONTENT_SIZE_MISMATCH' }); }
      finally { await writeFile(indexPath, indexBytes); }
      context('restored OCI layout still round-trips', { ref, artifactDigest: packed.artifactDigest });
      assertPackedBytes(await readOciLayout({ input: layout, ref }), files);
    });
  });
});
