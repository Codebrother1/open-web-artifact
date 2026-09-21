import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { packDirectory } from '../../core/src/index.js';
import { canonicalJson, compareUnicodeCodePoints, validateManifest } from '../../spec/src/index.js';

// Locale-independent pack ordering (issue #8). packDirectory orders COMPLETE OWA
// artifact paths by Unicode code-point lexicographic order — the same relation
// canonical JSON uses for object keys — never by locale collation, UTF-16 code
// units, normalization or case folding. Canonicalization itself still preserves
// whatever files order a manifest already has.

test('compareUnicodeCodePoints: code-point lexicographic order, no folding, no normalization, no UTF-16 order', () => {
  const lt = (a, b, why) => { assert.ok(compareUnicodeCodePoints(a, b) < 0, `${JSON.stringify(a)} < ${JSON.stringify(b)}: ${why}`); assert.ok(compareUnicodeCodePoints(b, a) > 0, `antisymmetric: ${JSON.stringify(b)} > ${JSON.stringify(a)}`); };
  lt('a', 'b', 'ASCII');
  lt('a', 'a0', 'a proper prefix sorts first');
  lt('', 'a', 'the empty string is the shortest prefix');
  lt('A', 'a', 'case is NOT folded (U+0041 < U+0061)');
  lt('Z', 'a', 'uppercase ASCII precedes lowercase ASCII by code point');
  lt('z', 'Ω', 'ASCII (U+007A) before Greek (U+03A9)');
  lt('Ω', '中', 'Greek (U+03A9) before CJK (U+4E2D)');
  lt('中', '', 'CJK (U+4E2D) before BMP private use (U+E000)');
  // THE code-point-versus-UTF-16 anchor: U+E000 = 57344 < U+10000 = 65536, but
  // U+10000 is the surrogate pair D800 DC00 and 0xD800 < 0xE000 as code units.
  lt('', '\u{10000}', 'BMP private use before supplementary BY CODE POINT');
  assert.ok(['\u{10000}', ''].sort()[0] === '\u{10000}', 'sanity: default .sort() (UTF-16 code units) puts U+10000 first — the very order this comparator must NOT produce');
  lt('\u{10000}', '\u{1F331}', 'supplementary values compare numerically');
  lt('￿', '\u{10000}', 'last BMP code point before the first supplementary one');
  // No normalization: "é" (U+0065 U+0301) and "é" (U+00E9) are distinct
  // strings compared by their actual code-point sequences: U+0065 < U+00E9.
  lt('é', 'é', 'decomposed e + combining acute sorts before precomposed é');
  assert.notEqual(compareUnicodeCodePoints('é', 'é'), 0, 'canonically equivalent strings are still distinct');
  lt('10', '2', 'no natural/numeric sort: "10" sorts before "2" because U+0031 < U+0032');
  lt('10', '9', 'no natural/numeric sort: "10" sorts before "9"');
  lt('f', 'fi', 'prefix'); lt('fi', 'ﬁ', 'ASCII "fi" before the ligature U+FB01 (no compatibility folding)'); lt('f', 'ｆ', 'ASCII f before fullwidth ｆ U+FF46');
  lt('/a.txt', '/a/x.txt', '"." U+002E < "/" U+002F: whole paths, not path segments');
  // Equality and reflexivity.
  for (const s of ['', 'a', '/a.txt', '', '\u{10000}', 'é']) assert.equal(compareUnicodeCodePoints(s, s), 0);
  // The relation is exactly the canonical-JSON key order.
  assert.equal(canonicalJson({ '\u{10000}': 1, '': 2, 'a': 3, 'A': 4 }), '{"A":4,"a":3,"":2,"\u{10000}":1}');
});

const codePointOrder = (a, b) => { const x = Array.from(a, c => c.codePointAt(0)), y = Array.from(b, c => c.codePointAt(0)); for (let i = 0; i < Math.min(x.length, y.length); i++) if (x[i] !== y[i]) return x[i] - y[i]; return x.length - y.length; };

test('packDirectory orders complete artifact paths by Unicode code point on this host, independent of locale', async t => {
  const root = await mkdtemp(join(tmpdir(), 'owa-pack-order-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  // Deliberately scrambled creation order; portable names only: no case-only pairs
  // (case-insensitive filesystems), no canonically-equivalent pairs, no name whose
  // Unicode case folding lands on another fixture name (APFS folds the U+FB01 "ﬁ"
  // ligature onto "fi"), no Windows-forbidden characters. "①" (U+2460) and "ｆ"
  // (U+FF46) are compatibility look-alikes that stay distinct files everywhere.
  const names = ['\u{1F331}.txt', 'z.txt', '\u{10000}.txt', 'a/x.txt', '中.txt', 'index.html', '.txt', 'a.txt', 'Ω.txt', 'b.txt', '10.txt', '2.txt', '①.txt', 'fi.txt', 'ｆ.txt', 'f.txt'];
  for (const name of names) { await mkdir(dirname(join(root, name)), { recursive: true }); await writeFile(join(root, name), `${name}\n`); }
  const packed = await packDirectory(root);
  // Literal, hand-ordered expectation (not derived from production code).
  const expected = [
    '/10.txt', '/2.txt', '/a.txt', '/a/x.txt', '/b.txt', '/f.txt', '/fi.txt', '/index.html', '/z.txt',
    '/Ω.txt', '/①.txt', '/中.txt', '/.txt', '/ｆ.txt', '/\u{10000}.txt', '/\u{1F331}.txt'
  ];
  assert.equal(packed.manifest.files.length, names.length, 'every fixture name materialized as a distinct file');
  assert.deepEqual(packed.manifest.files.map(f => f.path), expected);
  // The same list, independently sorted by a test-local code-point comparator, agrees.
  assert.deepEqual([...expected].sort(codePointOrder), expected);
  // Default UTF-16 code-unit sorting would NOT produce this order (the anchor).
  assert.notDeepEqual([...expected].sort(), expected, 'default .sort() differs at U+E000 / U+FF46 vs U+10000');
  // Identical trees created in the opposite order pack to the identical artifact.
  const mirror = await mkdtemp(join(tmpdir(), 'owa-pack-order-mirror-'));
  t.after(() => rm(mirror, { recursive: true, force: true }));
  for (const name of [...names].reverse()) { await mkdir(dirname(join(mirror, name)), { recursive: true }); await writeFile(join(mirror, name), `${name}\n`); }
  const again = await packDirectory(mirror);
  assert.deepEqual(again.manifest, packed.manifest);
  assert.equal(again.artifactDigest, packed.artifactDigest);
  assert.equal(canonicalJson(again.manifest), canonicalJson(packed.manifest));
  // Exact strings: nothing was normalized or folded.
  for (const name of names) assert.ok(packed.manifest.files.some(f => f.path === `/${name}`), `${name} preserved exactly`);
});

test('producer ordering is not a manifest rule: validation accepts any order and canonicalization preserves it', () => {
  const file = path => ({ path, digest: `sha256:${'0'.repeat(64)}`, size: 0, mediaType: 'text/plain' });
  const base = { specVersion: 'owa.dev/v1', artifactType: 'application/vnd.openwebartifact.site.v1+json', entrypoint: '/index.html' };
  const sorted = { ...base, files: [file('/a.txt'), file('/index.html'), file('/.txt'), file('/\u{10000}.txt')] };
  const unsorted = { ...base, files: [file('/\u{10000}.txt'), file('/index.html'), file('/.txt'), file('/a.txt')] };
  assert.doesNotThrow(() => validateManifest(unsorted), 'a manually authored manifest need not be sorted');
  assert.doesNotThrow(() => validateManifest(sorted));
  assert.notEqual(canonicalJson(sorted), canonicalJson(unsorted), 'canonicalization preserves array order, so these are different artifacts');
  assert.deepEqual(JSON.parse(canonicalJson(unsorted)).files.map(f => f.path), ['/\u{10000}.txt', '/index.html', '/.txt', '/a.txt'], 'canonical JSON did not sort files');
});
