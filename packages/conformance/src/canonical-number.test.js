import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { canonicalJson } from '../../spec/src/index.js';

// Canonical binary64 number serialization (spec-v0.2.md rule 5; issue #38).
// The static corpus (docs/conformance/v0.2/canonical.json, canonical-b64-*) is
// the cross-language oracle and pins exact bytes. This file proves PROPERTIES
// the static strings do not state explicitly, on this host:
//   - every canonical number text re-parses to the identical binary64 bits
//     (signed zero is the one deliberate exception: both zeros become "0");
//   - the canonical grammar: no "-0", no "+" sign, no leading zeros, no
//     trailing fractional zeros, no bare or trailing ".", scientific notation
//     has one digit before the point, a lowercase e, an explicit sign and no
//     zero padding, and no other exponent spelling exists;
//   - fixed notation exactly for 1e-6 <= |v| < 1e21, scientific otherwise;
//   - negation symmetry: canonical(-x) is "-" + canonical(x) for nonzero x.
// Expectations are never taken from another implementation; a deterministic
// xorshift32 stream (seed 0x4f574132, 4096 finite bit patterns) supplements the
// hand-picked corpus values. No Go code runs here.

const corpus = JSON.parse(await readFile(new URL('../../../docs/conformance/v0.2/canonical.json', import.meta.url), 'utf8'));
const rootNumberVectors = corpus.vectors.filter(vector => /^-?[0-9]/.test(vector.inputJson) && Object.hasOwn(vector.expected, 'canonicalJson'));
assert.ok(rootNumberVectors.length >= 80, `expected the binary64 anchors to be present, found ${rootNumberVectors.length} root-number vectors`);

// The complete canonical number grammar: exactly one of these shapes.
const CANONICAL_NUMBER = /^(?:0|-?(?:[1-9][0-9]*(?:\.[0-9]*[1-9])?|0\.[0-9]*[1-9]|[1-9](?:\.[0-9]*[1-9])?e[+-][1-9][0-9]*))$/;

const view = new DataView(new ArrayBuffer(8));
function bits(x) { view.setFloat64(0, x); return view.getBigUint64(0); }
function fromBits(b) { view.setBigUint64(0, b); return view.getFloat64(0); }

function assertCanonicalProperties(x, text, label) {
  assert.match(text, CANONICAL_NUMBER, `${label}: canonical grammar`);
  assert.ok(!/[E+]/.test(text.replace(/e[+-]/, '')), `${label}: no uppercase E or stray sign`);
  const reparsed = JSON.parse(text);
  if (x === 0) {
    assert.equal(text, '0', `${label}: both signed zeros serialize as 0`);
    assert.ok(Object.is(reparsed, 0), `${label}: 0 re-parses as positive zero`);
  } else {
    assert.equal(bits(reparsed), bits(x), `${label}: re-parses to the identical binary64 (${bits(x).toString(16)})`);
    assert.equal(canonicalJson(-x), `-${canonicalJson(x)}`.replace('--', ''), `${label}: negation symmetry`);
    const magnitude = Math.abs(x);
    const scientific = text.includes('e');
    assert.equal(scientific, magnitude < 1e-6 || magnitude >= 1e21, `${label}: fixed iff 1e-6 <= |v| < 1e21 (got ${text})`);
    if (scientific) {
      const exponent = Number(text.slice(text.indexOf('e') + 1));
      assert.ok(exponent >= 21 || exponent <= -7, `${label}: scientific exponent ${exponent} is outside the fixed range`);
      assert.match(text.slice(text.indexOf('e') + 1), /^[+-][1-9][0-9]*$/, `${label}: explicit sign, no zero padding`);
    }
  }
  // Idempotence: canonicalizing the re-parsed value gives the same text.
  assert.equal(canonicalJson(reparsed), text, `${label}: idempotent`);
}

test('every corpus number vector re-parses to the same binary64 and matches the canonical grammar', () => {
  for (const vector of rootNumberVectors) {
    const x = JSON.parse(vector.inputJson);
    assert.ok(Number.isFinite(x), `${vector.id}: finite`);
    assert.equal(canonicalJson(x), vector.expected.canonicalJson, `${vector.id}: corpus expectation`);
    assertCanonicalProperties(x, vector.expected.canonicalJson, vector.id);
  }
});

test('the corpus expectations themselves are independent of this implementation: expected strings re-parse to the input token value', () => {
  // A static check of the fixtures, not of canonicalJson: the frozen expected
  // text must denote the same binary64 as the input token it was authored for.
  for (const vector of rootNumberVectors) {
    const input = JSON.parse(vector.inputJson), expected = JSON.parse(vector.expected.canonicalJson);
    if (input === 0) assert.ok(Object.is(expected, 0), vector.id);
    else assert.equal(bits(expected), bits(input), `${vector.id}: expected text denotes the input's binary64`);
  }
});

test('hard boundaries by bit pattern: subnormal/normal edges, threshold neighbours, shortest-digit ties, integer edges', () => {
  // Hand-written from the rule; hex bit patterns are the identity under test.
  const cases = [
    ['0x0000000000000001', '5e-324'], ['0x0000000000000002', '1e-323'], ['0x000fffffffffffff', '2.225073858507201e-308'],
    ['0x0010000000000000', '2.2250738585072014e-308'], ['0x0010000000000001', '2.225073858507202e-308'],
    ['0x7fefffffffffffff', '1.7976931348623157e+308'], ['0xffefffffffffffff', '-1.7976931348623157e+308'],
    ['0x3eb0c6f7a0b5ed8c', '9.999999999999997e-7'], ['0x3eb0c6f7a0b5ed8d', '0.000001'], ['0x3eb0c6f7a0b5ed8e', '0.0000010000000000000002'],
    ['0x444b1ae4d6e2ef4f', '999999999999999900000'], ['0x444b1ae4d6e2ef50', '1e+21'], ['0x444b1ae4d6e2ef51', '1.0000000000000001e+21'],
    ['0x4310000000000001', '1125899906842624.2'], ['0x4310000000000003', '1125899906842624.8'], ['0xc310000000000001', '-1125899906842624.2'],
    ['0x433fffffffffffff', '9007199254740991'], ['0x4340000000000000', '9007199254740992'], ['0x43e0000000000000', '9223372036854776000'],
    ['0x3fb999999999999a', '0.1'], ['0x3fd3333333333334', '0.30000000000000004'], ['0x44b52d02c7e14af6', '1e+23'],
    ['0x0000000000000000', '0'], ['0x8000000000000000', '0']
  ];
  for (const [hex, expected] of cases) {
    const x = fromBits(BigInt(hex));
    assert.equal(canonicalJson(x), expected, hex);
    assertCanonicalProperties(x, expected, hex);
  }
});

test('deterministic seeded binary64 patterns (xorshift32, seed 0x4f574132, 4096 finite values) round-trip and obey the grammar', () => {
  let state = 0x4f574132 >>> 0;
  const next = () => { state ^= state << 13; state >>>= 0; state ^= state >>> 17; state ^= state << 5; state >>>= 0; return state; };
  let checked = 0, subnormals = 0, scientific = 0;
  while (checked < 4096) {
    const hi = BigInt(next()), lo = BigInt(next());
    let b = (hi << 32n) | lo;
    // Spread the exponent across the whole finite range rather than the uniform
    // 2^64 distribution: replace the exponent field with a seeded value.
    const exponent = BigInt(next() % 0x7ff); // 0..0x7fe (never 0x7ff: non-finite)
    b = (b & ~(0x7ffn << 52n)) | (exponent << 52n);
    const x = fromBits(b);
    assert.ok(Number.isFinite(x));
    const text = canonicalJson(x);
    assertCanonicalProperties(x, text, `seeded #${checked} bits 0x${b.toString(16)}`);
    checked++;
    if (exponent === 0n && x !== 0) subnormals++;
    if (text.includes('e')) scientific++;
  }
  assert.equal(checked, 4096);
  assert.ok(subnormals > 0 && scientific > 0, 'the seeded stream covers subnormals and scientific notation');
});
