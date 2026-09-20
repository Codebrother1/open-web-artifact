import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

const docs = new URL('../../../docs/', import.meta.url);
const load = async name => JSON.parse(await readFile(new URL(name, docs), 'utf8'));
const schema = await load('manifest.schema.json');
const { vectors: paths } = await load('conformance/v0.2/path.json');
const { vectors: manifests } = await load('conformance/v0.2/manifest.json');
const { artifactPath, digest, file } = schema.$defs;

// Focused checks of the published scalar constraints, not a JSON Schema engine.
// No production validator/canonicalizer is imported. Cross-field file membership
// and duplicate-path rules are deliberately not schema-only rejection criteria.
function matchesString(value, rule) {
  assert.equal(rule.type, 'string');
  return typeof value === 'string'
    && (rule.minLength === undefined || [...value].length >= rule.minLength)
    && (rule.maxLength === undefined || [...value].length <= rule.maxLength)
    && new RegExp(rule.pattern).test(value);
}

function scalarVectors(category) {
  return manifests.filter(vector => !vector.expected.errorCategory || vector.expected.errorCategory === category);
}

test('schema artifactPath type and pattern match every standalone path fixture', () => {
  for (const vector of paths) {
    assert.equal(matchesString(vector.input, artifactPath), !vector.expected.errorCategory, vector.id);
  }
});

test('schema artifactPath covers manifest file, entrypoint and fallback fixtures', () => {
  for (const vector of scalarVectors('OWA_INVALID_PATH')) {
    const manifest = JSON.parse(vector.inputJson);
    const values = [manifest.entrypoint, ...manifest.files.map(item => item.path)];
    if (Object.hasOwn(manifest.routing ?? {}, 'spaFallback')) values.push(manifest.routing.spaFallback);
    assert.equal(values.every(value => matchesString(value, artifactPath)), !vector.expected.errorCategory, vector.id);
  }
});

test('schema artifactPath handles generated segments, literal newlines and absolute end anchors', () => {
  const good = ['a', '...', '.a', 'a.', '%2e%2e', '%2f', 'a?b#c', 'é', '\n', 'a\nb', '.\n', '..\n', '\r', '\u2028'];
  const bad = ['', '.', '..', '/', '\\', '\0', 'a\0b', 'a\\b'];
  const segments = [...good.map(value => [value, true]), ...bad.map(value => [value, false])];
  for (const [left, leftValid] of segments) {
    assert.equal(matchesString(`/${left}`, artifactPath), leftValid, JSON.stringify(left));
    for (const [right, rightValid] of segments) {
      const value = `/${left}/${right}`;
      assert.equal(matchesString(value, artifactPath), leftValid && rightValid, JSON.stringify(value));
    }
  }
  for (const value of ['/a\n', '/.\n', '/..\n', '/a/\n']) assert.equal(matchesString(value, artifactPath), true);
  for (const value of ['/a\n/', '/a/./\n', '/a/../\n', '/a\0\n', '\n/a', null, 3, false, ['/a'], {}]) {
    assert.equal(matchesString(value, artifactPath), false, JSON.stringify(value));
  }
});

test('schema digest type, exact length and pattern match valid and malformed corpus digests', () => {
  assert.equal(digest.minLength, 71);
  assert.equal(digest.maxLength, 71);
  for (const vector of scalarVectors('OWA_INVALID_DIGEST')) {
    const manifest = JSON.parse(vector.inputJson);
    assert.equal(manifest.files.every(item => matchesString(item.digest, digest)), !vector.expected.errorCategory, vector.id);
    if (vector.expected.artifactDigest) assert.equal(matchesString(vector.expected.artifactDigest, digest), true, vector.id);
  }
});

test('schema digest rejects trailing LF and wrong lengths without coercion', () => {
  const valid = `sha256:${'a'.repeat(64)}`;
  assert.equal(matchesString(valid, digest), true);
  for (const length of [0, 1, 63, 65, 128]) {
    assert.equal(matchesString(`sha256:${'a'.repeat(length)}`, digest), false);
  }
  for (const value of [`${valid}\n`, `${valid}\r\n`, `${valid}\0`, ` ${valid}`, valid.toUpperCase(),
    `sha256:${'g'.repeat(64)}`, `sha512:${'a'.repeat(64)}`, null, false, 71, [valid], {}]) {
    assert.equal(matchesString(value, digest), false, JSON.stringify(value));
  }
});

test('schema size bounds match the safe-integer maximum and positive/negative corpus', () => {
  const size = file.properties.size;
  assert.deepEqual(size, { type: 'integer', minimum: 0, maximum: 9007199254740991 });
  const maximum = manifests.find(vector => vector.id === 'manifest-maximum-size');
  assert.equal(JSON.parse(maximum.inputJson).files[0].size, size.maximum);
  const matchesSize = value => Number.isInteger(value) && value >= size.minimum && value <= size.maximum;
  for (const vector of scalarVectors('OWA_INVALID_SIZE')) {
    assert.equal(JSON.parse(vector.inputJson).files.every(item => matchesSize(item.size)), !vector.expected.errorCategory, vector.id);
  }
  assert.equal(matchesSize(size.maximum + 1), false);
});

test('published object shapes, constants and references remain explicit', () => {
  assert.equal(schema.type, 'object');
  assert.equal(schema.additionalProperties, false);
  assert.deepEqual(schema.required, ['specVersion', 'artifactType', 'entrypoint', 'files']);
  assert.deepEqual(schema.properties.specVersion, { const: 'owa.dev/v1' });
  assert.deepEqual(schema.properties.artifactType, { const: 'application/vnd.openwebartifact.site.v1+json' });
  assert.deepEqual(schema.properties.entrypoint, { $ref: '#/$defs/artifactPath' });
  assert.deepEqual(schema.properties.files, { type: 'array', minItems: 1, items: { $ref: '#/$defs/file' } });
  assert.equal(file.type, 'object');
  assert.equal(file.additionalProperties, false);
  assert.deepEqual(file.required, ['path', 'digest', 'size', 'mediaType']);
  assert.deepEqual(file.properties.path, { $ref: '#/$defs/artifactPath' });
  assert.deepEqual(file.properties.digest, { $ref: '#/$defs/digest' });
  assert.deepEqual(file.properties.mediaType, { type: 'string', minLength: 1 });
});

test('schema expiry lexical pattern covers portable timestamps and rejects malformed strings', () => {
  const rule = schema.properties.lifecycle.properties.expiresAt;
  assert.equal(typeof rule.pattern, 'string');
  const pattern = new RegExp(rule.pattern);
  for (const vector of manifests.filter(item => !item.expected.errorCategory)) {
    const value = JSON.parse(vector.inputJson).lifecycle?.expiresAt;
    if (typeof value === 'string') assert.equal(pattern.test(value), true, vector.id);
  }
  for (const value of ['2026-09-20', '2026-09-20T12:00:00', '2026-09-20 12:00:00Z',
    '2026-13-20T12:00:00Z', '2026-09-32T12:00:00Z', '2026-09-20T24:00:00Z',
    '2026-09-20T12:60:00Z', '2026-09-20T12:00:60Z', '2026-09-20T12:00:00+24:00',
    '2026-09-20T12:00:00+00:60', '2026-09-20T12:00:00.Z', '2026-09-20T12:00:00Z\n']) {
    assert.equal(pattern.test(value), false, JSON.stringify(value));
  }
  // Calendar validity remains a required semantic/format assertion, not just regex.
  assert.equal(pattern.test('2025-02-29T12:00:00Z'), true);
});

test('published optional-object, enum and scalar-annotation constraints remain unchanged', () => {
  assert.deepEqual(schema.properties.routing, {
    type: 'object', properties: { spaFallback: { $ref: '#/$defs/artifactPath' } }, additionalProperties: false
  });
  assert.deepEqual(schema.properties.access, {
    type: 'object', properties: { visibility: { enum: ['public', 'unlisted'] } }, additionalProperties: false
  });
  assert.deepEqual(schema.properties.annotations, {
    type: 'object', additionalProperties: { type: ['string', 'number', 'boolean', 'null'] }
  });
  const lifecycle = schema.properties.lifecycle;
  assert.equal(lifecycle.type, 'object');
  assert.equal(lifecycle.additionalProperties, false);
  assert.deepEqual(lifecycle.required ?? [], []);
  assert.deepEqual(Object.keys(lifecycle.properties), ['expiresAt']);
  assert.deepEqual(lifecycle.properties.expiresAt.type, ['string', 'null']);
  assert.equal(lifecycle.properties.expiresAt.format, 'date-time');
  // Calendar validity belongs to the expiry fixtures, not this deliberately
  // limited scalar checker; the lexical pattern is exercised below.
  for (const name of ['routing', 'access', 'lifecycle', 'annotations']) {
    assert.equal(schema.required.includes(name), false, `${name} remains optional`);
  }
});
