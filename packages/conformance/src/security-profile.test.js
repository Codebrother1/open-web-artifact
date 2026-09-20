import test from 'node:test';
import assert from 'node:assert/strict';
import { artifactDigest, canonicalJson, OWA_MEDIA_TYPE, OWA_SPEC_VERSION, sha256, validateManifest } from '../../spec/src/index.js';
import { artifactHeaders, PROFILE_CSP, PROFILE_NAME, securityHeaders } from '../../server/src/security-profile.js';

// These tests establish response-header logic only, not browser enforcement.
const EXPECTED_CSP = "sandbox; default-src 'none'; script-src 'none'; style-src 'unsafe-inline'; img-src data:; connect-src 'none'; font-src 'none'; media-src 'none'; object-src 'none'; frame-src 'none'; worker-src 'none'; form-action 'none'; frame-ancestors 'none'; base-uri 'none'";
const EXPECTED_HEADERS = {
  'content-security-policy': EXPECTED_CSP,
  'x-content-type-options': 'nosniff',
  'referrer-policy': 'no-referrer',
  'x-robots-tag': 'noindex, nofollow, noarchive',
  'cache-control': 'no-store',
  'x-frame-options': 'DENY',
  'x-dns-prefetch-control': 'off',
  'x-owa-security-profile': 'sandboxed-web-v1'
};
const APPROVED_TYPES = [
  'text/html', 'text/plain', 'text/javascript', 'application/javascript',
  'text/css', 'application/json', 'application/wasm', 'image/svg+xml',
  'image/png', 'image/jpeg', 'image/gif', 'image/webp', 'image/avif',
  'image/x-icon', 'image/vnd.microsoft.icon'
];

function assertInline(mediaType) {
  assert.deepEqual(artifactHeaders(mediaType), {
    ...EXPECTED_HEADERS,
    'content-type': mediaType,
    'content-disposition': 'inline'
  }, JSON.stringify(mediaType));
}

function assertAttachment(mediaType) {
  assert.deepEqual(artifactHeaders(mediaType), {
    ...EXPECTED_HEADERS,
    'content-type': 'application/octet-stream',
    'content-disposition': 'attachment'
  }, typeof mediaType === 'string' ? JSON.stringify(mediaType) : typeof mediaType);
}

test('security profile name, exact CSP, and lowercase response headers are fixed', () => {
  assert.equal(PROFILE_NAME, 'sandboxed-web-v1');
  assert.equal(PROFILE_CSP, EXPECTED_CSP);
  assert.deepEqual(securityHeaders(), EXPECTED_HEADERS);
  assert.equal(Object.getPrototypeOf(securityHeaders()), Object.prototype);
  assert.ok(Object.keys(securityHeaders()).every(key => key === key.toLowerCase()));
  const directives = PROFILE_CSP.split('; ');
  assert.equal(directives[0], 'sandbox');
  assert.equal(directives.length, 14);
  assert.doesNotMatch(PROFILE_CSP, /allow-|\bself\b|https?:|blob:|\*/);
  assert.equal(directives.filter(value => value.includes('unsafe-inline')).length, 1);
});

test('header objects are fresh plain objects and response mutation cannot change policy', () => {
  const baseline = securityHeaders();
  const inline = artifactHeaders('text/html');
  const download = artifactHeaders('application/octet-stream');
  for (const [headers, fresh] of [
    [baseline, securityHeaders()],
    [inline, artifactHeaders('text/html')],
    [download, artifactHeaders('application/octet-stream')]
  ]) {
    assert.notEqual(headers, fresh);
    assert.equal(Object.getPrototypeOf(headers), Object.prototype);
    assert.ok(Object.keys(headers).every(key => key === key.toLowerCase()));
    assert.ok(Object.values(headers).every(value => typeof value === 'string'));
    headers['content-security-policy'] = "script-src *";
    headers['cache-control'] = 'public';
    headers['content-type'] = 'text/html';
    headers['content-disposition'] = 'inline; filename=evil.html';
    headers['x-extra'] = 'mutable';
    delete headers['x-robots-tag'];
    assert.equal(fresh['content-security-policy'], EXPECTED_CSP);
    assert.equal(fresh['cache-control'], 'no-store');
    assert.equal(fresh['x-robots-tag'], EXPECTED_HEADERS['x-robots-tag']);
    assert.equal(fresh['x-extra'], undefined);
  }
  assert.deepEqual(securityHeaders(), EXPECTED_HEADERS);
  assertInline('text/html');
  assertAttachment('application/octet-stream');
});

test('all 15 explicit approved essences preserve exact case, spacing, and parameters', () => {
  for (const essence of APPROVED_TYPES) {
    for (const mediaType of [
      essence,
      essence.toUpperCase(),
      `${essence}; charset=utf-8`,
      `${essence.toUpperCase()}  ;  CHARSET="Utf-8" ; note="a;b/c"`
    ]) assertInline(mediaType);
  }
});

const VALID_PARAMETERS = [
  'text/html;charset=utf-8;v=1',
  'TeXt/HtMl; ChArSeT="UTF-8"',
  'text/html ;charset=utf-8; version=1',
  'text/plain  ; note="space = inside quotes" ; charset=utf-8',
  'text/plain; empty=""',
  'text/html; note="; charset=evil; / = , () [] {} : @ ?"; charset=utf-8',
  'text/html; note="charset=x; charset=y"',
  'text/html; note="trailing space "',
  'text/html; note=" leading space"',
  'text/html; note="a/b"',
  'text/html; __proto__=a; constructor=b; toString=c',
  "text/html; !#$%&'*+-.^_`|~=!#$%&'*+-.^_`|~012aZ",
  String.raw`text/html; note="escaped \" quote"; charset=utf-8`,
  String.raw`text/html; note="escaped \\ backslash"`,
  String.raw`text/html; note="escaped \; semicolon and \/ slash and \  space"`,
  String.raw`text/html; note="\q"`
];

test(`valid parameter grammar preserves the entire value (${VALID_PARAMETERS.length} cases)`, () => {
  for (const mediaType of VALID_PARAMETERS) assertInline(mediaType);
});

test('quoted values accept every printable ASCII character, including valid quoted pairs', () => {
  for (let code = 0x20; code <= 0x7e; code++) {
    const character = String.fromCharCode(code);
    assertInline(`text/html; note="\\${character}"`);
    if (character !== '"' && character !== '\\') assertInline(`text/html; note="${character}"`);
  }
});

const UNAPPROVED_TYPES = [
  'application/octet-stream', 'APPLICATION/OCTET-STREAM; name="index.html"',
  'application/xml', 'text/xml; charset=utf-8', 'application/xhtml+xml',
  'application/pdf', 'image/bmp', 'image/tiff', 'image/heic', 'image/jxl',
  'image/svg', 'image/svg+xmlz', 'image/x-png', 'image/jpg', 'text/csv',
  'text/markdown', 'application/ecmascript', 'application/x-javascript',
  'application/ld+json', 'application/vnd.test+json', 'font/woff', 'font/woff2',
  'audio/mpeg', 'video/mp4', 'multipart/mixed; boundary=abc',
  'message/rfc822', 'application/zip', 'text/*', 'image/*', '*/*',
  'text/html+evil', 'x-text/html', 'application/x-httpd-php'
];

test(`unapproved types never inherit a wildcard or suffix allowance (${UNAPPROVED_TYPES.length} cases)`, () => {
  for (const mediaType of UNAPPROVED_TYPES) assertAttachment(mediaType);
});

const MALFORMED_TYPES = [
  '', ' ', ' text/html', 'text/html ', 'text/html; charset=utf-8 ',
  'text/html; note="ok" ', 'text', '/html', 'text/', 'text//html',
  'text /html', 'text/ html', 'text/html/extra', 'text\\html',
  'text/html, text/plain', 'text/html#fragment', 'text/html?x=y',
  'text/html (comment)', 'text/html;charset=utf-8(comment)',
  'text/html;', 'text/html; ', 'text/html;;charset=utf-8',
  'text/html; =utf-8', 'text/html; charset', 'text/html; charset=',
  'text/html; charset= ', 'text/html; charset==utf-8',
  'text/html; charset =utf-8', 'text/html; charset= utf-8',
  'text/html; CHARSET = "Utf-8"',
  'text/html ;charset =utf-8; version= 1',
  'TEXT/HTML  ;  CHARSET = "Utf-8" ; note = "a;b/c"',
  'TeXt/HtMl  ; CHARSET = "UtF-8"; note="a;b"',
  'text/plain; note="a;b"; charset = utf-8',
  'text/html; "charset"=utf-8', 'text/html; char set=utf-8',
  'text/html; char/set=utf-8', 'text/html; charset=utf 8',
  'text/html; charset=utf-8 garbage', 'text/html; charset=utf/8',
  'text/html; charset=[utf-8]', 'text/html; charset=(utf-8)',
  'text/html; charset=utf:8', 'text/html; charset=utf@8',
  'text/html; charset=utf,8', 'text/html; charset=utf?8',
  'text/html; charset="utf-8', 'text/html; charset="utf-8"junk',
  'text/html; charset="utf-8""', 'text/html; charset="utf-8"next=x',
  'text/html; charset=utf-8; charset=utf-8',
  'text/html; CHARSET=utf-8; charset=latin1',
  'text/html; note="a;b"; NOTE="c"',
  'text/html; charset="a;still quoted"; charset=b',
  'text/html; note="closed"; charset=utf-8; CHARSET=latin1',
  'text/html; __proto__=x; __PROTO__=y',
  'text/html\r\nX-Evil: injected',
  'text/html; note="x\r\nContent-Type: text/html"',
  String.raw`text/html; note=unquoted\escape`,
  'text/html; note="unterminated\\',
  String.raw`text/html; note="escaped closing quote\"`,
  String.raw`text/html; note="valid\\"junk`
];

test(`malformed MIME is rejected without prefix acceptance or repair (${MALFORMED_TYPES.length} cases)`, () => {
  for (const mediaType of MALFORMED_TYPES) assertAttachment(mediaType);
});

function insertions(character) {
  return [
    `${character}text/html`, `text/html${character}`, `te${character}xt/html`,
    `text/ht${character}ml`, `text/html; na${character}me=x`,
    `text/html; note=x${character}y`, `text/html; note="x${character}y"`,
    `text/html; note="x\\${character}y"`
  ];
}
const CONTROLS = [...Array.from({ length: 32 }, (_, code) => String.fromCharCode(code)), '\x7f'];
const NON_ASCII = ['\x80', '\x85', '\x9f', '\xa0', 'é', 'ÿ', 'İ', 'ſ', '\u200b', '\u2028', '\u2029', '\uff1b', '\uff0f', '💣', '\ud800'];

test(`all ASCII controls are rejected in every grammar context (${CONTROLS.length * 8} cases)`, () => {
  for (const character of CONTROLS) {
    for (const mediaType of insertions(character)) assertAttachment(mediaType);
  }
});

test(`non-ASCII is rejected before case folding or quoted-pair parsing (${NON_ASCII.length * 8} cases)`, () => {
  for (const character of NON_ASCII) {
    for (const mediaType of insertions(character)) assertAttachment(mediaType);
  }
});

test('non-string values fall back without coercion, property access, or byte sniffing', () => {
  const trap = new Proxy({}, { get() { throw new Error('must not inspect input'); } });
  for (const mediaType of [
    undefined, null, false, 0, 1n, Symbol('text/html'), {}, [],
    ['text/html'], new String('text/html'), Buffer.from('text/html'),
    new Uint8Array([0x3c, 0x68, 0x31, 0x3e]), () => 'text/html', trap
  ]) assertAttachment(mediaType);
});

test('dispatch uses only manifest MIME, not the path or a filename argument', () => {
  assert.equal(artifactHeaders.length, 1);
  for (const path of ['/index.html', '/image.png', '/script.js', '/payload.pdf', '/unknown.bin', '/no-extension']) {
    for (const mediaType of APPROVED_TYPES) {
      const file = Object.freeze({ path, mediaType });
      assertInline(file.mediaType);
    }
    const disguised = Object.freeze({ path, mediaType: 'application/pdf' });
    assertAttachment(disguised.mediaType);
  }
  const file = { mediaType: 'image/svg+xml', get path() { throw new Error('path must not be read'); } };
  assertInline(file.mediaType);
  // A metadata object is not an overloaded filename/MIME API.
  assertAttachment(file);
});

test('policy selection preserves canonical manifest bytes, identity, metadata, and blob bytes', () => {
  const bytes = new Uint8Array(Buffer.from('<!doctype html><script>untrusted()</script>\x00\xff', 'latin1'));
  const originalBytes = bytes.slice();
  const digest = sha256(bytes);
  const files = Object.freeze([
    Object.freeze({ path: '/index.bin', digest, size: bytes.byteLength, mediaType: 'TeXt/HtMl  ; CHARSET="UtF-8"; note="a;b"' }),
    Object.freeze({ path: '/unsafe.html', digest, size: bytes.byteLength, mediaType: 'text/html\r\nX-Evil: yes' }),
    Object.freeze({ path: '/blank.html', digest, size: bytes.byteLength, mediaType: '   ' }),
    Object.freeze({ path: '/download.html', digest, size: bytes.byteLength, mediaType: 'application/pdf; name="a.html"' })
  ]);
  const manifest = Object.freeze({
    specVersion: OWA_SPEC_VERSION, artifactType: OWA_MEDIA_TYPE,
    entrypoint: '/index.bin', files
  });
  const before = structuredClone(manifest);
  const canonicalBytes = Buffer.from(canonicalJson(manifest), 'utf8');
  const identity = artifactDigest(manifest);
  assert.equal(validateManifest(manifest), manifest);
  assertInline(files[0].mediaType);
  for (const file of files.slice(1)) assertAttachment(file.mediaType);
  assert.deepEqual(manifest, before);
  assert.deepEqual(Buffer.from(canonicalJson(manifest), 'utf8'), canonicalBytes);
  assert.equal(artifactDigest(manifest), identity);
  assert.deepEqual(bytes, originalBytes);
  assert.equal(sha256(bytes), digest);
  assert.equal(validateManifest(manifest), manifest);
});
