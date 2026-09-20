import test from 'node:test';
import assert from 'node:assert/strict';
import { createHmac } from 'node:crypto';
import { AuthError, CAPABILITIES, createAuthorizer, createToken, isLoopback, isSiteScope, verifyToken } from '../../server/src/auth.js';

// Fixed synthetic bytes constructed at runtime; never check in or print bearer
// tokens. Token/key comparisons use boolean assertions to prevent secret diffs.
const secret = Buffer.from(Array.from({ length: 32 }, (_, i) => i + 33));
const otherSecret = Buffer.from(Array.from({ length: 32 }, (_, i) => i + 97));
const NOW = 1700000000;
const now = () => NOW;
const baseClaims = () => ({ v: 1, jti: 'operator-audit_001', exp: NOW + 60, sites: ['demo'], capabilities: ['read'] });
const mint = (overrides = {}) => createToken({ ...baseClaims(), secret, now, ...overrides });
const verify = (token, overrides = {}) => verifyToken(token, { secret, now, ...overrides });
const request = (token, extras = {}) => ({ headers: { authorization: `Bearer ${token}` }, socket: { remoteAddress: '127.0.0.1' }, ...extras });

function expectAuth(fn, code, status = 401) {
  let caught;
  try { fn(); } catch (error) { caught = error; }
  assert.ok(caught instanceof AuthError, 'expected a safe AuthError');
  assert.ok(caught.code === code, `expected ${code}`);
  assert.ok(caught.status === status, `expected status ${status}`);
  assert.ok(typeof caught.message === 'string' && caught.message.length > 0, 'safe message is present');
  assert.ok(!Object.hasOwn(caught, 'cause'), 'error must not retain its cause');
  return caught;
}

// Independent wire-format oracle: no module helpers, artifact canonicalizer, or
// checked-in signed values. Each invocation signs its supplied raw payload bytes.
function oracle(payload, key = secret) {
  const segment = Buffer.from(payload).toString('base64url');
  const input = Buffer.from(`owa1.${segment}`, 'ascii');
  const mac = createHmac('sha256', key).update(input).digest('base64url');
  return `owa1.${segment}.${mac}`;
}

function replaceSignature(token, signature) {
  return `${token.split('.').slice(0, 2).join('.')}.${signature}`;
}

test('capability vocabulary is exact and frozen', () => {
  assert.deepEqual(CAPABILITIES, ['plan', 'upload', 'commit', 'activate', 'read']);
  assert.ok(Object.isFrozen(CAPABILITIES));
  assert.throws(() => CAPABILITIES.push('admin'), TypeError);
});

test('site scopes use exact lower-ASCII grammar and length limits', () => {
  for (const site of ['a', '0', 'site-1_a', 'a'.repeat(63)]) assert.ok(isSiteScope(site));
  for (const site of ['', '*', 'demo*', 'Demo', '-demo', '_demo', 'a'.repeat(64), 'démo', 'demo/child', '../demo', ' demo', 'demo ', 'demo\n', 'demo\r', 'demo\0', 'demo.example', null, 123]) {
    assert.ok(!isSiteScope(site), 'invalid site scope rejected');
  }
});

test('loopback detection accepts only supported actual socket address forms', () => {
  for (const address of ['127.0.0.1', '127.0.0.0', '127.255.255.255', '127.1.2.3', '::1', '::ffff:127.2.3.4', '::FFFF:127.0.0.1']) assert.ok(isLoopback(address));
  for (const address of ['localhost', '127.1', '127.0.0.01', '127.0.0.256', '128.0.0.1', '10.0.0.1', '0.0.0.0', '::', '::ffff:10.0.0.1', '::ffff:127.1', '[::1]', '::1%lo', '127.0.0.1:80', '127.0.0.1\n', '', null, undefined, 127]) {
    assert.ok(!isLoopback(address), 'non-loopback or malformed address rejected');
  }
});

test('minting is deterministic, sorts copied arrays, and matches independent signing-input oracle', () => {
  const sites = ['zeta', 'alpha'];
  const capabilities = ['upload', 'read', 'plan', 'commit', 'activate'];
  const token = mint({ sites, capabilities });
  const payload = `{"v":1,"jti":"operator-audit_001","exp":${NOW + 60},"sites":["alpha","zeta"],"capabilities":["activate","commit","plan","read","upload"]}`;
  assert.ok(token === oracle(payload), 'wire bytes and HMAC signing input match oracle');
  assert.ok(token === mint({ sites: [...sites].reverse(), capabilities: [...capabilities].reverse() }), 'identical claims mint identical tokens');
  assert.deepEqual(sites, ['zeta', 'alpha']);
  assert.deepEqual(capabilities, ['upload', 'read', 'plan', 'commit', 'activate']);
  const parts = token.split('.');
  assert.ok(parts.length === 3 && parts[0] === 'owa1');
  assert.ok(parts.every(part => !part.includes('=')), 'no base64 padding');
  assert.ok(Buffer.from(parts[2], 'base64url').length === 32, 'SHA-256 MAC has fixed length');
  assert.ok(Buffer.from(parts[1], 'base64url').toString('utf8') === payload, 'fixed JSON field order');
  assert.ok(token !== oracle(payload, otherSecret), 'separate signing keys produce distinct tokens');
});

test('verification returns only validated claims and explicit audit jti', () => {
  const result = verify(mint());
  assert.deepEqual(result, baseClaims());
  assert.deepEqual(Object.keys(result), ['v', 'jti', 'exp', 'sites', 'capabilities']);
  assert.equal(result.jti, 'operator-audit_001');
  result.sites.push('other');
  assert.deepEqual(verify(mint()).sites, ['demo']);
});

test('independently minted wire token verifies without calling createToken', () => {
  const expected = baseClaims();
  assert.deepEqual(verify(oracle(JSON.stringify(expected))), expected);
});

test('claim bounds accept 64 sites, five capabilities, 128 audit characters and maximum safe expiry', () => {
  const sites = Array.from({ length: 64 }, (_, i) => `s${String(i).padStart(2, '0')}${'a'.repeat(60)}`);
  const token = mint({ sites, capabilities: [...CAPABILITIES], jti: 'J'.repeat(128), exp: Number.MAX_SAFE_INTEGER });
  assert.ok(token.length <= 8192);
  const claims = verify(token);
  assert.equal(claims.sites.length, 64);
  assert.equal(claims.capabilities.length, 5);
  assert.equal(claims.jti.length, 128);
  assert.equal(claims.exp, Number.MAX_SAFE_INTEGER);
});

const invalidClaims = [
  ['missing audit identifier', { jti: undefined }],
  ['empty audit identifier', { jti: '' }],
  ['overlong audit identifier', { jti: 'a'.repeat(129) }],
  ['non-ASCII audit identifier', { jti: 'audít' }],
  ['audit identifier newline', { jti: 'audit\n' }],
  ['audit identifier punctuation', { jti: 'audit.1' }],
  ['non-string audit identifier', { jti: 123 }],
  ['empty sites', { sites: [] }],
  ['duplicate sites', { sites: ['demo', 'demo'] }],
  ['wildcard site', { sites: ['*'] }],
  ['uppercase site', { sites: ['Demo'] }],
  ['non-string site', { sites: [12] }],
  ['non-array sites', { sites: 'demo' }],
  ['too many sites', { sites: Array.from({ length: 65 }, (_, i) => `s${i}`) }],
  ['empty capabilities', { capabilities: [] }],
  ['duplicate capabilities', { capabilities: ['read', 'read'] }],
  ['unknown capability', { capabilities: ['admin'] }],
  ['uppercase capability', { capabilities: ['Read'] }],
  ['too many capabilities', { capabilities: [...CAPABILITIES, 'read'] }],
  ['non-array capabilities', { capabilities: 'read' }],
  ['fractional expiry', { exp: NOW + 0.5 }],
  ['unsafe expiry', { exp: Number.MAX_SAFE_INTEGER + 1 }],
  ['negative expiry', { exp: -1 }],
  ['zero expiry', { exp: 0 }],
  ['string expiry', { exp: String(NOW + 60) }],
  ['boolean expiry', { exp: true }],
  ['null expiry', { exp: null }],
  ['missing expiry', { exp: undefined }]
];
for (const [name, overrides] of invalidClaims) {
  test(`mint and verification reject ${name}`, () => {
    expectAuth(() => mint(overrides), 'OWA_AUTH_INVALID_TOKEN');
    expectAuth(() => verify(oracle(JSON.stringify({ ...baseClaims(), ...overrides }))), 'OWA_AUTH_INVALID_TOKEN');
  });
}

test('mint rejects sparse arrays and non-finite expiry without silently repairing', () => {
  for (const overrides of [{ sites: new Array(1) }, { capabilities: new Array(1) }, { exp: Infinity }, { exp: NaN }]) expectAuth(() => mint(overrides), 'OWA_AUTH_INVALID_TOKEN');
});

const invalidPayloads = [
  ['unknown version', () => JSON.stringify({ ...baseClaims(), v: 2 })],
  ['string version', () => JSON.stringify({ ...baseClaims(), v: '1' })],
  ['unknown field', () => JSON.stringify({ ...baseClaims(), admin: true })],
  ['duplicate member', () => JSON.stringify(baseClaims()).replace('"v":1,', '"v":1,"v":1,')],
  ['duplicate member with different value', () => JSON.stringify(baseClaims()).replace('"v":1,', '"v":2,"v":1,')],
  ['prototype field', () => JSON.stringify(baseClaims()).replace('"v":1,', '"__proto__":{},"v":1,')],
  ['missing version', () => JSON.stringify({ jti: 'audit', exp: NOW + 1, sites: ['demo'], capabilities: ['read'] })],
  ['wrong field order', () => JSON.stringify({ exp: NOW + 60, v: 1, jti: 'operator-audit_001', sites: ['demo'], capabilities: ['read'] })],
  ['leading whitespace', () => ` ${JSON.stringify(baseClaims())}`],
  ['trailing newline', () => `${JSON.stringify(baseClaims())}\n`],
  ['internal whitespace', () => JSON.stringify(baseClaims()).replace('"v":1,', '"v": 1,')],
  ['unsorted sites', () => JSON.stringify({ ...baseClaims(), sites: ['zeta', 'alpha'] })],
  ['unsorted capabilities', () => JSON.stringify({ ...baseClaims(), capabilities: ['upload', 'read'] })],
  ['noncanonical version number', () => JSON.stringify(baseClaims()).replace('"v":1,', '"v":1.0,')],
  ['noncanonical expiry number', () => JSON.stringify(baseClaims()).replace(`"exp":${NOW + 60}`, `"exp":${NOW + 60}.0`)],
  ['exponential expiry spelling', () => JSON.stringify(baseClaims()).replace(`"exp":${NOW + 60}`, `"exp":${NOW + 60}e0`)],
  ['overflow expiry spelling', () => JSON.stringify(baseClaims()).replace(`"exp":${NOW + 60}`, '"exp":1e400')],
  ['noncanonical string escape', () => JSON.stringify(baseClaims()).replace('"demo"', '"\\u0064emo"')],
  ['JSON array', () => '[]'],
  ['JSON null', () => 'null'],
  ['malformed JSON', () => '{'],
  ['UTF-8 BOM', () => Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), Buffer.from(JSON.stringify(baseClaims()))])],
  ['malformed UTF-8', () => Buffer.from([0xc3, 0x28])],
  ['overlong UTF-8', () => Buffer.from([0xc0, 0xaf])],
  ['UTF-8 surrogate', () => Buffer.from([0xed, 0xa0, 0x80])]
];
for (const [name, payload] of invalidPayloads) {
  test(`valid MAC cannot authorize ${name}`, () => {
    expectAuth(() => verify(oracle(payload())), 'OWA_AUTH_INVALID_TOKEN');
  });
}

test('format is exactly three owa1 segments with bounded input length', () => {
  const token = mint();
  const [prefix, payload, signature] = token.split('.');
  for (const invalid of [undefined, null, 12, {}, '', 'owa1', `owa1.${payload}`, `${token}.extra`, `OWA1.${payload}.${signature}`, `owa2.${payload}.${signature}`, `${prefix}..${signature}`, `${prefix}.${payload}.`, `${token}\n`, ` ${token}`, `owa1.${'a'.repeat(8192)}.${signature}`]) {
    expectAuth(() => verify(invalid), 'OWA_AUTH_INVALID_TOKEN');
  }
});

test('base64url must be unpadded, URL-safe, and canonical including unused bits', () => {
  const token = mint();
  const [, payload, signature] = token.split('.');
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
  const noncanonicalSignature = signature.slice(0, -1) + alphabet[alphabet.indexOf(signature.at(-1)) + 1];
  assert.ok(Buffer.from(signature, 'base64url').equals(Buffer.from(noncanonicalSignature, 'base64url')), 'unused bits decode to the same bytes');
  for (const invalid of [`owa1.${payload}=.${signature}`, `${token}=`, `owa1.${payload}.${noncanonicalSignature}`, `owa1.Zh.${signature}`, `owa1.A.${signature}`, `owa1.${payload}+.${signature}`, `owa1.${payload}.${signature.slice(0, -1)}/`, `owa1.${payload} .${signature}`]) {
    expectAuth(() => verify(invalid), 'OWA_AUTH_INVALID_TOKEN');
  }
  for (const length of [1, 31, 33, 64]) expectAuth(() => verify(replaceSignature(token, Buffer.alloc(length).toString('base64url'))), 'OWA_AUTH_INVALID_TOKEN');
});

test('canonical encodings with modified payload, MAC, or signing key fail signature authentication', () => {
  const token = mint();
  const [, payload, signature] = token.split('.');
  const modifiedPayload = Buffer.from(JSON.stringify({ ...baseClaims(), sites: ['other'] })).toString('base64url');
  const modifiedSignature = Buffer.from(signature, 'base64url');
  modifiedSignature[0] ^= 1;
  expectAuth(() => verify(`owa1.${modifiedPayload}.${signature}`), 'OWA_AUTH_INVALID_SIGNATURE');
  expectAuth(() => verify(`owa1.${payload}.${modifiedSignature.toString('base64url')}`), 'OWA_AUTH_INVALID_SIGNATURE');
  expectAuth(() => verify(token, { secret: otherSecret }), 'OWA_AUTH_INVALID_SIGNATURE');
});

test('signature authentication precedes trusting malformed or expired claims', () => {
  for (const payload of ['{', Buffer.from([0xff]), JSON.stringify({ ...baseClaims(), exp: NOW - 1 }), JSON.stringify({ ...baseClaims(), v: 999 })]) {
    expectAuth(() => verify(oracle(payload, otherSecret)), 'OWA_AUTH_INVALID_SIGNATURE');
  }
});

test('expiry is exclusive and mint refuses already-expired tokens', () => {
  const token = mint({ exp: NOW + 1 });
  assert.equal(verify(token).exp, NOW + 1);
  expectAuth(() => verify(token, { now: () => NOW + 1 }), 'OWA_AUTH_EXPIRED');
  expectAuth(() => verify(token, { now: () => NOW + 2 }), 'OWA_AUTH_EXPIRED');
  expectAuth(() => mint({ exp: NOW }), 'OWA_AUTH_EXPIRED');
  expectAuth(() => mint({ exp: NOW - 1 }), 'OWA_AUTH_EXPIRED');
  const epochToken = mint({ exp: 1, now: () => 0 });
  assert.equal(verify(epochToken, { now: () => 0 }).exp, 1);
});

test('invalid clock types, values and thrown errors fail closed without cause leakage', () => {
  const token = mint();
  const invalidClocks = [null, NOW, 'now', () => -1, () => 0.5, () => NaN, () => Infinity, () => Number.MAX_SAFE_INTEGER + 1, () => String(NOW), () => new Date(), () => Promise.resolve(NOW), () => { throw new Error(secret.toString('utf8')); }];
  for (const clock of invalidClocks) {
    for (const operation of [() => mint({ now: clock }), () => verify(token, { now: clock }), () => createAuthorizer({ secret, now: clock }), () => createAuthorizer({ mode: 'dev', now: clock })]) {
      const error = expectAuth(operation, 'OWA_AUTH_CONFIG', 500);
      assert.ok(!error.message.includes(secret.toString('utf8')), 'clock failure does not expose cause');
    }
  }
});

test('authorizer revalidates clock on each request and exposes a safe now callback', () => {
  let clockValue = NOW;
  const auth = createAuthorizer({ secret, now: () => clockValue });
  assert.equal(auth.now(), NOW);
  const req = request(mint());
  assert.equal(auth.authorize(req, 'demo', ['read']).jti, 'operator-audit_001');
  clockValue = NOW + 60;
  expectAuth(() => auth.authorize(req, 'demo', ['read']), 'OWA_AUTH_EXPIRED');
  clockValue = NaN;
  expectAuth(() => auth.now(), 'OWA_AUTH_CONFIG', 500);
  expectAuth(() => auth.authorize(req, 'demo'), 'OWA_AUTH_CONFIG', 500);
});

test('default clock is integer Unix seconds for mint, verify and authorizer', () => {
  const original = Date.now;
  try {
    Date.now = () => NOW * 1000 + 999;
    const token = createToken({ ...baseClaims(), secret });
    assert.deepEqual(verifyToken(token, { secret }), baseClaims());
    assert.equal(createAuthorizer({ secret }).now(), NOW);
  } finally { Date.now = original; }
});

test('minimum secret length is measured in bytes and Buffer/string representations agree', () => {
  const text = String.fromCodePoint(0x00e9).repeat(16);
  assert.equal(Buffer.byteLength(text, 'utf8'), 32);
  const token = mint({ secret: text });
  assert.ok(token === mint({ secret: Buffer.from(text, 'utf8') }), 'string keys use UTF-8');
  assert.equal(verify(token, { secret: Buffer.from(text, 'utf8') }).jti, 'operator-audit_001');
  for (const key of [undefined, null, '', 'x'.repeat(31), Buffer.alloc(31), text.slice(1), new Uint8Array(32), 32]) {
    expectAuth(() => mint({ secret: key }), 'OWA_AUTH_CONFIG', 500);
    expectAuth(() => verify(token, { secret: key }), 'OWA_AUTH_CONFIG', 500);
    expectAuth(() => createAuthorizer({ secret: key, now }), 'OWA_AUTH_CONFIG', 500);
  }
});

test('authorizer prechecks config, defaults required, and copies its secret bytes', () => {
  expectAuth(() => createAuthorizer(), 'OWA_AUTH_CONFIG', 500);
  for (const options of [null, false, [], 'dev']) {
    expectAuth(() => createAuthorizer(options), 'OWA_AUTH_CONFIG', 500);
    expectAuth(() => createToken(options), 'OWA_AUTH_CONFIG', 500);
    expectAuth(() => verifyToken(mint(), options), 'OWA_AUTH_CONFIG', 500);
  }
  for (const mode of ['', 'off', 'optional', 'REQUIRED', null, false, 1]) expectAuth(() => createAuthorizer({ mode, secret, now }), 'OWA_AUTH_CONFIG', 500);
  const key = Buffer.from(secret);
  const auth = createAuthorizer({ secret: key, now });
  assert.equal(auth.mode, 'required');
  assert.ok(Object.isFrozen(auth));
  key.fill(0);
  assert.equal(auth.authorize(request(mint()), 'demo', ['read']).jti, 'operator-audit_001');
});

test('environment cannot select dev mode or supply the authorizer secret', () => {
  const names = ['OWA_AUTH_MODE', 'OWA_AUTH_SECRET'];
  const previous = names.map(name => process.env[name]);
  try {
    process.env.OWA_AUTH_MODE = 'dev';
    process.env.OWA_AUTH_SECRET = secret.toString('utf8');
    expectAuth(() => createAuthorizer({ now }), 'OWA_AUTH_CONFIG', 500);
    const auth = createAuthorizer({ secret, now });
    assert.equal(auth.mode, 'required');
    expectAuth(() => auth.authorize({ headers: {}, socket: { remoteAddress: '127.0.0.1' } }, 'demo'), 'OWA_AUTH_MISSING');
  } finally {
    names.forEach((name, i) => { if (previous[i] === undefined) delete process.env[name]; else process.env[name] = previous[i]; });
  }
});

test('required authorization uses only a single Bearer header and returns audit claims', () => {
  const auth = createAuthorizer({ secret, now });
  const token = mint();
  for (const scheme of ['Bearer', 'bearer', 'BEARER', 'bEaReR']) {
    const req = { headers: { authorization: `${scheme} ${token}` }, rawHeaders: ['Authorization', `${scheme} ${token}`] };
    assert.deepEqual(auth.authorize(req, 'demo', ['read']), baseClaims());
  }
  assert.deepEqual(auth.authorize({ headers: { Authorization: `Bearer ${token}` } }, 'demo'), baseClaims());
  expectAuth(() => auth.authorize({ headers: {} }, 'demo'), 'OWA_AUTH_MISSING');
  expectAuth(() => auth.authorize({ headers: { cookie: `token=${token}` }, url: `/?token=${token}` }, 'demo'), 'OWA_AUTH_MISSING');
});

test('malformed, combined and duplicated Authorization headers are rejected', () => {
  const auth = createAuthorizer({ secret, now });
  const token = mint();
  for (const value of ['', `Basic ${token}`, `Bearer`, `Bearer\t${token}`, `Bearer  ${token}`, ` Bearer ${token}`, `Bearer ${token} `, `Bearer ${token}\n`, `Bearer ${token},Bearer ${token}`, [token], [`Bearer ${token}`, `Bearer ${token}`], null, 123]) {
    expectAuth(() => auth.authorize({ headers: { authorization: value } }, 'demo'), 'OWA_AUTH_INVALID_TOKEN');
  }
  expectAuth(() => auth.authorize({ headers: { authorization: `Bearer ${token}`, Authorization: `Bearer ${token}` } }, 'demo'), 'OWA_AUTH_INVALID_TOKEN');
  expectAuth(() => auth.authorize(request(token, { rawHeaders: ['Authorization', `Bearer ${token}`, 'AUTHORIZATION', `Bearer ${token}`] }), 'demo'), 'OWA_AUTH_INVALID_TOKEN');
  expectAuth(() => auth.authorize(request(token, { rawHeaders: ['Authorization'] }), 'demo'), 'OWA_AUTH_INVALID_TOKEN');
});

test('site scope is exact and checked before missing capabilities', () => {
  const auth = createAuthorizer({ secret, now });
  const req = request(mint({ sites: ['demo', 'second'] }));
  assert.equal(auth.authorize(req, 'second', ['read']).jti, 'operator-audit_001');
  for (const site of ['other', 'Demo', 'demo-child', '*', 'demo\n', null]) expectAuth(() => auth.authorize(req, site, ['plan']), 'OWA_AUTH_SITE', 403);
  expectAuth(() => auth.authorize(req, 'demo', ['plan']), 'OWA_AUTH_CAPABILITY', 403);
});

test('all required capabilities must be present, with no implication between capabilities', () => {
  const auth = createAuthorizer({ secret, now });
  for (const cap of CAPABILITIES) {
    const req = request(mint({ capabilities: [cap] }));
    assert.equal(auth.authorize(req, 'demo', [cap]).jti, 'operator-audit_001');
    for (const missing of CAPABILITIES.filter(candidate => candidate !== cap)) expectAuth(() => auth.authorize(req, 'demo', [missing]), 'OWA_AUTH_CAPABILITY', 403);
  }
  const publisher = request(mint({ capabilities: ['plan', 'upload', 'commit', 'activate'] }));
  assert.ok(auth.authorize(publisher, 'demo', ['plan', 'upload', 'commit', 'activate']));
  expectAuth(() => auth.authorize(publisher, 'demo', ['read']), 'OWA_AUTH_CAPABILITY', 403);
  expectAuth(() => auth.authorize(request(mint({ capabilities: ['commit'] })), 'demo', ['commit', 'activate']), 'OWA_AUTH_CAPABILITY', 403);
  for (const invalid of [null, 'read', ['admin'], new Array(1)]) expectAuth(() => auth.authorize(publisher, 'demo', invalid), 'OWA_AUTH_CONFIG', 500);
});

test('required mode never accepts a token signed by an unrelated upload key', () => {
  const auth = createAuthorizer({ secret, now });
  expectAuth(() => auth.authorize(request(mint({ secret: otherSecret })), 'demo', ['read']), 'OWA_AUTH_INVALID_SIGNATURE');
});

test('explicit dev mode permits only direct loopback and returns null metadata', () => {
  const auth = createAuthorizer({ mode: 'dev', now });
  assert.equal(auth.mode, 'dev');
  for (const remoteAddress of ['127.0.0.1', '127.9.8.7', '::1', '::ffff:127.0.0.1']) {
    assert.equal(auth.authorize({ headers: {}, socket: { remoteAddress } }, 'demo', ['plan', 'upload', 'commit', 'activate', 'read']), null);
  }
  for (const remoteAddress of ['10.0.0.1', '192.168.0.2', '::ffff:192.168.0.2', 'localhost', undefined]) {
    expectAuth(() => auth.authorize({ headers: { host: 'localhost' }, socket: { remoteAddress } }, 'demo'), 'OWA_AUTH_DEV_ONLY', 403);
  }
  expectAuth(() => auth.authorize({ headers: { host: '127.0.0.1' }, connection: { remoteAddress: '127.0.0.1' } }, 'demo'), 'OWA_AUTH_DEV_ONLY', 403);
  expectAuth(() => auth.authorize({ headers: {}, socket: { remoteAddress: '127.0.0.1' } }, '*'), 'OWA_AUTH_SITE', 403);
});

test('dev rejects Forwarded and all X-Forwarded-* headers, including raw or empty values', () => {
  const auth = createAuthorizer({ mode: 'dev', now });
  for (const name of ['forwarded', 'Forwarded', 'x-forwarded-for', 'X-Forwarded-For', 'X-Forwarded-Proto', 'x-forwarded-host']) {
    for (const value of ['', 'for=127.0.0.1', '127.0.0.1', '203.0.113.5', undefined]) {
      expectAuth(() => auth.authorize({ headers: { [name]: value }, socket: { remoteAddress: '127.0.0.1' } }, 'demo'), 'OWA_AUTH_DEV_ONLY', 403);
    }
    expectAuth(() => auth.authorize({ headers: {}, rawHeaders: [name, ''], socket: { remoteAddress: '::1' } }, 'demo'), 'OWA_AUTH_DEV_ONLY', 403);
  }
});

test('safe errors never echo keys, tokens, request values or underlying causes', () => {
  const token = mint();
  const auth = createAuthorizer({ secret, now });
  const errors = [
    expectAuth(() => verify(token, { secret: otherSecret }), 'OWA_AUTH_INVALID_SIGNATURE'),
    expectAuth(() => verify(`${token}.private`), 'OWA_AUTH_INVALID_TOKEN'),
    expectAuth(() => auth.authorize(request(token), token), 'OWA_AUTH_SITE', 403),
    expectAuth(() => createAuthorizer({ mode: token, secret, now }), 'OWA_AUTH_CONFIG', 500),
    expectAuth(() => createAuthorizer({ secret: secret.subarray(0, 31), now }), 'OWA_AUTH_CONFIG', 500)
  ];
  for (const error of errors) {
    for (const value of [token, secret.toString('utf8'), secret.subarray(0, 31).toString('utf8')]) {
      assert.ok(!error.message.includes(value), 'message is redacted');
      assert.ok(!String(error.stack).includes(value), 'stack is redacted');
      assert.ok(!JSON.stringify(error).includes(value), 'enumerable metadata is redacted');
    }
    assert.deepEqual(Object.keys(error).sort(), ['code', 'name', 'status']);
  }
});
