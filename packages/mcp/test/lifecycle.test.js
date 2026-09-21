import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { packDirectory } from '../../core/src/index.js';
import { canonicalJson, sha256 } from '../../spec/src/index.js';
import {
  CAPS, NOW, SOURCE, CHANGED_CSS, fixture, exactKeys, resultData, expectError, assertSafe
} from './helpers.js';

// `url` is an advertised property but is NOT required: the adapter omits it when
// the server supplies no canonical content URL rather than synthesizing one.
const PUBLISH_KEYS = ['ok', 'site', 'artifactDigest', 'releaseId', 'activeReleaseId', 'uploaded', 'reused', 'url'];
const PUBLISH_REQUIRED = PUBLISH_KEYS.filter(key => key !== 'url');
const CONTENT_ORIGIN = Object.freeze({ baseDomain: 'sites.example.invalid', scheme: 'https' });
const ACTIVATE_KEYS = ['ok', 'site', 'activeReleaseId'];
const LIST_KEYS = ['ok', 'site', 'activeReleaseId', 'releases'];
const RELEASE_KEYS = ['releaseId', 'artifactDigest', 'createdAt'];
const ERROR_KEYS = ['ok', 'error'];
const RELEASE_PATTERN = /^r_[0-9a-f]{20}$/;
const DIGEST_PATTERN = /^sha256:[0-9a-f]{64}$/;
// Fixed fixture identities make canonicalization drift visible independently of
// equality between two clients that share a packer. No clock/path/token fields.
const BASELINE_DIGEST = 'sha256:71e9c7a38c5d24bbd37f4cee787aba08f1bc428416e5eb3a02031142da16d660';
const CHANGED_DIGEST = 'sha256:86fc4e2f961313653b347c655812333b2795af33498af4695c4da576402b2600';

function expectPublish(result, f, { uploaded, reused, digest, active = true, url = null }) {
  const data = resultData(result, f.secrets());
  // Exactly the base fields, plus `url` only when the server provided one.
  exactKeys(data, url === null ? PUBLISH_REQUIRED : PUBLISH_KEYS);
  assert.equal(data.ok, true);
  assert.equal(data.site, 'demo');
  assert.match(data.releaseId, RELEASE_PATTERN);
  assert.match(data.artifactDigest, DIGEST_PATTERN);
  assert.equal(data.artifactDigest, digest);
  assert.equal(data.uploaded, uploaded);
  assert.equal(data.reused, reused);
  assert.equal(data.activeReleaseId, active ? data.releaseId : null);
  if (url === null) {
    assert.equal(Object.hasOwn(data, 'url'), false, 'no URL is invented when the server provides none');
  } else {
    assert.equal(data.url, url, 'the server canonical content URL is returned verbatim');
  }
  const serialized = JSON.stringify(data);
  assert.ok(!serialized.includes('?site='), 'the prototype query URL is never synthesized');
  assert.ok(!serialized.includes(f.origin), 'the control origin is never returned as a public URL');
  return data;
}

function expectActivation(result, f, releaseId) {
  const data = resultData(result, f.secrets());
  exactKeys(data, ACTIVATE_KEYS);
  assert.deepEqual(data, { ok: true, site: 'demo', activeReleaseId: releaseId });
  return data;
}

function expectSequence(records, methodsAndStatuses) {
  assert.deepEqual(records.map(record => [record.method, record.status]), methodsAndStatuses);
  assert.ok(records.every(record => !record.leakedOutsideHeader && !record.leakedInBody), 'bearer remains header-only');
}

function assertClosedObjects(schema) {
  if (!schema || typeof schema !== 'object') return;
  if (schema.properties) {
    assert.equal(schema.type, 'object');
    assert.equal(schema.additionalProperties, false, 'every object shape rejects extra fields');
    assert.ok(Array.isArray(schema.required));
    assert.ok(schema.required.every(key => Object.hasOwn(schema.properties, key)));
    for (const child of Object.values(schema.properties)) assertClosedObjects(child);
  }
  for (const union of ['oneOf', 'anyOf']) for (const child of schema[union] ?? []) assertClosedObjects(child);
  if (schema.items) assertClosedObjects(schema.items);
}

// No imports from MCP internals: discovery, schemas and results are asserted at
// the same public boundary an external official SDK client sees.
test('MCP initializes over official stdio and discovers exactly four closed-schema tools', { timeout: 20_000 }, async t => {
  const f = await fixture(t, { mode: 'dev' });
  const peer = await f.connect();
  assert.deepEqual(peer.tools.map(tool => tool.name).sort(), ['activate', 'list_releases', 'publish', 'rollback']);
  const shapes = {
    publish: { input: ['site', 'server', 'directory', 'activate'], required: ['site', 'server', 'directory'], output: PUBLISH_KEYS, requiredOutput: PUBLISH_REQUIRED },
    list_releases: { input: ['site', 'server'], required: ['site', 'server'], output: LIST_KEYS },
    activate: { input: ['site', 'server', 'releaseId'], required: ['site', 'server', 'releaseId'], output: ACTIVATE_KEYS },
    rollback: { input: ['site', 'server', 'releaseId'], required: ['site', 'server', 'releaseId'], output: ACTIVATE_KEYS }
  };
  for (const tool of peer.tools) {
    const expected = shapes[tool.name];
    assert.ok(typeof tool.description === 'string' && tool.description.length > 0);
    assertClosedObjects(tool.inputSchema);
    assertClosedObjects(tool.outputSchema);
    exactKeys(tool.inputSchema.properties, expected.input, 'exact tool input fields; no credential/manifest/upload inputs');
    assert.deepEqual([...tool.inputSchema.required].sort(), [...expected.required].sort());
    assert.equal(tool.inputSchema.properties.site.type, 'string');
    assert.ok(new RegExp(tool.inputSchema.properties.site.pattern).test('demo'));
    assert.ok(!new RegExp(tool.inputSchema.properties.site.pattern).test('demo\n'));
    assert.equal(tool.inputSchema.properties.server.type, 'string');
    assert.equal(tool.outputSchema.type, 'object');
    assert.equal(tool.outputSchema.oneOf.length, 2);
    const [success, failure] = tool.outputSchema.oneOf;
    exactKeys(success.properties, expected.output, 'exact success schema fields');
    assert.deepEqual([...success.required].sort(), [...(expected.requiredOutput ?? expected.output)].sort());
    assert.equal(success.properties.ok.const, true);
    exactKeys(failure.properties, ERROR_KEYS);
    assert.equal(failure.properties.ok.const, false);
    exactKeys(failure.properties.error.properties, ['code', 'category', 'message', 'status']);
    assert.deepEqual(failure.properties.error.required, ['code', 'category', 'message']);
    assert.ok(failure.properties.error.properties.code.enum.includes('OWA_AUTH_CAPABILITY'));
    assert.equal(tool.annotations.readOnlyHint, tool.name === 'list_releases');
    assert.equal(tool.annotations.destructiveHint, tool.name !== 'list_releases');
    if (tool.name === 'publish') {
      assert.equal(tool.inputSchema.properties.directory.type, 'string');
      assert.equal(tool.inputSchema.properties.activate.type, 'boolean');
      assert.equal(tool.inputSchema.properties.activate.default, true);
      assert.equal(success.properties.uploaded.type, 'integer');
      assert.equal(success.properties.reused.type, 'integer');
      assert.equal(success.properties.uploaded.minimum, 0);
      assert.equal(success.properties.url.type, 'string');
      assert.ok(!success.required.includes('url'), 'discovery advertises url as optional');
    } else if (tool.name === 'list_releases') {
      assert.equal(success.properties.releases.type, 'array');
      exactKeys(success.properties.releases.items.properties, RELEASE_KEYS);
    } else {
      assert.ok(new RegExp(tool.inputSchema.properties.releaseId.pattern).test(`r_${'a'.repeat(20)}`));
      assert.ok(!new RegExp(tool.inputSchema.properties.releaseId.pattern).test('latest'));
    }
  }
  assert.deepEqual(f.exchanges, [], 'initialize and discovery do not call the HTTP backend');
});

test('MCP dev-mode publish uses real plan/local PUT/commit and returns canonical identity without credentials', { timeout: 20_000 }, async t => {
  const f = await fixture(t, { mode: 'dev' });
  const packed = await packDirectory(f.directory); // Test-only expected identity; never used to publish.
  const peer = await f.connect(undefined, { trustedServer: `${f.origin}/` });
  const value = expectPublish(await peer.call('publish', f.args({ directory: 'site' })), f,
    { uploaded: 3, reused: 0, digest: packed.artifactDigest });
  expectSequence(f.exchanges, [['POST', 200], ['PUT', 204], ['PUT', 204], ['PUT', 204], ['POST', 201]]);
  assert.equal(f.exchanges[0].path, '/v1/sites/demo/publish/plan');
  assert.equal(f.exchanges.at(-1).path, '/v1/sites/demo/publish/commit');
  assert.ok(f.exchanges.every(record => !record.hasAuthorization), 'OWA_TOKEN may be omitted only for explicit loopback dev');
  for (const upload of f.exchanges.filter(record => record.method === 'PUT')) {
    assert.ok(upload.hasSignature && upload.validExpiry, 'legacy dev local grant is signed and accepted');
    assert.deepEqual(upload.queryKeys, ['expires', 'sig']);
    assert.equal(upload.hasContentType, false);
  }
  const { site, releases } = await f.fullReleases();
  assert.equal(site.activeReleaseId, value.releaseId);
  assert.equal(releases.length, 1);
  assert.equal(canonicalJson(releases[0].manifest), canonicalJson(packed.manifest));
  assert.equal(sha256(Buffer.from(canonicalJson(releases[0].manifest))), value.artifactDigest);
});

test('MCP required-auth pipeline uploads 3/0/1 unique blobs and matches the actual HTTP CLI canonical digest and manifests', { timeout: 30_000 }, async t => {
  const f = await fixture(t, { duplicate: true });
  const token = f.mint();
  const peer = await f.connect(token);
  const baseline = await packDirectory(f.directory);
  assert.equal(baseline.artifactDigest, BASELINE_DIGEST, 'fixed canonical fixture identity');
  assert.equal(baseline.manifest.files.length, 4, 'duplicate path has the same bytes as app.js');
  assert.equal(baseline.blobs.size, 3, 'upload accounting is by unique digest, not filename');
  const first = expectPublish(await peer.call('publish', f.args({ directory: f.directory, server: `${f.origin}/` })), f,
    { uploaded: 3, reused: 0, digest: baseline.artifactDigest });
  const firstRequests = f.exchanges.slice();
  expectSequence(firstRequests, [['POST', 200], ['PUT', 204], ['PUT', 204], ['PUT', 204], ['POST', 201]]);
  assert.equal(firstRequests[0].path, '/v1/sites/demo/publish/plan');
  assert.equal(firstRequests.at(-1).path, '/v1/sites/demo/publish/commit');
  assert.ok(firstRequests.every(record => record.bearerMatches), 'all control calls AND marked filesystem PUTs carry the env bearer');
  for (const upload of firstRequests.filter(record => record.method === 'PUT')) {
    assert.match(upload.path, /^\/v1\/uploads\/sha256%3A[0-9a-f]{64}$/);
    assert.ok(upload.hasSignature && upload.validExpiry && upload.localScope, 'successful real PUT proves bearer AND scoped signature composition');
    assert.deepEqual(upload.queryKeys, ['expires', 'sig', 'site']);
    assert.equal(upload.hasContentType, false, 'control-plane JSON headers are not copied to upload');
  }

  let offset = f.exchanges.length;
  const second = expectPublish(await peer.call('publish', f.args({ directory: 'site' })), f,
    { uploaded: 0, reused: 3, digest: baseline.artifactDigest });
  expectSequence(f.exchanges.slice(offset), [['POST', 200], ['POST', 201]]);
  assert.notEqual(first.releaseId, second.releaseId, 'identical artifacts may still create distinct releases');

  // Required proof: a separate actual CLI child publishes the exact same local
  // directory to the same real HTTP server. No mocked response or core publish.
  offset = f.exchanges.length;
  const cli = await f.runCli(token);
  expectSequence(f.exchanges.slice(offset), [['POST', 200], ['POST', 201]]);
  assert.equal(cli.artifactDigest, first.artifactDigest, 'MCP and HTTP CLI return byte-identical canonical identity');
  const beforeChange = await f.fullReleases(token);
  assert.equal(beforeChange.releases.length, 3);
  const canonicalBytes = Buffer.from(canonicalJson(baseline.manifest));
  assert.equal(sha256(canonicalBytes), first.artifactDigest);
  for (const release of beforeChange.releases) {
    assert.equal(release.artifactDigest, baseline.artifactDigest);
    assert.ok(Buffer.from(canonicalJson(release.manifest)).equals(canonicalBytes), 'HTTP release listing includes the exact same canonical manifest bytes');
    const stored = JSON.parse(await readFile(f.metadata.releasePath(beforeChange.site.id, release.id), 'utf8'));
    assert.equal(stored.artifactDigest, baseline.artifactDigest);
    assert.ok(Buffer.from(canonicalJson(stored.manifest)).equals(canonicalBytes), 'persisted MCP/CLI release manifest bytes are stable');
  }
  assert.equal(beforeChange.site.activeReleaseId, cli.releaseId);

  await writeFile(join(f.directory, 'style.css'), CHANGED_CSS);
  const changed = await packDirectory(f.directory);
  assert.equal(changed.artifactDigest, CHANGED_DIGEST, 'fixed one-file-change identity');
  assert.notEqual(changed.artifactDigest, baseline.artifactDigest);
  offset = f.exchanges.length;
  const third = expectPublish(await peer.call('publish', f.args({ directory: 'site' })), f,
    { uploaded: 1, reused: 2, digest: changed.artifactDigest });
  expectSequence(f.exchanges.slice(offset), [['POST', 200], ['PUT', 204], ['POST', 201]]);
  const afterChange = await f.fullReleases(token);
  assert.equal(afterChange.releases.length, 4);
  assert.equal(afterChange.site.activeReleaseId, third.releaseId);
  const newest = afterChange.releases.find(release => release.id === third.releaseId);
  assert.equal(canonicalJson(newest.manifest), canonicalJson(changed.manifest));
  for (const old of afterChange.releases.filter(release => release.id !== third.releaseId)) {
    assert.ok(Buffer.from(canonicalJson(old.manifest)).equals(canonicalBytes), 'later publish did not mutate prior manifests');
  }
  for (const [digest, bytes] of changed.blobs) assert.ok(Buffer.from(await f.blobs.get(digest)).equals(Buffer.from(bytes)), 'real stored blob bytes match packed source');
  assertSafe(JSON.stringify({ first, second, third, cli }), f.secrets(), { fileBytes: true });
  t.diagnostic(`Exact MCP/HTTP-CLI fixture digest: ${first.artifactDigest}; changed digest: ${third.artifactDigest}`);
});

for (const scenario of [
  { name: 'missing token', code: 'OWA_AUTH_MISSING', status: 401, token: () => undefined },
  { name: 'wrong site', code: 'OWA_AUTH_SITE', status: 403, token: f => f.mint(CAPS, { sites: ['other'] }) },
  { name: 'expired token at fixed auth clock', code: 'OWA_AUTH_EXPIRED', status: 401,
    token: f => f.mint(CAPS, { exp: NOW - 1, now: NOW - 2 }) },
  { name: 'tampered signature', code: 'OWA_AUTH_INVALID_SIGNATURE', status: 401, token: f => f.tamper(f.mint()) },
  { name: 'missing plan capability', code: 'OWA_AUTH_CAPABILITY', status: 403, token: f => f.mint(CAPS.filter(cap => cap !== 'plan')) },
  { name: 'missing upload capability with actually absent blobs', code: 'OWA_AUTH_CAPABILITY', status: 403,
    token: f => f.mint(CAPS.filter(cap => cap !== 'upload')) }
]) {
  test(`MCP publish preserves ${scenario.name} denial and has no downstream writes`, { timeout: 20_000 }, async t => {
    const f = await fixture(t);
    const expected = await packDirectory(f.directory);
    for (const digest of expected.blobs.keys()) assert.equal(await f.blobs.has(digest), false, 'the fixture really has missing blobs');
    const peer = await f.connect(scenario.token(f));
    expectError(await peer.call('publish', f.args({ directory: 'site' })), scenario.code, scenario.status, f.secrets());
    expectSequence(f.exchanges, [['POST', scenario.status]]);
    assert.equal(f.exchanges[0].path, '/v1/sites/demo/publish/plan');
    await f.assertNoWrites();
  });
}

for (const missing of ['commit', 'activate']) {
  test(`MCP default publish missing ${missing} capability preserves denial after uploads but creates no release`, { timeout: 20_000 }, async t => {
    const f = await fixture(t);
    const token = f.mint(CAPS.filter(cap => cap !== missing));
    const peer = await f.connect(token);
    expectError(await peer.call('publish', f.args({ directory: 'site' })), 'OWA_AUTH_CAPABILITY', 403, f.secrets());
    expectSequence(f.exchanges, [['POST', 200], ['PUT', 204], ['PUT', 204], ['PUT', 204], ['POST', 403]]);
    assert.equal(f.exchanges.at(-1).path, '/v1/sites/demo/publish/commit');
    assert.equal(await f.metadata.getSite('demo'), null, 'commit authorization denial cannot create metadata or an active pointer');
    // The plan/upload/commit workflow legitimately leaves immutable orphan
    // blobs when authorization fails at commit. Do not incorrectly demand that
    // a commit denial undo already-authorized uploads.
    const packed = await packDirectory(f.directory);
    for (const digest of packed.blobs.keys()) assert.equal(await f.blobs.has(digest), true, 'authorized upload remains after denied commit');
  });
}

test('MCP activate:false succeeds with plan/upload/commit and an identical deduplicated publish needs no upload capability', { timeout: 20_000 }, async t => {
  const f = await fixture(t);
  const packed = await packDirectory(f.directory);
  const staged = await f.connect(f.mint(['plan', 'upload', 'commit']));
  const first = expectPublish(await staged.call('publish', f.args({ directory: 'site', activate: false })), f,
    { uploaded: 3, reused: 0, digest: packed.artifactDigest, active: false });
  assert.equal((await f.metadata.getSite('demo')).activeReleaseId, null);
  const offset = f.exchanges.length;
  const dedup = await f.connect(f.mint(['plan', 'commit']));
  const second = expectPublish(await dedup.call('publish', f.args({ directory: 'site', activate: false })), f,
    { uploaded: 0, reused: 3, digest: packed.artifactDigest, active: false });
  expectSequence(f.exchanges.slice(offset), [['POST', 200], ['POST', 201]]);
  assert.notEqual(first.releaseId, second.releaseId);
  const site = await f.metadata.getSite('demo');
  assert.equal(site.activeReleaseId, null);
  assert.equal((await f.metadata.listReleases(site.id)).length, 2);
});

test('MCP read/activate capability boundaries and explicit rollback use only the existing activation route', { timeout: 30_000 }, async t => {
  const f = await fixture(t);
  const publisher = await f.connect(f.mint(['plan', 'upload', 'commit']));
  const original = await packDirectory(f.directory);
  const old = expectPublish(await publisher.call('publish', f.args({ directory: 'site', activate: false })), f,
    { uploaded: 3, reused: 0, digest: original.artifactDigest, active: false });
  await writeFile(join(f.directory, 'style.css'), CHANGED_CSS);
  const changed = await packDirectory(f.directory);
  const newer = expectPublish(await publisher.call('publish', f.args({ directory: 'site', activate: false })), f,
    { uploaded: 1, reused: 2, digest: changed.artifactDigest, active: false });
  const site = await f.metadata.getSite('demo');
  const immutablePaths = [old.releaseId, newer.releaseId].map(id => f.metadata.releasePath(site.id, id));
  const immutableBytes = await Promise.all(immutablePaths.map(path => readFile(path)));
  const activator = await f.connect(f.mint(['activate']));
  const reader = await f.connect(f.mint(['read']));

  let offset = f.exchanges.length;
  expectError(await activator.call('list_releases', f.args()), 'OWA_AUTH_CAPABILITY', 403, f.secrets());
  expectSequence(f.exchanges.slice(offset), [['GET', 403]]);
  assert.equal((await f.metadata.getSite('demo')).activeReleaseId, null);

  offset = f.exchanges.length;
  expectActivation(await activator.call('activate', f.args({ releaseId: newer.releaseId })), f, newer.releaseId);
  expectSequence(f.exchanges.slice(offset), [['POST', 200]]);
  assert.equal(f.exchanges.at(-1).path, `/v1/sites/demo/activate/${newer.releaseId}`);
  assert.equal((await f.metadata.getSite('demo')).activeReleaseId, newer.releaseId);

  offset = f.exchanges.length;
  const listed = resultData(await reader.call('list_releases', f.args()), f.secrets());
  exactKeys(listed, LIST_KEYS);
  assert.equal(listed.ok, true);
  assert.equal(listed.site, 'demo');
  assert.equal(listed.activeReleaseId, newer.releaseId);
  assert.equal(listed.releases.length, 2);
  expectSequence(f.exchanges.slice(offset), [['GET', 200]]);
  assert.equal(f.exchanges.at(-1).path, '/v1/sites/demo/releases');
  for (const release of listed.releases) {
    exactKeys(release, RELEASE_KEYS, 'release projection excludes full manifest, bytes, URL and internal metadata');
    assert.match(release.releaseId, RELEASE_PATTERN);
    assert.match(release.artifactDigest, DIGEST_PATTERN);
    assert.equal(new Date(release.createdAt).toISOString(), release.createdAt);
    const stored = await f.metadata.getRelease(site.id, release.releaseId);
    assert.equal(release.artifactDigest, stored.artifactDigest);
    assert.equal(release.createdAt, stored.createdAt);
  }
  assert.deepEqual(new Set(listed.releases.map(release => release.releaseId)), new Set([old.releaseId, newer.releaseId]));

  for (const name of ['activate', 'rollback']) {
    offset = f.exchanges.length;
    expectError(await reader.call(name, f.args({ releaseId: old.releaseId })), 'OWA_AUTH_CAPABILITY', 403, f.secrets());
    expectSequence(f.exchanges.slice(offset), [['POST', 403]]);
    assert.equal(f.exchanges.at(-1).path, `/v1/sites/demo/activate/${old.releaseId}`);
    assert.equal((await f.metadata.getSite('demo')).activeReleaseId, newer.releaseId, 'denied mutation leaves active pointer intact');
  }

  offset = f.exchanges.length;
  expectError(await activator.call('rollback', f.args()), 'OWA_MCP_INVALID_INPUT', undefined, f.secrets());
  assert.equal(f.exchanges.length, offset, 'rollback cannot infer a release when explicit releaseId is absent');
  expectActivation(await activator.call('rollback', f.args({ releaseId: old.releaseId })), f, old.releaseId);
  const rollbackRequests = f.exchanges.slice(offset);
  expectSequence(rollbackRequests, [['POST', 200]]);
  assert.equal(rollbackRequests[0].path, `/v1/sites/demo/activate/${old.releaseId}`,
    'rollback uses activation, never a new rollback endpoint or implicit read/list');
  assert.equal((await f.metadata.getSite('demo')).activeReleaseId, old.releaseId);
  assert.equal((await f.metadata.listReleases(site.id)).length, 2, 'activation does not create releases');
  for (let i = 0; i < immutablePaths.length; i++) {
    assert.ok((await readFile(immutablePaths[i])).equals(immutableBytes[i]), 'activation and rollback preserve release files byte-for-byte');
  }
});

test('MCP invalid input and local packing failures map safely without HTTP or storage effects', { timeout: 20_000 }, async t => {
  const f = await fixture(t);
  const peer = await f.connect(f.mint());
  await mkdir(join(f.staging, 'empty'));
  await mkdir(join(f.staging, 'no-entrypoint'));
  await writeFile(join(f.staging, 'no-entrypoint', 'notes.txt'), 'Not an artifact entrypoint.\n');
  const args = f.args({ directory: 'site' });
  for (const invalid of [
    { ...args, site: 'demo\n' },
    { ...args, activate: 'false' },
    { ...args, directory: 'absent' },
    { ...args, directory: 'empty' },
    { ...args, directory: 'no-entrypoint' },
    { ...args, directory: '..' },
    { ...args, directory: 'site/index.html' },
    { ...args, server: `${f.origin}/v1` },
    { ...args, server: f.origin.replace('127.0.0.1', 'localhost') },
    { ...args, extra: true }
  ]) {
    expectError(await peer.call('publish', invalid), 'OWA_MCP_INVALID_INPUT', undefined, f.secrets());
  }
  assert.deepEqual(f.exchanges, [], 'invalid input never reaches even the plan endpoint');
  await f.assertNoWrites();
  assert.ok(Object.keys(SOURCE).length === 3, 'fixture source remains deterministic');
});

// Issue #14: the adapter must surface the SERVER's canonical content URL and
// must invent nothing when the server has no content origin. Both halves run
// through the real official SDK client against a real HTTP server.
test('MCP publish returns the server canonical content URL when a content origin is configured', { timeout: 20_000 }, async t => {
  const f = await fixture(t, { content: CONTENT_ORIGIN });
  const peer = await f.connect(f.mint(CAPS));
  const value = expectPublish(await peer.call('publish', f.args({ directory: 'site' })), f,
    { uploaded: 3, reused: 0, digest: BASELINE_DIGEST, url: 'https://demo.sites.example.invalid/' });

  // The URL is the content origin, never the control origin the client dialed,
  // and carries no credential, query selector or storage grant material.
  const url = new URL(value.url);
  assert.equal(url.origin, 'https://demo.sites.example.invalid');
  assert.equal(url.pathname, '/');
  assert.equal(url.search, '');
  assert.equal(url.username, '');
  assert.equal(url.password, '');
  assert.notEqual(url.origin, new URL(f.origin).origin);
  assertSafe(value.url, f.secrets());

  // structuredContent projection must validate against the optional-url schema.
  const republish = expectPublish(await peer.call('publish', f.args({ directory: 'site' })), f,
    { uploaded: 0, reused: 3, digest: BASELINE_DIGEST, url: 'https://demo.sites.example.invalid/' });
  assert.equal(republish.url, value.url, 'the canonical URL is stable across publishes');
});

test('MCP publish omits url entirely when the server provides no canonical content URL', { timeout: 20_000 }, async t => {
  const f = await fixture(t); // No content origin configured on the server.
  const peer = await f.connect(f.mint(CAPS));
  const value = expectPublish(await peer.call('publish', f.args({ directory: 'site' })), f,
    { uploaded: 3, reused: 0, digest: BASELINE_DIGEST });

  assert.equal(Object.hasOwn(value, 'url'), false, 'absent, not null and not fabricated');
  assert.equal(value.ok, true, 'omitting the URL does not fail the call or its schema projection');
  assert.ok(!JSON.stringify(value).includes('?site='), 'the retired prototype URL is never reconstructed');
});
