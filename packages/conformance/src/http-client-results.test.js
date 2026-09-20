import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { once } from 'node:events';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { createServer } from 'node:http';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { isDeepStrictEqual } from 'node:util';
import {
  CliError, cliErrorMessage, remotePublish, remotePublishResult,
  remoteReleases, remoteReleasesResult, remoteActivate, remoteActivateResult,
  validateRemoteServer
} from '../../cli/src/remote.js';

const RELEASE = `r_${'a'.repeat(20)}`;
const OTHER_RELEASE = `r_${'c'.repeat(20)}`;
const DIGEST = `sha256:${'b'.repeat(64)}`;
const TIMESTAMP = '2023-11-14T22:13:20.000Z';
const goodRelease = () => ({ id: RELEASE, artifactDigest: DIGEST, createdAt: TIMESTAMP });

function json(res, status, body) {
  res.writeHead(status, { 'content-type': 'application/json' });
  res.end(JSON.stringify(body));
}
async function readJson(req) {
  let text = ''; for await (const chunk of req) text += chunk;
  return JSON.parse(text || '{}');
}
function noLeaks(value, forbidden) {
  const text = typeof value === 'string' ? value : JSON.stringify(value);
  for (const secret of forbidden) assert.ok(!text.includes(secret), 'no sensitive response data escapes');
}
function matches(actual, expected) {
  // Boolean assertions only: a regression must not print poisoned responses.
  assert.ok(isDeepStrictEqual(actual, expected), 'exact public result or format');
}
async function rejectsSafely(action, code, forbidden, status) {
  let caught;
  try { await action(); } catch (error) { caught = error; }
  assert.ok(caught instanceof CliError, 'original CliError type is preserved');
  assert.ok(caught.code === code && caught.status === status, 'original bounded code and status are preserved');
  assert.ok(!Object.hasOwn(caught, 'cause'), 'no provider cause is retained');
  noLeaks([caught.message, caught.stack, caught, cliErrorMessage(caught)], forbidden);
  return cliErrorMessage(caught);
}

async function fixture(t, options = {}) {
  // Runtime-only credentials and signed-looking URLs, never literal fixtures/logs.
  const token = randomBytes(32).toString('base64url');
  const secretUrl = `https://storage.invalid/object?X-Amz-Signature=${randomBytes(32).toString('hex')}`;
  const rawSiteId = randomBytes(24).toString('hex');
  const forbidden = [token, secretUrl, rawSiteId];
  const poison = { token, url: secretUrl, siteId: rawSiteId, manifest: { token, url: secretUrl } };
  const previousToken = process.env.OWA_TOKEN;
  process.env.OWA_TOKEN = token;
  t.after(() => {
    if (previousToken === undefined) delete process.env.OWA_TOKEN;
    else process.env.OWA_TOKEN = previousToken;
  });
  const directory = await mkdtemp(join(tmpdir(), 'owa-http-results-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  await writeFile(join(directory, 'index.html'), '<h1>HTTP result fixture</h1>');
  await writeFile(join(directory, 'style.css'), 'body { color: navy; }');
  const seen = [], commits = [];
  let origin, artifactDigest;
  // Explicit required-auth loopback control stub; object uploads remain unsigned
  // unless the grant carries the existing bearer marker and exact FS URL shape.
  const server = createServer(async (req, res) => {
    const path = new URL(req.url, 'http://localhost').pathname;
    const authorized = req.headers.authorization === `Bearer ${token}`;
    seen.push({ method: req.method, path, authorized,
      hasAuthorization: Object.hasOwn(req.headers, 'authorization'),
      contentType: req.headers['content-type'],
      leaked: req.url.includes(token) || Object.entries(req.headers)
        .some(([name, value]) => name !== 'authorization' && String(value).includes(token)) });
    try {
      if (path === '/objects/blob') {
        for await (const chunk of req) void chunk;
        res.writeHead(204); res.end(); return;
      }
      if (!authorized) return json(res, 401, { code: 'OWA_AUTH_MISSING', ...poison });
      if (options.errorCode) return json(res, 403, { code: options.errorCode, error: poison });
      if (path.endsWith('/publish/plan')) {
        const body = await readJson(req);
        artifactDigest = body.artifactDigest;
        const digest = body.manifest.files[0].digest;
        const grant = options.bearer ? {
          digest, method: 'PUT', authorization: 'bearer',
          url: `${origin}/v1/uploads/${encodeURIComponent(digest)}?expires=1700000300&sig=${randomBytes(32).toString('hex')}&site=demo`
        } : { digest, method: 'PUT', url: `${origin}/objects/blob?X-Amz-Signature=${randomBytes(32).toString('hex')}` };
        return json(res, 200, { ...poison, slug: 'demo', artifactDigest, uploads: [grant], reused: 1 });
      }
      if (path.endsWith('/publish/commit')) {
        const body = await readJson(req);
        commits.push({ hasActivate: Object.hasOwn(body, 'activate'), activate: body.activate });
        return json(res, 201, { ...poison, slug: 'demo', artifactDigest: body.artifactDigest,
          releaseId: RELEASE, activeReleaseId: body.activate === false ? null : RELEASE });
      }
      if (path.endsWith('/releases')) return json(res, 200, options.releasesResponse ?? {
        ...poison, site: { ...poison, id: rawSiteId, slug: 'demo', activeReleaseId: RELEASE },
        releases: [{ ...poison, ...goodRelease() }, { ...poison, ...goodRelease(), id: OTHER_RELEASE }]
      });
      if (path.includes('/activate/')) return json(res, 200, { ...poison, slug: 'demo', activeReleaseId: RELEASE });
      if (path.startsWith('/v1/uploads/')) {
        for await (const chunk of req) void chunk;
        res.writeHead(204); res.end(); return;
      }
      json(res, 404, {});
    } catch { json(res, 500, { error: 'Synthetic fixture failure' }); }
  });
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  t.after(() => new Promise(resolve => { server.close(resolve); server.closeAllConnections(); }));
  origin = `http://127.0.0.1:${server.address().port}`;
  return { directory, origin, token, forbidden, poison, seen, commits, get artifactDigest() { return artifactDigest; } };
}

for (const bearer of [false, true]) {
  test(`structured publish projects exact fields and preserves ${bearer ? 'marked FS' : 'ordinary object'} upload headers`, async t => {
    const f = await fixture(t, { bearer });
    const result = await remotePublishResult(f.directory, 'demo', f.origin);
    noLeaks(result, f.forbidden);
    const expected = { site: 'demo', artifactDigest: f.artifactDigest, releaseId: RELEASE,
      activeReleaseId: RELEASE, uploaded: 1, reused: 1 };
    matches(result, expected);
    result.site = 'changed'; result.extra = true;
    const fresh = await remotePublishResult(f.directory, 'demo', f.origin);
    noLeaks(fresh, f.forbidden);
    matches(fresh, expected);
    assert.ok(fresh !== result, 'publish returns a fresh object');
    const formatted = await remotePublish(f.directory, 'demo', f.origin);
    noLeaks(formatted, f.forbidden);
    matches(formatted, `Published ${RELEASE}\nArtifact ${f.artifactDigest}\nUploaded 1 blob(s), reused 1`);
    assert.ok(f.seen.every(req => !req.leaked), 'token never enters URLs or unrelated headers');
    assert.ok(f.seen.filter(req => req.method !== 'PUT').every(req => req.authorized), 'control requests stay authenticated');
    assert.ok(f.seen.filter(req => req.method === 'PUT').every(req =>
      req.hasAuthorization === bearer && req.authorized === bearer && req.contentType === undefined),
    'only explicitly marked FS uploads carry bearer auth, never control JSON headers');
  });
}

test('publish structured and formatted calls send activate:false only for literal false', async t => {
  const f = await fixture(t);
  for (const publish of [remotePublishResult, remotePublish]) {
    for (const options of [undefined, {}, { activate: undefined }, { activate: true }, { activate: false },
      { activate: null }, { activate: 0 }, { activate: '' }, { activate: 'false' }]) {
      const result = await publish(f.directory, 'demo', f.origin, options);
      noLeaks(result, f.forbidden);
      const disabled = options?.activate === false;
      matches(f.commits.at(-1), { hasActivate: disabled, activate: disabled ? false : undefined });
      if (publish === remotePublishResult) {
        matches(result, { site: 'demo', artifactDigest: f.artifactDigest, releaseId: RELEASE,
          activeReleaseId: disabled ? null : RELEASE, uploaded: 1, reused: 1 });
      } else matches(result, `Published ${RELEASE}\nArtifact ${f.artifactDigest}\nUploaded 1 blob(s), reused 1`);
    }
  }
});

test('release results are fresh allowlisted projections and the wrapper keeps exact rows', async t => {
  const options = {};
  const f = await fixture(t, options);
  const result = await remoteReleasesResult('demo', f.origin);
  noLeaks(result, f.forbidden);
  const expected = { site: 'demo', activeReleaseId: RELEASE, releases: [
    { releaseId: RELEASE, artifactDigest: DIGEST, createdAt: TIMESTAMP },
    { releaseId: OTHER_RELEASE, artifactDigest: DIGEST, createdAt: TIMESTAMP }
  ] };
  matches(result, expected);
  result.releases[0].extra = true; result.releases.pop();
  const fresh = await remoteReleasesResult('demo', f.origin);
  noLeaks(fresh, f.forbidden);
  matches(fresh, expected);
  assert.ok(fresh !== result && fresh.releases !== result.releases && fresh.releases[0] !== result.releases[0]);
  const formatted = await remoteReleases('demo', f.origin);
  noLeaks(formatted, f.forbidden);
  matches(formatted, `${RELEASE} *\t${DIGEST}\t${TIMESTAMP}\n${OTHER_RELEASE}\t${DIGEST}\t${TIMESTAMP}`);
  options.releasesResponse = { ...f.poison, site: { ...f.poison, slug: 'demo', activeReleaseId: null }, releases: [] };
  matches(await remoteReleasesResult('demo', f.origin), { site: 'demo', activeReleaseId: null, releases: [] });
  matches(await remoteReleases('demo', f.origin), '');
});

test('activate results contain only site and active release; wrapper remains exact', async t => {
  const f = await fixture(t);
  const expected = { site: 'demo', activeReleaseId: RELEASE };
  const result = await remoteActivateResult(RELEASE, 'demo', f.origin);
  noLeaks(result, f.forbidden); matches(result, expected);
  result.extra = true;
  const fresh = await remoteActivateResult(RELEASE, 'demo', f.origin);
  noLeaks(fresh, f.forbidden); matches(fresh, expected);
  assert.ok(fresh !== result, 'activate returns a fresh object');
  const formatted = await remoteActivate(RELEASE, 'demo', f.origin);
  noLeaks(formatted, f.forbidden); matches(formatted, `Activated ${RELEASE} for demo`);
  assert.ok(f.seen.every(req => req.method === 'POST' && req.authorized));
});

test('release validation rejects a poisoned later row before returning any projected list', async t => {
  const options = {};
  const f = await fixture(t, options);
  for (const field of ['id', 'artifactDigest', 'createdAt']) {
    options.releasesResponse = { site: { slug: 'demo', activeReleaseId: RELEASE },
      releases: [goodRelease(), { ...goodRelease(), [field]: f.token }] };
    for (const releases of [remoteReleasesResult, remoteReleases]) {
      await rejectsSafely(() => releases('demo', f.origin), 'OWA_CLI_RESPONSE', f.forbidden);
    }
  }
  options.releasesResponse.releases[1] = { ...goodRelease(), createdAt: '2023-02-30T22:13:20.000Z' };
  await rejectsSafely(() => remoteReleasesResult('demo', f.origin), 'OWA_CLI_RESPONSE', f.forbidden);
});

test('structured operations and wrappers preserve whitelisted auth errors and fixed formatting', async t => {
  const options = {};
  const f = await fixture(t, options);
  const actions = [
    () => remotePublishResult(f.directory, 'demo', f.origin),
    () => remotePublish(f.directory, 'demo', f.origin),
    () => remoteReleasesResult('demo', f.origin), () => remoteReleases('demo', f.origin),
    () => remoteActivateResult(RELEASE, 'demo', f.origin), () => remoteActivate(RELEASE, 'demo', f.origin)
  ];
  for (const code of ['OWA_AUTH_CONFIG', 'OWA_AUTH_INVALID_TOKEN', 'OWA_AUTH_INVALID_SIGNATURE',
    'OWA_AUTH_EXPIRED', 'OWA_AUTH_MISSING', 'OWA_AUTH_SITE', 'OWA_AUTH_CAPABILITY', 'OWA_AUTH_DEV_ONLY', f.token]) {
    options.errorCode = code;
    const expected = code === f.token ? 'OWA_CLI_HTTP' : code;
    for (const action of actions) matches(await rejectsSafely(action, expected, f.forbidden, 403),
      `artifact: ${expected}: Control-plane request failed (HTTP 403)`);
  }
  delete process.env.OWA_TOKEN;
  for (const action of actions) await rejectsSafely(action, 'OWA_AUTH_MISSING', f.forbidden, 401);
});

test('validateRemoteServer returns only normalized origin without fetching and retains config checks', async t => {
  const f = await fixture(t);
  let fetches = 0;
  t.mock.method(globalThis, 'fetch', () => { fetches++; throw new Error('unexpected fetch'); });
  for (const [input, expected] of [
    [f.origin, f.origin], [`${f.origin}/`, f.origin],
    ['HTTPS://CONTROL.EXAMPLE.INVALID:443/', 'https://control.example.invalid'],
    ['http://localhost:7331/', 'http://localhost:7331'],
    ['http://127.2.3.4:7331', 'http://127.2.3.4:7331'], ['http://[::1]:7331/', 'http://[::1]:7331']
  ]) {
    const result = validateRemoteServer(input);
    noLeaks(result, f.forbidden); matches(result, expected);
    assert.ok(typeof result === 'string', 'no client or token is returned');
  }
  for (const input of [undefined, null, {}, '', 'file:///tmp', '/relative', `${f.origin}/path`,
    `${f.origin}/discard/..`, `${f.origin}?`, `${f.origin}?query=value`, `${f.origin}#`,
    `${f.origin}#fragment`, `${f.origin}\n`, `${f.origin}\\path`,
    f.origin.replace('http://', 'http://@'), f.origin.replace('http://', `http://${f.token}@`),
    'http://192.0.2.1', 'http://example.invalid', 'http://localhost.example.invalid',
    'http://[::ffff:192.0.2.1]', 'http://[::]']) {
    await rejectsSafely(() => validateRemoteServer(input), 'OWA_CLI_CONFIG', f.forbidden);
  }
  for (const token of [`${f.token}\n`, `${f.token} `, `${f.token}/`, f.token.repeat(200)]) {
    process.env.OWA_TOKEN = token;
    await rejectsSafely(() => validateRemoteServer(f.origin), 'OWA_CLI_CONFIG', f.forbidden);
  }
  for (const token of ['', undefined]) {
    if (token === undefined) delete process.env.OWA_TOKEN; else process.env.OWA_TOKEN = token;
    matches(validateRemoteServer('http://example.invalid/'), 'http://example.invalid');
  }
  assert.ok(fetches === 0 && f.seen.length === 0, 'validation never invokes the transport');
});

test('structured and formatted input checks run before packing or network requests', async t => {
  const f = await fixture(t);
  const missingDirectory = join(f.directory, 'missing');
  for (const slug of [undefined, null, 'Demo', 'a'.repeat(64), 'demo\n', 'demo/other', '_demo', 'démo']) {
    for (const action of [
      () => remotePublishResult(missingDirectory, slug, f.origin), () => remotePublish(missingDirectory, slug, f.origin),
      () => remoteReleasesResult(slug, f.origin), () => remoteReleases(slug, f.origin),
      () => remoteActivateResult(RELEASE, slug, f.origin), () => remoteActivate(RELEASE, slug, f.origin)
    ]) await rejectsSafely(action, 'OWA_CLI_INPUT', f.forbidden);
  }
  for (const release of [undefined, null, 'r_bad', `r_${'A'.repeat(20)}`, `${RELEASE}\n`, '../release']) {
    for (const activate of [remoteActivateResult, remoteActivate]) {
      await rejectsSafely(() => activate(release, 'demo', f.origin), 'OWA_CLI_INPUT', f.forbidden);
    }
  }
  for (const publish of [remotePublishResult, remotePublish]) {
    await rejectsSafely(() => publish(missingDirectory, 'demo', `${f.origin}/path`), 'OWA_CLI_CONFIG', f.forbidden);
  }
  assert.ok(f.seen.length === 0, 'invalid inputs cause no HTTP requests');
});
