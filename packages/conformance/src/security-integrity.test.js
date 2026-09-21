import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash, createHmac } from 'node:crypto';
import { once } from 'node:events';
import { createServer, request as httpRequest } from 'node:http';
import { mkdir, mkdtemp, readFile, rm, symlink, writeFile } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { FilesystemBlobStore, FilesystemLeaseStore, FilesystemMetadataStore } from '../../storage-filesystem/src/index.js';
import { S3BlobStore, uploadHeadersFor } from '../../storage-s3/src/index.js';
import {
  IntegrityError, commitManifest, expectedBlobSizes, planManifest, publishDirectory, verifyStoredBlob
} from '../../core/src/index.js';
import { artifactDigest, canonicalJson, sha256, validateManifest } from '../../spec/src/index.js';
import { createContentServer, createControlServer, createDefaultStores } from '../../server/src/index.js';
import { createToken } from '../../server/src/auth.js';
import { remotePublishResult } from '../../cli/src/remote.js';

// Commit-boundary blob integrity (issue #10). Offline, deterministic. The mock
// S3 below ENFORCES the provider contract the design relies on — signature over
// signed headers, checksum against payload bytes, create-once — so the TOCTOU
// regressions prove the protocol shape, not just our own client behavior.

const NOW = 1_800_000_000;
const FIXED = new Date(NOW * 1000);
const SECRET = 'integrity-suite-auth-secret-0123456789abcdef';
const UPLOAD_SECRET = 'integrity-suite-upload-secret-0123456789abc';
const ACCESS = 'AKIDINTEGRITY';
const PROVIDER_SECRET = 'integrity-provider-secret-never-real-0123456789';
const b64 = bytes => createHash('sha256').update(bytes).digest('base64');

function manifestFor(files) {
  const manifest = {
    specVersion: 'owa.dev/v1',
    artifactType: 'application/vnd.openwebartifact.site.v1+json',
    entrypoint: files[0].path,
    files: files.map(file => ({
      path: file.path, digest: file.digest ?? sha256(file.bytes), size: file.size ?? file.bytes.length, mediaType: file.mediaType ?? 'text/html'
    })),
    access: { visibility: 'public' },
    lifecycle: { expiresAt: null }
  };
  validateManifest(manifest);
  return manifest;
}
const single = bytes => manifestFor([{ path: '/index.html', bytes }]);

// ------------------------------------------------------------- mock S3 ----

/** Independent SigV4 for a presigned PUT over the signed headers the URL names. */
function presignedSignature(url, sentHeaders, secret, region) {
  const enc = v => encodeURIComponent(v).replace(/[!'()*]/g, c => `%${c.charCodeAt(0).toString(16).toUpperCase()}`);
  const params = [...url.searchParams].filter(([n]) => n !== 'X-Amz-Signature').sort(([a, av], [b, bv]) => a === b ? av.localeCompare(bv) : a.localeCompare(b));
  const query = params.map(([n, v]) => `${enc(n)}=${enc(v)}`).join('&');
  const names = url.searchParams.get('X-Amz-SignedHeaders').split(';');
  const values = { host: url.host, ...sentHeaders };
  for (const name of names) if (values[name] === undefined) return null; // A signed header is missing.
  const canonical = ['PUT', url.pathname, query, names.map(n => `${n}:${String(values[n]).trim()}\n`).join(''), names.join(';'), 'UNSIGNED-PAYLOAD'].join('\n');
  const ts = url.searchParams.get('X-Amz-Date'), date = ts.slice(0, 8), scope = `${date}/${region}/s3/aws4_request`;
  const sts = ['AWS4-HMAC-SHA256', ts, scope, createHash('sha256').update(canonical).digest('hex')].join('\n');
  const h = (k, d) => createHmac('sha256', k).update(d).digest();
  return createHmac('sha256', h(h(h(h(`AWS4${secret}`, date), region), 's3'), 'aws4_request')).update(sts).digest('hex');
}

/**
 * An S3/R2-shaped provider that behaves the way the live R2 probe proved:
 * checksum validated against payload (400 BadDigest), signed headers enforced
 * (403), If-None-Match honoured (412), SHA-256 evidence on HEAD only when the
 * last write was checksum-validated, GetObjectAttributes unsupported.
 */
// `checksumEvidence` and `directUploadIntegrity` default to 'enforced' because
// this mock DOES enforce the full contract, like R2; pass 'auto' to exercise the
// store's own conservative defaults for its loopback endpoint. `echo` models a
// lax provider that stores the caller's claimed checksum without validating it
// and later echoes it on HEAD; `weak` additionally ignores If-None-Match — an
// unknown provider with no usable direct-upload semantics at all.
async function mockS3(t, { region = 'auto', checksumEvidence = 'enforced', directUploadIntegrity = 'enforced', echo = false, weak = false } = {}) {
  const objects = new Map();
  const log = [];
  let fail = null;
  const xml = code => `<Error><Code>${code}</Code><Message>provider-detail-must-not-leak</Message></Error>`;
  const server = createServer(async (req, res) => {
    const url = new URL(req.url, 'http://mock');
    const key = url.pathname;
    const auth = req.headers.authorization ?? '';
    log.push({
      method: req.method, key, presigned: url.searchParams.has('X-Amz-Signature'),
      authScheme: auth ? auth.split(' ')[0] : null,
      signedHeaders: url.searchParams.get('X-Amz-SignedHeaders') ?? (auth.match(/SignedHeaders=([^,]+)/)?.[1] ?? null),
      hasChecksumHeader: 'x-amz-checksum-sha256' in req.headers, hasIfNoneMatch: 'if-none-match' in req.headers,
      hasSecurityToken: 'x-amz-security-token' in req.headers || url.searchParams.has('X-Amz-Security-Token')
    });
    const chunks = []; for await (const c of req) chunks.push(c); const body = Buffer.concat(chunks);
    if (fail === 'error' && req.method !== 'DELETE') { res.writeHead(500, { 'content-type': 'application/xml' }); return res.end(xml('InternalError')); }
    if (req.method === 'PUT') {
      if (url.searchParams.has('X-Amz-Signature')) {
        const expected = presignedSignature(url, req.headers, PROVIDER_SECRET, region);
        if (expected === null || expected !== url.searchParams.get('X-Amz-Signature')) { res.writeHead(403); return res.end(xml('SignatureDoesNotMatch')); }
      }
      if (!weak && req.headers['if-none-match'] === '*' && objects.has(key)) { res.writeHead(412); return res.end(xml('PreconditionFailed')); }
      const claimed = req.headers['x-amz-checksum-sha256'];
      if (!echo && !weak && claimed !== undefined && claimed !== b64(body)) { res.writeHead(400); return res.end(xml('BadDigest')); }
      objects.set(key, { bytes: body, checksum: claimed !== undefined ? claimed : null });
      res.writeHead(200); return res.end();
    }
    const object = objects.get(key);
    if (req.method === 'HEAD') {
      if (!object) { res.writeHead(404); return res.end(); }
      const headers = { 'content-length': String(object.bytes.length), 'x-amz-checksum-crc64nvme': 'ignored' };
      if (object.checksum && req.headers['x-amz-checksum-mode'] === 'ENABLED') headers['x-amz-checksum-sha256'] = object.checksum;
      res.writeHead(200, headers); return res.end();
    }
    if (req.method === 'GET') {
      if (url.searchParams.has('attributes')) { res.writeHead(501); return res.end(xml('NotImplemented')); }
      if (!object) { res.writeHead(404); return res.end(); }
      res.writeHead(200, { 'content-length': String(object.bytes.length) }); return res.end(object.bytes);
    }
    if (req.method === 'DELETE') { objects.delete(key); res.writeHead(204); return res.end(); }
    res.writeHead(400); res.end();
  });
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  t.after(() => new Promise(resolve => { server.closeAllConnections(); server.close(() => resolve()); }));
  const origin = `http://127.0.0.1:${server.address().port}`;
  const auto = value => value === 'auto' ? undefined : value;
  const store = new S3BlobStore({ endpoint: origin, bucket: 'bucket', region, accessKeyId: ACCESS, secretAccessKey: PROVIDER_SECRET, prefix: 'owa', now: () => FIXED, checksumEvidence: auto(checksumEvidence), directUploadIntegrity: auto(directUploadIntegrity) });
  return {
    origin, store, objects, log,
    /** A second store over the same objects with a different trust setting. */
    storeWith(evidence, extra = {}) { return new S3BlobStore({ endpoint: origin, bucket: 'bucket', region, accessKeyId: ACCESS, secretAccessKey: PROVIDER_SECRET, prefix: 'owa', now: () => FIXED, checksumEvidence: evidence, directUploadIntegrity: 'enforced', ...extra }); },
    deletes() { return log.filter(r => r.method === 'DELETE').length; },
    writes() { return log.filter(r => r.method === 'PUT').length; },
    /** Plant an object directly, bypassing every OWA write path. */
    plant(digest, bytes, { checksum = false } = {}) { objects.set(store.urlForKey(store.key(digest)).pathname, { bytes: Buffer.from(bytes), checksum: checksum ? b64(bytes) : null }); },
    remove(digest) { objects.delete(store.urlForKey(store.key(digest)).pathname); },
    bytesOf(digest) { return objects.get(store.urlForKey(store.key(digest)).pathname)?.bytes ?? null; },
    setFail(mode) { fail = mode; },
    reset() { log.length = 0; }
  };
}

async function fsEnv(t) {
  const root = await mkdtemp(join(tmpdir(), 'owa-integrity-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  return { root, blobs: new FilesystemBlobStore(root), metadata: new FilesystemMetadataStore(root), leases: new FilesystemLeaseStore(root) };
}
const codeOf = async promise => { try { await promise; return 'OK'; } catch (error) { return error?.code ?? `THREW:${error?.message}`; } };

// ------------------------------------------------------ filesystem 1-5 ----

test('1-5. filesystem verification: correct passes; missing, wrong size, wrong bytes, symlink and directory fail', async t => {
  const e = await fsEnv(t);
  const good = Buffer.from('filesystem integrity payload'), digest = sha256(good);
  assert.equal(await codeOf(e.blobs.verifyBlob({ digest, size: good.length })), 'OWA_BLOB_MISSING', '2. missing');
  await e.blobs.put(digest, good);
  assert.deepEqual(await e.blobs.verifyBlob({ digest, size: good.length }), { ok: true, method: 'rehash' }, '1. correct bytes verify');
  assert.equal(await codeOf(e.blobs.verifyBlob({ digest, size: good.length + 1 })), 'OWA_BLOB_INTEGRITY', '3. declared size disagrees');
  await writeFile(e.blobs.path(digest), Buffer.from('filesystem integrity PAYLOAD')); // same length, different bytes
  assert.equal(await codeOf(e.blobs.verifyBlob({ digest, size: good.length })), 'OWA_BLOB_INTEGRITY', '4. same-size wrong content');
  await writeFile(e.blobs.path(digest), Buffer.from('short'));
  assert.equal(await codeOf(e.blobs.verifyBlob({ digest, size: good.length })), 'OWA_BLOB_INTEGRITY', '3b. stored size disagrees');

  // 5. a symlink named as the digest can never satisfy verification, even when
  // its target holds exactly the right bytes; the target is never modified.
  const outside = await mkdtemp(join(tmpdir(), 'owa-integrity-outside-'));
  t.after(() => rm(outside, { recursive: true, force: true }));
  const target = join(outside, 'real-bytes');
  await writeFile(target, good);
  await rm(e.blobs.path(digest));
  await symlink(target, e.blobs.path(digest));
  assert.equal(await codeOf(e.blobs.verifyBlob({ digest, size: good.length })), 'OWA_BLOB_UNVERIFIED', '5. symlink is not a regular file');
  assert.ok(Buffer.from(await readFile(target)).equals(good), 'symlink target untouched');
  await rm(e.blobs.path(digest));
  await mkdir(e.blobs.path(digest));
  assert.equal(await codeOf(e.blobs.verifyBlob({ digest, size: good.length })), 'OWA_BLOB_UNVERIFIED', '5b. directory is not a regular file');
  // Malformed inputs never pass.
  assert.equal(await codeOf(e.blobs.verifyBlob({ digest: 'sha256:zz', size: 1 })), 'OWA_BLOB_UNVERIFIED');
  assert.equal(await codeOf(e.blobs.verifyBlob({ digest, size: -1 })), 'OWA_BLOB_UNVERIFIED');
});

test('filesystem verification streams the file rather than buffering it', async t => {
  const e = await fsEnv(t);
  const big = Buffer.alloc(3 * 1024 * 1024, 7); // spans many read chunks
  const digest = sha256(big);
  await e.blobs.put(digest, big);
  assert.deepEqual(await e.blobs.verifyBlob({ digest, size: big.length }), { ok: true, method: 'rehash' });
  big[big.length - 1] ^= 1;
  await writeFile(e.blobs.path(digest), big);
  assert.equal(await codeOf(e.blobs.verifyBlob({ digest, size: big.length })), 'OWA_BLOB_INTEGRITY', 'a single flipped trailing bit is caught');
});

// ------------------------------------------------------------- core 6-14 ----

test('6. a digest shared by several manifest paths is verified exactly once per commit', async t => {
  const e = await fsEnv(t);
  const bytes = Buffer.from('shared bytes'), digest = sha256(bytes);
  await e.blobs.put(digest, bytes);
  let calls = 0;
  const counting = Object.create(e.blobs);
  counting.verifyBlob = async args => { calls++; return e.blobs.verifyBlob(args); };
  const manifest = manifestFor([{ path: '/a.html', bytes }, { path: '/b.html', bytes }, { path: '/c/d.html', bytes }]);
  await commitManifest({ slug: 'dup', manifest, blobs: counting, metadata: e.metadata });
  assert.equal(calls, 1, 'one verification for three paths');
});

test('7. the same digest declared with conflicting sizes fails closed before any mutation or grant', async t => {
  const e = await fsEnv(t);
  const bytes = Buffer.from('conflict bytes'), digest = sha256(bytes);
  await e.blobs.put(digest, bytes);
  const manifest = manifestFor([{ path: '/a.html', bytes }, { path: '/b.html', bytes, size: bytes.length + 1 }]);
  assert.throws(() => expectedBlobSizes(manifest), error => error instanceof IntegrityError && error.code === 'OWA_BLOB_INTEGRITY');
  assert.equal(await codeOf(commitManifest({ slug: 'conflict', manifest, blobs: e.blobs, metadata: e.metadata })), 'OWA_BLOB_INTEGRITY');
  assert.equal(await e.metadata.getSite('conflict'), null, 'no site record');
  let grants = 0;
  assert.equal(await codeOf(planManifest({ manifest, blobs: e.blobs, uploadFactory: async () => { grants++; } })), 'OWA_BLOB_INTEGRITY');
  assert.equal(grants, 0, 'plan fails before minting any grant');
});

test('8-11. integrity failure never creates a site, release or activation, and never touches an existing site', async t => {
  const e = await fsEnv(t);
  const good = Buffer.from('good release bytes'), digest = sha256(good);
  const cases = {
    'missing blob': async () => {},
    'wrong-size blob': async () => e.blobs.put(digest, Buffer.from('short')),
    'same-size wrong-digest blob': async () => e.blobs.put(digest, Buffer.from('GOOD release bytes')),
    'unverifiable backend proof': async () => { await e.blobs.put(digest, good); e.blobs.verifyBlob = async () => { throw new Error('backend exploded: /secret/path'); }; }
  };
  for (const [name, arrange] of Object.entries(cases)) {
    await t.test(`brand-new slug: ${name}`, async () => {
      const store = new FilesystemBlobStore(e.root);
      Object.assign(e, { blobs: store });
      await arrange();
      const slug = `fresh-${Object.keys(cases).indexOf(name)}`;
      const code = await codeOf(commitManifest({ slug, manifest: single(good), blobs: e.blobs, metadata: e.metadata }));
      assert.ok(code.startsWith('OWA_BLOB_'), `fails with a fixed integrity code (${code})`);
      assert.equal(await e.metadata.getSite(slug), null, '8. no site record');
      assert.equal(existsSync(join(e.root, 'sites-by-slug', `${slug}.json`)), false, '9/10. no release and no activation pointer (no site directory at all)');
      await rm(e.blobs.path(digest), { force: true });
    });
  }

  await t.test('existing site: failed commit leaves releases and activeReleaseId untouched', async () => {
    const blobs = new FilesystemBlobStore(e.root);
    await blobs.put(digest, good);
    const first = await commitManifest({ slug: 'existing', manifest: single(good), blobs, metadata: e.metadata });
    const before = await e.metadata.getSite('existing');
    const releasesBefore = await e.metadata.listAllReleases(before.id);
    // Now a second manifest whose blob is corrupt.
    const other = Buffer.from('second release bytes'), otherDigest = sha256(other);
    await blobs.put(otherDigest, Buffer.from('SECOND release bytes'));
    assert.equal(await codeOf(commitManifest({ slug: 'existing', manifest: single(other), blobs, metadata: e.metadata })), 'OWA_BLOB_INTEGRITY');
    const after = await e.metadata.getSite('existing');
    assert.deepEqual(after, before, '11. site record and activeReleaseId unchanged');
    assert.equal(after.activeReleaseId, first.release.id);
    assert.deepEqual(await e.metadata.listAllReleases(before.id), releasesBefore, 'no release added or altered');
  });
});

test('12-14. a valid commit produces the pre-change release shape, digest and canonical bytes', async t => {
  const e = await fsEnv(t);
  const good = Buffer.from('shape check bytes'), digest = sha256(good);
  await e.blobs.put(digest, good);
  const manifest = single(good);
  const { site, release } = await commitManifest({ slug: 'shape', manifest, blobs: e.blobs, metadata: e.metadata });
  assert.deepEqual(Object.keys(release).sort(), ['artifactDigest', 'createdAt', 'id', 'manifest'], '12. release record shape unchanged');
  assert.equal(release.artifactDigest, artifactDigest(manifest), '13. artifactDigest is the spec digest of the manifest');
  assert.equal(release.artifactDigest, `sha256:${createHash('sha256').update(canonicalJson(manifest)).digest('hex')}`, '13. …and the SHA-256 of canonical JSON');
  assert.equal(canonicalJson(release.manifest), canonicalJson(manifest), '14. canonical manifest bytes unchanged');
  assert.ok(!JSON.stringify(release).includes('verif') && !JSON.stringify(release).includes('method'), 'no verification metadata enters the release');
  assert.equal(site.activeReleaseId, release.id);
});

// ------------------------------------------------------ recovery 15-17 ----

test('15-17. filesystem: a corrupt existing CAS object is repaired by the next publish and reused afterwards', async t => {
  const e = await fsEnv(t);
  const good = Buffer.from('repairable bytes'), digest = sha256(good);
  await e.blobs.put(digest, Buffer.from('REPAIRABLE bytes')); // same length, wrong content
  const manifest = single(good);
  let grants = 0;
  const plan = await planManifest({ manifest, blobs: e.blobs, leases: e.leases, uploadFactory: async d => { grants++; return { digest: d, method: 'PUT', url: 'http://127.0.0.1/x', expiresIn: 60 }; } });
  assert.equal(plan.reused, 0, '15. a corrupt object is NOT reported reusable');
  assert.equal(plan.uploads.length, 1);
  assert.equal(await e.blobs.has(digest), true, 'plan is NON-destructive: the corrupt object is left in place for the repair upload');
  assert.equal(grants, 1);
  // Client uploads the right bytes (local route path) and commits.
  await e.blobs.put(digest, good);
  const { release } = await commitManifest({ slug: 'repair', manifest, blobs: e.blobs, metadata: e.metadata });
  assert.equal(release.artifactDigest, artifactDigest(manifest), '16. repaired object commits');
  const again = await planManifest({ manifest, blobs: e.blobs, leases: e.leases, uploadFactory: async () => { throw new Error('must not upload'); } });
  assert.equal(again.reused, 1, '17. identical re-publish reuses normally');
  assert.equal(again.uploads.length, 0);
});

test('plan does not destroy an object it cannot verify: UNVERIFIED fails the plan rather than deleting', async t => {
  const e = await fsEnv(t);
  const good = Buffer.from('unverifiable'), digest = sha256(good);
  await e.blobs.put(digest, good);
  const flaky = Object.create(e.blobs);
  flaky.verifyBlob = async () => { throw Object.assign(new Error('transient'), { code: 'OWA_BLOB_UNVERIFIED' }); };
  let deleted = 0; flaky.delete = async () => { deleted++; };
  assert.equal(await codeOf(planManifest({ manifest: single(good), blobs: flaky, uploadFactory: async () => ({}) })), 'OWA_BLOB_UNVERIFIED');
  assert.equal(deleted, 0, 'a possibly-valid object is never deleted on an unverifiable probe');
  assert.equal(await e.blobs.has(digest), true);
});

test('publishDirectory reuses only verified blobs and rewrites a corrupt one with the packed bytes', async t => {
  const e = await fsEnv(t);
  const directory = join(e.root, 'site');
  await mkdir(directory, { recursive: true });
  const good = Buffer.from('<h1>local publish</h1>');
  await writeFile(join(directory, 'index.html'), good);
  const digest = sha256(good);
  await e.blobs.put(digest, Buffer.from('<h1>LOCAL publish</h1>'));
  const first = await publishDirectory({ directory, slug: 'local', blobs: e.blobs, metadata: e.metadata, leases: e.leases });
  assert.equal(first.uploaded, 1, 'corrupt existing blob is rewritten, not reused');
  assert.ok(Buffer.from(await e.blobs.get(digest)).equals(good));
  const second = await publishDirectory({ directory, slug: 'local', blobs: e.blobs, metadata: e.metadata, leases: e.leases });
  assert.equal(second.reused, 1);
  assert.equal(second.uploaded, 0);
});

// ------------------------------------------------------------- S3 18-23 ----

test('18-23. S3 verification: wrong size, wrong content, missing, redaction, storage credentials only', async t => {
  const m = await mockS3(t);
  const good = Buffer.from('s3 integrity payload'), digest = sha256(good);

  await t.test('20. missing', async () => {
    assert.equal(await codeOf(m.store.verifyBlob({ digest, size: good.length })), 'OWA_BLOB_MISSING');
  });
  await t.test('18. a valid object with provider evidence and a WRONG declared size is a manifest fault, decided on HEAD alone', async () => {
    m.plant(digest, good, { checksum: true });
    m.reset();
    let caught; try { await m.store.verifyBlob({ digest, size: good.length + 1 }); } catch (error) { caught = error; }
    assert.equal(caught?.code, 'OWA_BLOB_INTEGRITY');
    assert.equal(caught?.reason, 'size', 'the OBJECT is valid; the declared size is wrong');
    assert.deepEqual(m.log.map(r => r.method), ['HEAD'], 'no payload transfer needed');
  });
  await t.test('18b. a shorter object with no evidence is rehashed and attributed to the OBJECT', async () => {
    m.plant(digest, Buffer.from('short'));
    m.reset();
    let caught; try { await m.store.verifyBlob({ digest, size: good.length }); } catch (error) { caught = error; }
    assert.equal(caught?.code, 'OWA_BLOB_INTEGRITY');
    assert.equal(caught?.reason, 'digest', 'the bytes do not hash to the key');
    assert.deepEqual(m.log.map(r => r.method), ['HEAD', 'GET']);
  });
  await t.test('19. same-size wrong content with no provider evidence is caught by streaming rehash', async () => {
    m.plant(digest, Buffer.from('S3 INTEGRITY PAYLOAD'));
    m.reset();
    assert.equal(await codeOf(m.store.verifyBlob({ digest, size: good.length })), 'OWA_BLOB_INTEGRITY');
    assert.deepEqual(m.log.map(r => r.method), ['HEAD', 'GET']);
  });
  await t.test('provider-validated checksum evidence verifies with zero payload bytes', async () => {
    m.plant(digest, good, { checksum: true });
    m.reset();
    assert.deepEqual(await m.store.verifyBlob({ digest, size: good.length }), { ok: true, method: 'provider-checksum' });
    assert.deepEqual(m.log.map(r => r.method), ['HEAD'], 'no GET when the provider vouches for the SHA-256');
  });
  await t.test('correct bytes without evidence verify by rehash', async () => {
    m.plant(digest, good);
    m.reset();
    assert.deepEqual(await m.store.verifyBlob({ digest, size: good.length }), { ok: true, method: 'rehash' });
    assert.deepEqual(m.log.map(r => r.method), ['HEAD', 'GET']);
  });
  await t.test('an object longer than declared is rehashed in full and attributed to the OBJECT', async () => {
    m.plant(digest, Buffer.concat([good, Buffer.from('extra')]));
    let caught; try { await m.store.verifyBlob({ digest, size: good.length }); } catch (error) { caught = error; }
    assert.equal(caught?.code, 'OWA_BLOB_INTEGRITY');
    assert.equal(caught?.reason, 'digest');
  });
  await t.test('21. provider failures are redacted to a fixed code', async () => {
    m.plant(digest, good);
    m.setFail('error');
    let caught;
    try { await m.store.verifyBlob({ digest, size: good.length }); } catch (error) { caught = error; }
    m.setFail(null);
    assert.equal(caught?.code, 'OWA_BLOB_UNVERIFIED');
    assert.ok(!String(caught?.message).includes('provider-detail-must-not-leak') && !String(caught?.message).includes('InternalError'), 'no provider body in the error');
    // Through core the message is also fixed and digest-only.
    const viaCore = await verifyStoredBlob(Object.assign(Object.create(m.store), { verifyBlob: async () => { throw Object.assign(new Error('<Error>secret</Error>'), { code: 'OWA_BLOB_UNVERIFIED' }); } }), digest, good.length).catch(e => e);
    assert.ok(viaCore instanceof IntegrityError && !viaCore.message.includes('secret'));
  });
  await t.test('22-23. every verification request used storage SigV4 and none carried a Bearer', async () => {
    assert.ok(m.log.length > 0);
    assert.ok(m.log.every(r => r.authScheme === 'AWS4-HMAC-SHA256' || r.presigned), 'storage credentials only');
    assert.ok(m.log.every(r => r.authScheme !== 'Bearer'), 'zero OWA bearer reaches storage');
  });
});

// ------------------------------------------------- grant / TOCTOU 24-29 ----

test('24-29. checksum-bound create-once grant: header required, tamper rejected, wrong bytes rejected, post-commit reuse cannot corrupt', async t => {
  const m = await mockS3(t);
  const root = await mkdtemp(join(tmpdir(), 'owa-integrity-meta-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  const metadata = new FilesystemMetadataStore(root);
  const good = Buffer.from('grant-bound payload bytes'), digest = sha256(good);
  const wrong = Buffer.from(good.map(b => b ^ 0xff)); // same length
  const grant = await m.store.createUpload(digest, { expires: 600 });
  const put = (body, headers) => fetch(grant.url, { method: 'PUT', headers, body }).then(async r => { await r.arrayBuffer(); return r.status; });

  assert.deepEqual(grant.headers, uploadHeadersFor(digest), '24. grant declares exactly the required headers');
  assert.deepEqual(Object.keys(grant.headers).sort(), ['if-none-match', 'x-amz-checksum-sha256']);
  assert.equal(grant.headers['x-amz-checksum-sha256'], b64(good), 'checksum header is the base64 SHA-256 the digest names');
  assert.equal(new URL(grant.url).searchParams.get('X-Amz-SignedHeaders'), 'host;if-none-match;x-amz-checksum-sha256');
  assert.ok(!Object.hasOwn(grant, 'authorization') && !JSON.stringify(grant).toLowerCase().includes('bearer'), 'no OWA material on a storage grant');

  assert.equal(await put(good, {}), 403, '25. omitting a signed header invalidates the signature');
  assert.equal(await put(good, { ...grant.headers, 'x-amz-checksum-sha256': b64(wrong) }), 403, '26. changing the signed checksum header invalidates the signature');
  assert.equal(await put(wrong, grant.headers), 400, '27. wrong payload bytes are rejected by the provider (BadDigest)');
  assert.equal(m.bytesOf(digest), null, 'nothing was stored by the rejected attempts');
  assert.equal(await put(good, grant.headers), 200, '28. correct payload is accepted');
  assert.ok(m.bytesOf(digest).equals(good));

  const { release } = await commitManifest({ slug: 'grant', manifest: single(good), blobs: m.store, metadata });
  assert.equal(release.artifactDigest, artifactDigest(single(good)), 'commit verifies via provider checksum evidence');

  // 29. THE POST-COMMIT TOCTOU: the very same still-valid grant is reused.
  assert.equal(await put(wrong, grant.headers), 412, '29a. create-once: an existing object is never overwritten by the grant');
  assert.equal(await put(good, grant.headers), 412, '29b. …not even with the right bytes');
  assert.ok(m.bytesOf(digest).equals(good), '29c. committed CAS bytes are byte-identical after the reuse attempts');
  assert.deepEqual(await m.store.verifyBlob({ digest, size: good.length }), { ok: true, method: 'provider-checksum' }, 'serving-side verification still passes');
});

test('S3 recovery: a corrupt existing CAS object is deleted by plan, replaced through a create-once grant, then reused', async t => {
  const m = await mockS3(t);
  const root = await mkdtemp(join(tmpdir(), 'owa-integrity-meta2-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  const metadata = new FilesystemMetadataStore(root), leases = new FilesystemLeaseStore(root);
  const good = Buffer.from('s3 repairable bytes'), digest = sha256(good);
  m.plant(digest, Buffer.from('S3 REPAIRABLE BYTES')); // same length, wrong, no evidence
  const manifest = single(good);
  const plan = await planManifest({ manifest, blobs: m.store, leases, uploadFactory: (d, options) => m.store.createUpload(d, { expires: 600, ...options }) });
  assert.equal(plan.reused, 0, 'corrupt object is not reusable');
  assert.equal(plan.uploads.length, 1);
  assert.equal(m.deletes(), 0, 'plan issued no DELETE');
  assert.ok(m.bytesOf(digest).equals(Buffer.from('S3 REPAIRABLE BYTES')), 'plan is NON-destructive: the corrupt object is left in place');
  const repair = plan.uploads[0];
  assert.deepEqual(repair.headers, uploadHeadersFor(digest, { repair: true }), 'a REPAIR grant: checksum-bound, without create-once');
  assert.deepEqual(Object.keys(repair.headers), ['x-amz-checksum-sha256']);
  const put = (body, headers = repair.headers) => fetch(repair.url, { method: 'PUT', headers, body }).then(async r => { await r.arrayBuffer(); return r.status; });
  assert.equal(await put(Buffer.from('S3 REPAIRABLE BYTES')), 400, 'the repair grant still refuses wrong bytes');
  assert.equal(await put(good, {}), 403, 'and still requires its signed checksum header');
  assert.equal(await put(good), 200, 'correct bytes replace the corrupt object');
  assert.ok(m.bytesOf(digest).equals(good));
  await commitManifest({ slug: 's3repair', manifest, blobs: m.store, metadata });
  // Repair-grant replay after commit: wrong bytes fail; correct bytes are harmless.
  assert.equal(await put(Buffer.from('S3 REPAIRABLE BYTES')), 400, 'post-commit replay with wrong bytes is refused');
  assert.equal(await put(good), 200, 'post-commit replay with the same correct bytes is allowed and harmless');
  assert.ok(m.bytesOf(digest).equals(good), 'committed bytes remain correct after both replays');
  const again = await planManifest({ manifest, blobs: m.store, leases, uploadFactory: async () => { throw new Error('must not upload'); } });
  assert.equal(again.reused, 1, 'repaired object is reused; no infinite reuse/reject loop');
});

// ------------------------------------------------------- presign 30-31 ----

test('30-31. presign without headers is unchanged and deterministic; session tokens stay signed for grants and verification', async t => {
  const plain = new S3BlobStore({ endpoint: 'https://acct.r2.cloudflarestorage.com', bucket: 'b', region: 'auto', accessKeyId: ACCESS, secretAccessKey: PROVIDER_SECRET, now: () => FIXED });
  const a = new URL(plain.presign('PUT', plain.key(sha256(Buffer.from('x'))), { expires: 900 }));
  const b = new URL(plain.presign('PUT', plain.key(sha256(Buffer.from('x'))), { expires: 900 }));
  assert.equal(a.searchParams.get('X-Amz-SignedHeaders'), 'host', '30. header-less presign still signs only host');
  assert.equal(a.href, b.href, '30. deterministic for fixed inputs');
  const withHeaders = new URL(plain.presign('PUT', plain.key(sha256(Buffer.from('x'))), { expires: 900, headers: uploadHeadersFor(sha256(Buffer.from('x'))) }));
  assert.notEqual(withHeaders.searchParams.get('X-Amz-Signature'), a.searchParams.get('X-Amz-Signature'), 'signing headers changes the signature');

  const m = await mockS3(t);
  const withToken = new S3BlobStore({ endpoint: m.origin, bucket: 'bucket', region: 'auto', accessKeyId: ACCESS, secretAccessKey: PROVIDER_SECRET, sessionToken: 'session-token-value', now: () => FIXED, directUploadIntegrity: 'enforced' });
  const grant = await withToken.createUpload(sha256(Buffer.from('y')), { expires: 600 });
  assert.equal(new URL(grant.url).searchParams.get('X-Amz-Security-Token'), 'session-token-value', '31. grant carries the session token');
  m.plant(sha256(Buffer.from('y')), Buffer.from('y'), { checksum: true });
  m.reset();
  await withToken.verifyBlob({ digest: sha256(Buffer.from('y')), size: 1 });
  assert.ok(m.log.every(r => r.hasSecurityToken && /x-amz-security-token/.test(r.signedHeaders)), '31. verification requests sign and send the session token');
});

// -------------------------------------------------------------- CLI ------

async function cliEnv(t, m) {
  const root = await mkdtemp(join(tmpdir(), 'owa-integrity-cli-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  const directory = join(root, 'site');
  await mkdir(directory, { recursive: true });
  const metadata = new FilesystemMetadataStore(join(root, 'meta')), leases = new FilesystemLeaseStore(join(root, 'meta'));
  const server = createControlServer({ blobs: m.store, metadata, leases, uploadSecret: UPLOAD_SECRET, auth: { secret: SECRET, now: () => NOW } });
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  t.after(() => new Promise(resolve => { server.closeAllConnections(); server.close(() => resolve()); }));
  const previous = process.env.OWA_TOKEN;
  process.env.OWA_TOKEN = createToken({ secret: SECRET, jti: 'integrity', exp: NOW + 600, sites: ['demo'], capabilities: ['plan', 'upload', 'commit', 'activate', 'read'], now: () => NOW });
  t.after(() => { if (previous === undefined) delete process.env.OWA_TOKEN; else process.env.OWA_TOKEN = previous; });
  return { directory, metadata, origin: `http://127.0.0.1:${server.address().port}` };
}

test('CLI sends exactly the grant storage headers, never a bearer, and the published bytes verify', async t => {
  const m = await mockS3(t);
  const c = await cliEnv(t, m);
  await writeFile(join(c.directory, 'index.html'), '<h1>cli integrity</h1>');
  await writeFile(join(c.directory, 'app.js'), 'console.log(1)');
  const result = await remotePublishResult(c.directory, 'demo', c.origin);
  assert.equal(result.uploaded, 2);
  const puts = m.log.filter(r => r.method === 'PUT' && r.presigned);
  assert.equal(puts.length, 2);
  assert.ok(puts.every(r => r.hasChecksumHeader && r.hasIfNoneMatch), 'CLI sent both required storage headers');
  assert.ok(m.log.every(r => r.authScheme !== 'Bearer'), 'no OWA bearer reached storage');
  // Every stored object carries provider checksum evidence, so re-publish verifies by HEAD alone.
  m.reset();
  const again = await remotePublishResult(c.directory, 'demo', c.origin);
  assert.equal(again.reused, 2);
  assert.equal(again.uploaded, 0);
  assert.ok(!m.log.some(r => r.method === 'GET'), 'identical re-publish needed no payload re-download');
});

test('CLI treats a create-once 412 as already-uploaded, and commit still verifies', async t => {
  const m = await mockS3(t);
  const c = await cliEnv(t, m);
  const bytes = Buffer.from('<h1>pre-existing</h1>');
  await writeFile(join(c.directory, 'index.html'), bytes);
  // Object appears (correct bytes) between plan and PUT — e.g. a concurrent publisher.
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async (url, options) => {
    if (options?.method === 'PUT' && String(url).includes('X-Amz-Signature')) m.plant(sha256(bytes), bytes, { checksum: true });
    return originalFetch(url, options);
  };
  t.after(() => { globalThis.fetch = originalFetch; });
  const result = await remotePublishResult(c.directory, 'demo', c.origin);
  assert.equal(result.uploaded, 1, 'the CLI counts the grant as satisfied');
  assert.ok(m.log.some(r => r.method === 'PUT' && r.presigned), 'a PUT was attempted and answered 412 by the provider');
});

test('CLI rejects grants whose headers are not exactly the integrity-binding set', async t => {
  const m = await mockS3(t);
  const root = await mkdtemp(join(tmpdir(), 'owa-integrity-tamper-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  const directory = join(root, 'site');
  await mkdir(directory, { recursive: true });
  const bytes = Buffer.from('<h1>tamper</h1>');
  await writeFile(join(directory, 'index.html'), bytes);
  const digest = sha256(bytes);
  let tamper = null, puts = 0;
  // A hostile/buggy control plane that returns crafted grants.
  const control = createServer(async (req, res) => {
    const chunks = []; for await (const c of req) chunks.push(c);
    if (req.method === 'PUT') { puts++; res.writeHead(204); return res.end(); }
    const body = JSON.parse(Buffer.concat(chunks).toString() || '{}');
    if (req.url.endsWith('/plan')) {
      const grant = await m.store.createUpload(digest, { expires: 600 });
      const crafted = tamper(grant);
      res.writeHead(200, { 'content-type': 'application/json' });
      return res.end(JSON.stringify({ slug: 'demo', artifactDigest: body.artifactDigest, uploads: [crafted], reused: 0 }));
    }
    res.writeHead(500, { 'content-type': 'application/json' }); res.end('{}');
  });
  control.listen(0, '127.0.0.1'); await once(control, 'listening');
  t.after(() => new Promise(resolve => { control.closeAllConnections(); control.close(() => resolve()); }));
  const origin = `http://127.0.0.1:${control.address().port}`;
  const previous = process.env.OWA_TOKEN; delete process.env.OWA_TOKEN;
  t.after(() => { if (previous !== undefined) process.env.OWA_TOKEN = previous; });

  const cases = [
    ['wrong checksum value', g => ({ ...g, headers: { ...g.headers, 'x-amz-checksum-sha256': b64(Buffer.from('other')) } })],
    ['foreign header smuggled in', g => ({ ...g, headers: { ...g.headers, 'x-provider-key': 'untrusted' } })],
    ['empty headers object', g => ({ ...g, headers: {} })],
    ['non-object headers', g => ({ ...g, headers: 'x-amz-checksum-sha256: abc' })],
    ['if-none-match not create-once', g => ({ ...g, headers: { ...g.headers, 'if-none-match': '"etag"' } })],
    ['bearer grant carrying storage headers', g => ({ ...g, authorization: 'bearer', url: `${origin}/v1/uploads/${encodeURIComponent(digest)}?expires=${NOW + 300}&sig=${'a'.repeat(64)}&site=demo` })]
  ];
  for (const [name, mutate] of cases) {
    await t.test(name, async () => {
      tamper = mutate; puts = 0; m.reset();
      const code = await codeOf(remotePublishResult(directory, 'demo', origin));
      assert.equal(code, 'OWA_CLI_GRANT', 'rejected before any byte leaves the client');
      assert.equal(puts + m.log.filter(r => r.method === 'PUT').length, 0, 'no upload was attempted');
    });
  }
  await t.test('an untampered grant is accepted by the same validator', async () => {
    tamper = g => g; m.reset();
    const code = await codeOf(remotePublishResult(directory, 'demo', origin));
    assert.notEqual(code, 'OWA_CLI_GRANT');
    assert.equal(m.log.filter(r => r.method === 'PUT').length, 1, 'the genuine grant was used');
  });
});

// ============================================================== GATE 1 ====
// A publisher-supplied manifest that lies about the size of a VALID, globally
// shared CAS object must never cause that object to be deleted, overwritten or
// "repaired". Plan is non-destructive; a repair grant is minted only for an
// object that fails to hash to its OWN key, and only after upload authority.

async function seedSiteA(e, bytes) {
  const digest = sha256(bytes);
  await e.blobs.put(digest, bytes);
  const { site, release } = await commitManifest({ slug: 'site-a', manifest: single(bytes), blobs: e.blobs, metadata: e.metadata });
  return { digest, site, release, snapshot: JSON.stringify({ site: await e.metadata.getSite('site-a'), releases: await e.metadata.listAllReleases(site.id) }) };
}
function spyStore(base) {
  const counts = { delete: 0, put: 0 };
  const spy = Object.create(base);
  spy.delete = async (...a) => { counts.delete++; return base.delete(...a); };
  spy.put = async (...a) => { counts.put++; return base.put(...a); };
  return { spy, counts };
}
/** Serve through a REAL content listener. node:http, because fetch overrides Host. */
async function servesBytes(t, e, host, expected) {
  const server = createContentServer({ blobs: e.blobs, metadata: e.metadata, content: { baseDomain: 'localhost', scheme: 'http' } });
  server.listen(0, '127.0.0.1'); await once(server, 'listening');
  try {
    return await new Promise((resolve, reject) => {
      const req = httpRequest({ hostname: '127.0.0.1', port: server.address().port, path: '/', method: 'GET', headers: { host, connection: 'close' } }, res => {
        const chunks = []; res.on('data', c => chunks.push(c)); res.on('error', reject);
        res.on('end', () => resolve(res.statusCode === 200 && Buffer.concat(chunks).equals(expected)));
      });
      req.on('error', reject); req.end();
    });
  } finally { await new Promise(r => { server.closeAllConnections(); server.close(() => r()); }); }
}

test('GATE 1 (filesystem): a wrong submitted size cannot delete, overwrite or repair a valid shared CAS object', async t => {
  const e = await fsEnv(t);
  const B = Buffer.from('valid bytes shared between sites');
  const a = await seedSiteA(e, B);
  assert.ok(await servesBytes(t, e, 'site-a.localhost', B), 'site A serves B before the attack');

  const { spy, counts } = spyStore(e.blobs);
  let grants = 0;
  const lying = manifestFor([{ path: '/index.html', bytes: B, size: B.length + 1 }]);
  let caught; try { await planManifest({ manifest: lying, blobs: spy, leases: e.leases, uploadFactory: async () => { grants++; return {}; } }); } catch (error) { caught = error; }
  assert.ok(caught instanceof IntegrityError && caught.code === 'OWA_BLOB_INTEGRITY', 'plan fails with the fixed integrity contract');
  assert.equal(caught.reason, 'size', 'internally attributed to the manifest, not the object');
  assert.equal(counts.delete, 0, 'zero CAS deletes');
  assert.equal(counts.put, 0, 'zero CAS writes');
  assert.equal(grants, 0, 'zero repair grants');
  assert.equal(await e.blobs.has(a.digest), true, 'D still exists');
  assert.ok(Buffer.from(await e.blobs.get(a.digest)).equals(B), 'bytes are byte-identical');
  assert.equal(JSON.stringify({ site: await e.metadata.getSite('site-a'), releases: await e.metadata.listAllReleases(a.site.id) }), a.snapshot, 'site A release metadata and activeReleaseId unchanged');
  assert.ok(await servesBytes(t, e, 'site-a.localhost', B), 'site A still serves B');
  // Commit with the lying manifest fails the same way, mutating nothing.
  assert.equal(await codeOf(commitManifest({ slug: 'site-b', manifest: lying, blobs: spy, metadata: e.metadata })), 'OWA_BLOB_INTEGRITY');
  assert.equal(await e.metadata.getSite('site-b'), null);
  assert.equal(counts.delete + counts.put, 0);
});

test('GATE 1 (S3-shaped): valid provider evidence + wrong submitted size → no deletion, no repair, no payload read', async t => {
  for (const evidence of ['enforced', 'advisory']) {
    await t.test(`store trust = ${evidence}`, async () => {
      const m = await mockS3(t, { checksumEvidence: evidence });
      const root = await mkdtemp(join(tmpdir(), 'owa-g1-s3-'));
      t.after(() => rm(root, { recursive: true, force: true }));
      const metadata = new FilesystemMetadataStore(root), leases = new FilesystemLeaseStore(root);
      const B = Buffer.from('valid s3 bytes shared between sites'), D = sha256(B);
      m.plant(D, B, { checksum: true });
      await commitManifest({ slug: 'site-a', manifest: single(B), blobs: m.store, metadata });
      const siteA = JSON.stringify(await metadata.getSite('site-a'));
      m.reset();
      let grants = 0;
      const lying = manifestFor([{ path: '/index.html', bytes: B, size: B.length + 1 }]);
      let caught; try { await planManifest({ manifest: lying, blobs: m.store, leases, uploadFactory: async () => { grants++; return {}; } }); } catch (error) { caught = error; }
      assert.equal(caught?.code, 'OWA_BLOB_INTEGRITY');
      assert.equal(caught?.reason, 'size');
      assert.equal(grants, 0, 'no repair grant');
      assert.equal(m.deletes(), 0, 'no DELETE');
      assert.equal(m.writes(), 0, 'no PUT');
      // plan's has() is one HEAD; verifyBlob's checksum-mode HEAD is the second.
      const methods = m.log.map(r => r.method);
      if (evidence === 'enforced') assert.deepEqual(methods, ['HEAD', 'HEAD'], 'trusted evidence settles it without a GET');
      else assert.deepEqual(methods, ['HEAD', 'HEAD', 'GET'], 'advisory trust rehashes to attribute the fault');
      assert.ok(m.bytesOf(D).equals(B), 'object byte-identical');
      assert.equal(JSON.stringify(await metadata.getSite('site-a')), siteA, 'site A unchanged');
    });
  }
});

test('GATE 1 (authorization ordering): a plan-only token cannot mutate CAS through the real control listener', async t => {
  const m = await mockS3(t);
  const root = await mkdtemp(join(tmpdir(), 'owa-g1-auth-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  const metadata = new FilesystemMetadataStore(root), leases = new FilesystemLeaseStore(root);
  const server = createControlServer({ blobs: m.store, metadata, leases, uploadSecret: UPLOAD_SECRET, auth: { secret: SECRET, now: () => NOW } });
  server.listen(0, '127.0.0.1'); await once(server, 'listening');
  t.after(() => new Promise(r => { server.closeAllConnections(); server.close(() => r()); }));
  const origin = `http://127.0.0.1:${server.address().port}`;
  const planOnly = createToken({ secret: SECRET, jti: 'plan-only', exp: NOW + 600, sites: ['site-b'], capabilities: ['plan'], now: () => NOW });
  const post = manifest => fetch(`${origin}/v1/sites/site-b/publish/plan`, {
    method: 'POST', headers: { 'content-type': 'application/json', authorization: `Bearer ${planOnly}` },
    body: JSON.stringify({ manifest, artifactDigest: artifactDigest(manifest) })
  }).then(async r => ({ status: r.status, body: await r.json() }));

  await t.test('wrong-size manifest against a valid shared object', async () => {
    const B = Buffer.from('valid object behind a healthy release'), D = sha256(B);
    m.plant(D, B, { checksum: true });
    await commitManifest({ slug: 'site-a', manifest: single(B), blobs: m.store, metadata });
    const before = JSON.stringify(await metadata.getSite('site-a'));
    m.reset();
    const res = await post(manifestFor([{ path: '/index.html', bytes: B, size: B.length + 1 }]));
    assert.equal(res.status, 500); assert.equal(res.body.code, 'OWA_BLOB_INTEGRITY');
    assert.ok(!JSON.stringify(res.body).includes('reason'), 'the internal attribution is never exposed');
    assert.equal(m.deletes(), 0); assert.equal(m.writes(), 0);
    assert.ok(m.bytesOf(D).equals(B), 'object untouched');
    assert.equal(JSON.stringify(await metadata.getSite('site-a')), before, 'existing release stays healthy');
    assert.equal(await metadata.getSite('site-b'), null);
  });

  await t.test('genuinely corrupt object: repair needs upload authority, which the token lacks', async () => {
    const G = Buffer.from('bytes the manifest expects'), D = sha256(G);
    const corrupt = Buffer.from('BYTES the manifest expects'); // same length, wrong content
    m.plant(D, corrupt);
    m.reset();
    const res = await post(single(G));
    assert.equal(res.status, 403); assert.equal(res.body.code, 'OWA_AUTH_CAPABILITY', 'the upload capability check precedes any repair instrument');
    assert.equal(m.deletes(), 0, 'no delete before authorization'); assert.equal(m.writes(), 0, 'no overwrite before authorization');
    assert.ok(m.bytesOf(D).equals(corrupt), 'CAS state is exactly as before the request');
    assert.equal(m.log.filter(r => r.presigned).length, 0, 'no grant was exercised');
  });
});

test('GATE 1 (filesystem, real server): plan-only token, valid object, wrong size → zero mutation', async t => {
  const e = await fsEnv(t);
  const B = Buffer.from('fs valid shared object'), a = await seedSiteA(e, B);
  const { spy, counts } = spyStore(e.blobs);
  const server = createControlServer({ blobs: spy, metadata: e.metadata, leases: e.leases, uploadSecret: UPLOAD_SECRET, auth: { secret: SECRET, now: () => NOW } });
  server.listen(0, '127.0.0.1'); await once(server, 'listening');
  t.after(() => new Promise(r => { server.closeAllConnections(); server.close(() => r()); }));
  const planOnly = createToken({ secret: SECRET, jti: 'plan-only-fs', exp: NOW + 600, sites: ['site-b'], capabilities: ['plan'], now: () => NOW });
  const lying = manifestFor([{ path: '/index.html', bytes: B, size: B.length + 1 }]);
  const res = await fetch(`http://127.0.0.1:${server.address().port}/v1/sites/site-b/publish/plan`, {
    method: 'POST', headers: { 'content-type': 'application/json', authorization: `Bearer ${planOnly}` },
    body: JSON.stringify({ manifest: lying, artifactDigest: artifactDigest(lying) })
  });
  assert.equal(res.status, 500); assert.equal((await res.json()).code, 'OWA_BLOB_INTEGRITY');
  assert.equal(counts.delete + counts.put, 0, 'zero CAS mutation');
  assert.ok(Buffer.from(await e.blobs.get(a.digest)).equals(B));
  assert.equal(JSON.stringify({ site: await e.metadata.getSite('site-a'), releases: await e.metadata.listAllReleases(a.site.id) }), a.snapshot);
});

test('GATE 1 (filesystem): a genuinely corrupt object is repaired without any destructive pre-grant step', async t => {
  const e = await fsEnv(t);
  const G = Buffer.from('fs bytes the manifest expects'), D = sha256(G);
  await e.blobs.put(D, Buffer.from('FS BYTES the manifest expects')); // same length, wrong content
  const { spy, counts } = spyStore(e.blobs);
  let repairGrants = 0;
  const plan = await planManifest({ manifest: single(G), blobs: spy, leases: e.leases, uploadFactory: async (d, { repair }) => { if (repair) repairGrants++; return { digest: d, method: 'PUT', url: 'http://127.0.0.1/x', expiresIn: 60 }; } });
  assert.equal(plan.reused, 0, 'not reported reused');
  assert.equal(repairGrants, 1, 'a REPAIR grant is requested');
  assert.equal(counts.delete, 0, 'no destructive pre-grant delete');
  assert.equal(await e.blobs.has(D), true);
  await e.blobs.put(D, G); // the local upload route writes only bytes that hash to D
  await commitManifest({ slug: 'repaired', manifest: single(G), blobs: e.blobs, metadata: e.metadata });
  const again = await planManifest({ manifest: single(G), blobs: e.blobs, leases: e.leases, uploadFactory: async () => { throw new Error('must not upload'); } });
  assert.equal(again.reused, 1, 'subsequent identical plan reuses normally');
});

// ============================================================== GATE 2 ====
// A provider-returned checksum is strong proof ONLY where the provider is known
// to validate it against stored bytes. Unknown endpoints must rehash.

test('GATE 2: provider checksum trust is explicit, auto-detected conservatively, and cannot be disabled into a bypass', async t => {
  const make = (endpoint, extra = {}) => new S3BlobStore({ endpoint, bucket: 'b', accessKeyId: ACCESS, secretAccessKey: PROVIDER_SECRET, ...extra });
  assert.equal(make('https://acct.r2.cloudflarestorage.com').checksumEvidence, 'enforced', 'R2 is live-proven to enforce');
  assert.equal(make('http://127.0.0.1:9000').checksumEvidence, 'advisory', 'a generic endpoint is advisory by default');
  assert.equal(make('https://s3.us-east-1.amazonaws.com').checksumEvidence, 'advisory', 'not live-proven here → advisory until an operator asserts otherwise');
  assert.equal(make('http://127.0.0.1:9000', { checksumEvidence: 'enforced' }).checksumEvidence, 'enforced', 'an operator may assert a verified provider');
  for (const bad of ['off', 'trust-everything', 'skip', true, 1]) {
    assert.throws(() => make('http://127.0.0.1:9000', { checksumEvidence: bad }), /Unsupported S3 checksumEvidence/);
  }

  await t.test('a lax provider that echoes an unvalidated checksum cannot make corrupt bytes look verified under advisory trust', async () => {
    const m = await mockS3(t, { checksumEvidence: 'advisory', echo: true });
    const good = Buffer.from('what the digest promises'), D = sha256(good);
    // Corrupt bytes uploaded WITH a header claiming D's checksum; the lax provider stores the claim.
    const status = await fetch(`${m.origin}/bucket/owa/blobs/sha256/${D.slice(7)}`, { method: 'PUT', headers: { 'x-amz-checksum-sha256': b64(good) }, body: Buffer.from('WHAT the digest promises') }).then(async r => { await r.arrayBuffer(); return r.status; });
    assert.equal(status, 200, 'the lax provider accepted the lie');
    m.reset();
    let caught; try { await m.store.verifyBlob({ digest: D, size: good.length }); } catch (error) { caught = error; }
    assert.equal(caught?.code, 'OWA_BLOB_INTEGRITY');
    assert.equal(caught?.reason, 'digest', 'the rehash catches the corrupt bytes despite the echoed header');
    assert.deepEqual(m.log.map(r => r.method), ['HEAD', 'GET'], 'advisory trust always rehashes');
    // The same object seen through a store that WRONGLY asserts 'enforced' would be
    // accepted on the echoed header alone — which is exactly why the default is advisory.
    const misconfigured = m.storeWith('enforced');
    assert.deepEqual(await misconfigured.verifyBlob({ digest: D, size: good.length }), { ok: true, method: 'provider-checksum' });
  });

  await t.test('advisory trust rehashes even genuine evidence; enforced trust uses it', async () => {
    const m = await mockS3(t, { checksumEvidence: 'advisory' });
    const good = Buffer.from('genuinely validated bytes'), D = sha256(good);
    m.plant(D, good, { checksum: true });
    m.reset();
    assert.deepEqual(await m.store.verifyBlob({ digest: D, size: good.length }), { ok: true, method: 'rehash' });
    assert.deepEqual(m.log.map(r => r.method), ['HEAD', 'GET']);
    m.reset();
    assert.deepEqual(await m.storeWith('enforced').verifyBlob({ digest: D, size: good.length }), { ok: true, method: 'provider-checksum' });
    assert.deepEqual(m.log.map(r => r.method), ['HEAD']);
  });
});

// =========================================================== FINAL GATE ====
// Whether a publisher may HOLD a presigned grant on a final CAS key is a
// capability separate from checksum-evidence trust. A still-valid grant outlives
// commit; on a provider not proven to enforce the signed checksum and
// create-once semantics, a replay could overwrite a verified, ACTIVE release.
// An unknown provider therefore gets no direct grant at all: bytes travel
// through artifactd, which hashes them before put(). Only proven providers
// (R2 automatically, or an explicit operator assertion) keep the direct path.

const mint = (capabilities, sites, jti = `${capabilities.join('-')}-${sites.join('-')}`) =>
  createToken({ secret: SECRET, jti, exp: NOW + 600, sites, capabilities, now: () => NOW });

/** A REAL control listener over the given store, plus the requests a publisher makes. */
async function controlFor(t, blobs) {
  const root = await mkdtemp(join(tmpdir(), 'owa-final-gate-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  const metadata = new FilesystemMetadataStore(root), leases = new FilesystemLeaseStore(root);
  const server = createControlServer({ blobs, metadata, leases, uploadSecret: UPLOAD_SECRET, auth: { secret: SECRET, now: () => NOW } });
  server.listen(0, '127.0.0.1'); await once(server, 'listening');
  t.after(() => new Promise(r => { server.closeAllConnections(); server.close(() => r()); }));
  const origin = `http://127.0.0.1:${server.address().port}`;
  const post = (slug, operation, manifest, token) => fetch(`${origin}/v1/sites/${slug}/publish/${operation}`, {
    method: 'POST', headers: { 'content-type': 'application/json', authorization: `Bearer ${token}` },
    body: JSON.stringify({ manifest, artifactDigest: artifactDigest(manifest) })
  }).then(async r => ({ status: r.status, body: await r.json() }));
  return {
    origin, metadata, leases,
    plan: (slug, manifest, token) => post(slug, 'plan', manifest, token),
    commit: (slug, manifest, token) => post(slug, 'commit', manifest, token),
    /** Relay bytes to an artifactd grant exactly as the CLI does for a local bearer grant. */
    put: (url, token, bytes) => fetch(url, { method: 'PUT', headers: token ? { authorization: `Bearer ${token}` } : {}, body: bytes })
      .then(async r => { const text = await r.text(); return { status: r.status, body: text ? JSON.parse(text) : null }; })
  };
}
/** The ONLY grant shape a mediated backend may return: artifactd's own scoped local grant. */
function assertMediatedGrant(grant, { origin, digest, slug, storageOrigin }) {
  assert.equal(grant.digest, digest); assert.equal(grant.method, 'PUT');
  assert.equal(grant.authorization, 'bearer', 'marked local bearer grant, the shape the CLI already knows');
  assert.ok(!Object.hasOwn(grant, 'headers'), 'no storage grant headers');
  const url = new URL(grant.url);
  assert.equal(url.origin, origin, 'same control origin');
  assert.equal(url.pathname, `/v1/uploads/${encodeURIComponent(digest)}`);
  assert.deepEqual([...url.searchParams.keys()].sort(), ['expires', 'sig', 'site'], 'local signed expiry/site query only');
  assert.equal(url.searchParams.get('site'), slug);
  assert.match(url.searchParams.get('sig'), /^[0-9a-f]{64}$/);
  assert.ok(![...url.searchParams.keys()].some(k => /^x-amz-/i.test(k)), 'not an S3 presigned URL');
  assert.notEqual(url.port, new URL(storageOrigin).port, 'does not point at storage');
  assert.ok(Number(url.searchParams.get('expires')) <= NOW + 600 && grant.expiresIn <= 600, 'bounded by the bearer');
}
const status = promise => promise.then(async r => { await r.arrayBuffer(); return r.status; });

test('FINAL GATE: direct-upload integrity is a separate explicit capability — safe default, R2 auto, operator assertion, no bypass', async t => {
  const make = (endpoint, extra = {}) => new S3BlobStore({ endpoint, bucket: 'b', accessKeyId: ACCESS, secretAccessKey: PROVIDER_SECRET, ...extra });
  const r2 = make('https://acct.r2.cloudflarestorage.com');
  assert.equal(r2.directUploadIntegrity, 'enforced'); assert.equal(r2.canCreateSafeDirectUpload(), true, 'R2 is live-proven: direct grants by default');
  for (const generic of ['http://127.0.0.1:9000', 'https://s3.us-east-1.amazonaws.com', 'https://minio.internal.example:9000', 'https://storage.example.com']) {
    const store = make(generic);
    assert.equal(store.directUploadIntegrity, 'mediated', `${generic} is not proven → mediated`);
    assert.equal(store.canCreateSafeDirectUpload(), false);
    await assert.rejects(store.createUpload(sha256(Buffer.from('x')), { expires: 60 }), /mediated/, 'a mediated store refuses to sign a direct grant even when asked');
  }
  // The two capabilities are independent: checksum-evidence trust alone never
  // unlocks direct grants, and a direct-upload assertion alone never unlocks the
  // HEAD fast path.
  const evidenceOnly = make('http://127.0.0.1:9000', { checksumEvidence: 'enforced' });
  assert.equal(evidenceOnly.checksumEvidence, 'enforced'); assert.equal(evidenceOnly.directUploadIntegrity, 'mediated');
  const directOnly = make('http://127.0.0.1:9000', { directUploadIntegrity: 'enforced' });
  assert.equal(directOnly.directUploadIntegrity, 'enforced'); assert.equal(directOnly.checksumEvidence, 'advisory');
  assert.equal(directOnly.canCreateSafeDirectUpload(), true, 'a verified MinIO/operator deployment may assert the direct contract');
  assert.equal(make('https://acct.r2.cloudflarestorage.com', { directUploadIntegrity: 'mediated' }).canCreateSafeDirectUpload(), false, 'an operator may force the safe path even on a proven host');
  for (const bad of ['off', 'skip', 'unsafe', 'trust-all', 'direct', 'true', '', true, 1, null]) {
    assert.throws(() => make('http://127.0.0.1:9000', { directUploadIntegrity: bad }), /Unsupported S3 directUploadIntegrity/, `no bypass value: ${String(bad)}`);
  }

  await t.test('artifactd startup: a generic endpoint defaults to mediated; an invalid value fails construction', async () => {
    const dataDir = await mkdtemp(join(tmpdir(), 'owa-final-gate-startup-'));
    t.after(() => rm(dataDir, { recursive: true, force: true }));
    const keys = ['OWA_STORAGE', 'OWA_S3_ENDPOINT', 'OWA_S3_BUCKET', 'OWA_S3_ACCESS_KEY_ID', 'OWA_S3_SECRET_ACCESS_KEY', 'OWA_S3_DIRECT_UPLOAD_INTEGRITY', 'OWA_S3_CHECKSUM_EVIDENCE'];
    const saved = Object.fromEntries(keys.map(k => [k, process.env[k]]));
    t.after(() => { for (const k of keys) { if (saved[k] === undefined) delete process.env[k]; else process.env[k] = saved[k]; } });
    Object.assign(process.env, { OWA_STORAGE: 's3', OWA_S3_ENDPOINT: 'http://127.0.0.1:9000', OWA_S3_BUCKET: 'b', OWA_S3_ACCESS_KEY_ID: ACCESS, OWA_S3_SECRET_ACCESS_KEY: PROVIDER_SECRET });
    delete process.env.OWA_S3_DIRECT_UPLOAD_INTEGRITY; delete process.env.OWA_S3_CHECKSUM_EVIDENCE;
    const auto = await createDefaultStores({ dataDir });
    assert.equal(auto.storageKind, 's3'); assert.equal(auto.blobs.directUploadIntegrity, 'mediated'); assert.equal(auto.blobs.checksumEvidence, 'advisory');
    process.env.OWA_S3_DIRECT_UPLOAD_INTEGRITY = 'enforced';
    assert.equal((await createDefaultStores({ dataDir })).blobs.canCreateSafeDirectUpload(), true, 'explicit operator assertion');
    for (const bad of ['off', 'skip', 'unsafe', 'trust-all']) {
      process.env.OWA_S3_DIRECT_UPLOAD_INTEGRITY = bad;
      await assert.rejects(createDefaultStores({ dataDir }), /Unsupported S3 directUploadIntegrity/, `startup rejects ${bad}`);
    }
    process.env.OWA_S3_DIRECT_UPLOAD_INTEGRITY = 'mediated'; process.env.OWA_S3_CHECKSUM_EVIDENCE = 'off';
    await assert.rejects(createDefaultStores({ dataDir }), /Unsupported S3 checksumEvidence/);
  });
});

test('FINAL GATE (generic S3, real server): missing blob → artifactd-mediated grant; wrong bytes never reach storage; commit; replay cannot corrupt', async t => {
  const m = await mockS3(t, { checksumEvidence: 'auto', directUploadIntegrity: 'auto' }); // the store's own defaults for an unknown endpoint
  assert.equal(m.store.checksumEvidence, 'advisory'); assert.equal(m.store.directUploadIntegrity, 'mediated');
  let directAsked = 0;
  const guarded = Object.create(m.store);
  guarded.createUpload = async () => { directAsked++; throw new Error('must not be asked'); };
  const c = await controlFor(t, guarded);
  const token = mint(['plan', 'upload', 'commit', 'activate'], ['site-m']);
  const G = Buffer.from('bytes relayed through artifactd'), D = sha256(G), wrong = Buffer.from('BYTES relayed through artifactd');
  const manifest = single(G);

  // 1. plan: a mediated scoped grant, not an S3 presigned URL
  const planned = await c.plan('site-m', manifest, token);
  assert.equal(planned.status, 200); assert.equal(planned.body.reused, 0); assert.equal(planned.body.uploads.length, 1);
  const grant = planned.body.uploads[0];
  assertMediatedGrant(grant, { origin: c.origin, digest: D, slug: 'site-m', storageOrigin: m.origin });
  assert.equal(directAsked, 0, 'the server never asked the store for a direct grant');
  assert.equal(m.writes(), 0, 'plan minted nothing on storage'); assert.equal(m.log.filter(r => r.presigned).length, 0);

  // 2. wrong body: artifactd rejects before blobs.put
  const rejected = await c.put(grant.url, token, wrong);
  assert.equal(rejected.status, 400); assert.equal(rejected.body.error, 'blob digest mismatch');
  assert.equal(m.writes(), 0, 'zero S3 PUT'); assert.equal(m.bytesOf(D), null, 'no CAS object created');

  // 3. correct body: exactly one backend write, by artifactd, with storage credentials and a declared checksum
  assert.equal((await c.put(grant.url, token, G)).status, 204);
  assert.equal(m.writes(), 1, 'exactly one backend storage write');
  const write = m.log.find(r => r.method === 'PUT');
  assert.ok(!write.presigned && write.authScheme === 'AWS4-HMAC-SHA256' && write.hasChecksumHeader && !write.hasIfNoneMatch, 'a trusted put(): storage credentials, checksum declared, overwrite-capable by design');
  assert.ok(m.bytesOf(D).equals(G));
  const committed = await c.commit('site-m', manifest, token);
  assert.equal(committed.status, 201);
  assert.deepEqual(Object.keys(committed.body).sort(), ['activeReleaseId', 'artifactDigest', 'releaseId', 'slug'], 'commit response shape unchanged');
  assert.equal(committed.body.artifactDigest, artifactDigest(manifest)); assert.equal(committed.body.activeReleaseId, committed.body.releaseId);
  assert.deepEqual(await m.store.verifyBlob({ digest: D, size: G.length }), { ok: true, method: 'rehash' }, 'stored bytes verify; advisory trust rehashes');
  const site = await c.metadata.getSite('site-m');
  const release = await c.metadata.getRelease(site.id, committed.body.releaseId);
  assert.deepEqual(release.manifest, manifest); assert.equal(release.artifactDigest, committed.body.artifactDigest);
  const snapshot = JSON.stringify({ site, release });
  assert.ok(await servesBytes(t, { blobs: m.store, metadata: c.metadata }, 'site-m.localhost', G), 'served through a real content listener');

  // 4. replay the SAME still-unexpired artifactd grant after commit
  m.reset();
  const replay = await c.put(grant.url, token, wrong);
  assert.equal(replay.status, 400, 'the digest check still rejects');
  assert.equal(m.writes(), 0, 'zero corrupt backend write'); assert.ok(m.bytesOf(D).equals(G), 'committed CAS bytes unchanged');
  assert.equal((await c.put(grant.url, token, G)).status, 204, 'correct bytes while still authorized: permitted…');
  assert.equal(m.writes(), 1); assert.ok(m.bytesOf(D).equals(G), '…but it can only write the identical bytes');
  assert.equal(JSON.stringify({ site: await c.metadata.getSite('site-m'), release: await c.metadata.getRelease(site.id, committed.body.releaseId) }), snapshot, 'active release remains healthy');
  assert.ok(await servesBytes(t, { blobs: m.store, metadata: c.metadata }, 'site-m.localhost', G));
  assert.equal(m.log.filter(r => r.presigned).length, 0, 'no presigned request in the whole flow');
  assert.ok(m.log.every(r => r.authScheme !== 'Bearer'), 'no OWA bearer reached storage');
});

test('FINAL GATE (generic S3, real server): a genuinely corrupt object is repaired through artifactd — no delete, no overwrite-capable direct grant', async t => {
  const m = await mockS3(t, { checksumEvidence: 'auto', directUploadIntegrity: 'auto' });
  const c = await controlFor(t, m.store);
  const token = mint(['plan', 'upload', 'commit', 'activate'], ['site-r']);
  const G = Buffer.from('the bytes site-r expects'), D = sha256(G), corrupt = Buffer.from('THE BYTES site-r expects');
  m.plant(D, corrupt); m.reset();
  const planned = await c.plan('site-r', single(G), token);
  assert.equal(planned.status, 200); assert.equal(planned.body.reused, 0, 'a proven-corrupt object is never reusable'); assert.equal(planned.body.uploads.length, 1);
  assert.deepEqual(m.log.map(r => r.method), ['HEAD', 'HEAD', 'GET'], 'has(), then a verification that rehashes and identifies digest corruption');
  assert.equal(m.deletes(), 0, 'not deleted'); assert.equal(m.writes(), 0, 'not overwritten'); assert.ok(m.bytesOf(D).equals(corrupt), 'left in place for the repair');
  const repair = planned.body.uploads[0];
  assertMediatedGrant(repair, { origin: c.origin, digest: D, slug: 'site-r', storageOrigin: m.origin });
  assert.equal(m.log.filter(r => r.presigned).length, 0, 'no direct S3 repair URL escaped to the client');
  assert.equal((await c.put(repair.url, token, Buffer.from('the bytes SITE-R expects'))).status, 400, 'wrong repair bytes rejected');
  assert.equal(m.writes(), 0); assert.ok(m.bytesOf(D).equals(corrupt));
  assert.equal((await c.put(repair.url, token, G)).status, 204, 'correct repair bytes overwrite the key through blobs.put()');
  assert.equal(m.writes(), 1); assert.ok(m.bytesOf(D).equals(G));
  assert.equal((await c.commit('site-r', single(G), token)).status, 201);
  m.reset();
  const again = await c.plan('site-r', single(G), mint(['plan'], ['site-r']));
  assert.equal(again.status, 200); assert.equal(again.body.reused, 1); assert.equal(again.body.uploads.length, 0, 'a subsequent identical plan reuses normally');
  assert.equal(m.writes() + m.deletes(), 0);
});

test('FINAL GATE (generic S3, real server): a plan-only token obtains neither a direct nor a mediated grant; CAS is untouched', async t => {
  const m = await mockS3(t, { checksumEvidence: 'auto', directUploadIntegrity: 'auto' });
  const c = await controlFor(t, m.store);
  const planOnly = mint(['plan'], ['site-p']);
  const G = Buffer.from('never uploaded by a plan-only token'), D = sha256(G), corrupt = Buffer.from('NEVER uploaded by a plan-only token');
  const noGrant = body => assert.ok(!Object.hasOwn(body, 'uploads') && !JSON.stringify(body).includes('/v1/uploads/') && !JSON.stringify(body).includes('X-Amz'), 'no grant of any kind');

  await t.test('missing object', async () => {
    m.reset();
    const res = await c.plan('site-p', single(G), planOnly);
    assert.equal(res.status, 403); assert.equal(res.body.code, 'OWA_AUTH_CAPABILITY'); noGrant(res.body);
    assert.equal(m.writes() + m.deletes(), 0); assert.equal(m.log.filter(r => r.presigned).length, 0); assert.equal(m.bytesOf(D), null);
  });
  await t.test('corrupt object that would need a repair', async () => {
    m.plant(D, corrupt); m.reset();
    const res = await c.plan('site-p', single(G), planOnly);
    assert.equal(res.status, 403); assert.equal(res.body.code, 'OWA_AUTH_CAPABILITY'); noGrant(res.body);
    assert.equal(m.writes() + m.deletes(), 0); assert.ok(m.bytesOf(D).equals(corrupt), 'CAS unchanged');
  });
  await t.test('a mediated grant minted for an authorized publisher cannot be exercised without upload authority', async () => {
    const grant = (await c.plan('site-p', single(G), mint(['plan', 'upload'], ['site-p']))).body.uploads[0];
    assertMediatedGrant(grant, { origin: c.origin, digest: D, slug: 'site-p', storageOrigin: m.origin });
    m.reset();
    const denied = await c.put(grant.url, planOnly, G);
    assert.equal(denied.status, 403); assert.equal(denied.body.code, 'OWA_AUTH_CAPABILITY');
    const anonymous = await c.put(grant.url, null, G);
    assert.equal(anonymous.status, 401); assert.equal(anonymous.body.code, 'OWA_AUTH_MISSING');
    assert.equal(m.writes(), 0); assert.ok(m.bytesOf(D).equals(corrupt), 'still the corrupt bytes: nothing was written');
  });
});

test('FINAL GATE (proven provider, real server): an enforced store still issues direct grants with the exact normal and repair shapes; the local upload route stays closed', async t => {
  const m = await mockS3(t); // enforced/enforced: the contract R2 was proven to have
  assert.equal(m.store.canCreateSafeDirectUpload(), true);
  const c = await controlFor(t, m.store);
  const token = mint(['plan', 'upload', 'commit', 'activate'], ['site-d']);
  const G = Buffer.from('direct grant bytes'), D = sha256(G), wrong = Buffer.from('DIRECT grant bytes');
  const normal = (await c.plan('site-d', single(G), token)).body.uploads[0];
  assert.ok(!Object.hasOwn(normal, 'authorization'), 'a storage grant forwards no bearer');
  const nu = new URL(normal.url);
  assert.equal(nu.origin, m.origin, 'points at storage, not artifactd');
  assert.equal(nu.searchParams.get('X-Amz-SignedHeaders'), 'host;if-none-match;x-amz-checksum-sha256');
  assert.deepEqual(normal.headers, uploadHeadersFor(D), 'normal grant: checksum + if-none-match: *');
  m.plant(D, wrong); // same length, corrupt, no evidence
  const repair = (await c.plan('site-d', single(G), token)).body.uploads[0];
  const ru = new URL(repair.url);
  assert.equal(ru.origin, m.origin);
  assert.equal(ru.searchParams.get('X-Amz-SignedHeaders'), 'host;x-amz-checksum-sha256');
  assert.deepEqual(repair.headers, uploadHeadersFor(D, { repair: true }), 'repair grant: checksum only');
  assert.ok(!Object.hasOwn(repair.headers, 'if-none-match'));
  // The artifactd upload route does not exist for a direct store, whatever the URL claims.
  const local = await c.put(`${c.origin}/v1/uploads/${encodeURIComponent(D)}?expires=${NOW + 600}&sig=${'a'.repeat(64)}&site=site-d`, token, G);
  assert.equal(local.status, 404); assert.equal(m.writes(), 0);
  // The existing TOCTOU proof holds end to end through the real listener.
  assert.equal(await status(fetch(repair.url, { method: 'PUT', headers: repair.headers, body: wrong })), 400, 'wrong bytes under the repair grant: refused by the provider');
  assert.equal(await status(fetch(repair.url, { method: 'PUT', headers: repair.headers, body: G })), 200);
  assert.equal((await c.commit('site-d', single(G), token)).status, 201);
  assert.equal(await status(fetch(repair.url, { method: 'PUT', headers: repair.headers, body: wrong })), 400, 'post-commit repair replay cannot write wrong bytes');
  assert.equal(await status(fetch(normal.url, { method: 'PUT', headers: normal.headers, body: wrong })), 412, 'post-commit normal replay: create-once refuses');
  assert.ok(m.bytesOf(D).equals(G), 'committed bytes intact');
});

test('FINAL GATE (weak provider): an endpoint that ignores checksum validation and If-None-Match never receives a direct final-CAS grant by default; the mediated path keeps the committed object intact', async t => {
  const m = await mockS3(t, { checksumEvidence: 'auto', directUploadIntegrity: 'auto', weak: true });
  assert.equal(m.store.directUploadIntegrity, 'mediated'); assert.equal(m.store.checksumEvidence, 'advisory');
  const G = Buffer.from('weak provider bytes'), D = sha256(G), wrong = Buffer.from('WEAK PROVIDER BYTES');
  const grantPut = (grant, body) => status(fetch(grant.url, { method: 'PUT', headers: grant.headers, body }));

  await t.test('the hazard: a store WRONGLY asserted enforced hands out a grant the weak provider lets corrupt after commit', async () => {
    const root = await mkdtemp(join(tmpdir(), 'owa-final-gate-weak-'));
    t.after(() => rm(root, { recursive: true, force: true }));
    const misconfigured = m.storeWith('advisory', { directUploadIntegrity: 'enforced' });
    const grant = await misconfigured.createUpload(D, { expires: 600 });
    assert.equal(await grantPut(grant, G), 200);
    await commitManifest({ slug: 'weak-direct', manifest: single(G), blobs: misconfigured, metadata: new FilesystemMetadataStore(root) }); // rehash: correct at time T
    assert.equal(await grantPut(grant, wrong), 200, 'the weak provider accepts the replay: checksum unvalidated, If-None-Match ignored');
    assert.ok(m.bytesOf(D).equals(wrong), 'the ACTIVE release now serves corrupt CAS bytes — exactly the hole the default closes');
    assert.equal(await codeOf(misconfigured.verifyBlob({ digest: D, size: G.length })), 'OWA_BLOB_INTEGRITY', 'detectable only at the next verification, too late for the release');
    m.remove(D);
  });

  await t.test('the default: mediated flow; wrong bytes never reach the provider; replay cannot corrupt', async () => {
    m.reset();
    const c = await controlFor(t, m.store);
    const token = mint(['plan', 'upload', 'commit', 'activate'], ['weak']);
    const grant = (await c.plan('weak', single(G), token)).body.uploads[0];
    assertMediatedGrant(grant, { origin: c.origin, digest: D, slug: 'weak', storageOrigin: m.origin });
    assert.equal((await c.put(grant.url, token, wrong)).status, 400); assert.equal(m.writes(), 0, 'wrong bytes never reached the provider');
    assert.equal((await c.put(grant.url, token, G)).status, 204); assert.equal(m.writes(), 1);
    assert.equal((await c.commit('weak', single(G), token)).status, 201);
    assert.equal((await c.put(grant.url, token, wrong)).status, 400); assert.equal(m.writes(), 1, 'no second write');
    assert.ok(m.bytesOf(D).equals(G), 'committed bytes intact on a provider that enforces nothing');
    assert.deepEqual(await m.store.verifyBlob({ digest: D, size: G.length }), { ok: true, method: 'rehash' });
    assert.equal(m.log.filter(r => r.presigned).length, 0, 'no presigned request in the entire default flow');
  });
});

test('FINAL GATE (CLI): against a mediated S3 backend the CLI sees only the local bearer grant it already knows, and artifactd relays verified bytes', async t => {
  const m = await mockS3(t, { checksumEvidence: 'auto', directUploadIntegrity: 'auto' });
  const c = await cliEnv(t, m);
  await writeFile(join(c.directory, 'index.html'), '<h1>mediated cli</h1>');
  await writeFile(join(c.directory, 'app.js'), 'console.log(2)');
  const result = await remotePublishResult(c.directory, 'demo', c.origin);
  assert.equal(result.uploaded, 2); assert.equal(result.reused, 0);
  const puts = m.log.filter(r => r.method === 'PUT');
  assert.equal(puts.length, 2, 'one storage write per blob, by artifactd');
  assert.ok(puts.every(r => !r.presigned && r.authScheme === 'AWS4-HMAC-SHA256' && r.hasChecksumHeader && !r.hasIfNoneMatch), 'trusted writes with storage credentials; nothing presigned');
  assert.ok(m.log.every(r => r.authScheme !== 'Bearer'), 'no OWA bearer reached storage');
  m.reset();
  const again = await remotePublishResult(c.directory, 'demo', c.origin);
  assert.equal(again.reused, 2); assert.equal(again.uploaded, 0); assert.equal(m.writes(), 0);
});
