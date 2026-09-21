import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes, randomUUID } from 'node:crypto';
import { once } from 'node:events';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { artifactDigest, sha256, validateManifest } from '../../spec/src/index.js';
import { FilesystemLeaseStore, FilesystemMetadataStore } from '../../storage-filesystem/src/index.js';
import { S3BlobStore, uploadHeadersFor } from '../../storage-s3/src/index.js';
import { commitManifest, planManifest } from '../../core/src/index.js';
import { createControlServer } from '../../server/src/index.js';
import { createToken } from '../../server/src/auth.js';
import { providerConfiguration } from './providers.js';
import { meterRequests, withRequestLimits } from './requests.js';

// Live commit-boundary integrity evidence (issue #10) against real S3-compatible
// services. Opt-in through the explicit OWA_TEST_* variables; never a fallback to
// artifactd's own configuration. A skipped case is not evidence.
//
// Every object lives under a UUID-isolated prefix that is emptied at the end.
// Only aggregate counts, statuses and digests are reported — never a URL,
// signature, Authorization value or credential.
//
// Two independent provider capabilities may be asserted per provider once the
// probe has PROVEN them; otherwise the store's conservative defaults apply:
//   OWA_TEST_<PROVIDER>_CHECKSUM_EVIDENCE=enforced        HEAD checksum is proof
//   OWA_TEST_<PROVIDER>_DIRECT_UPLOAD_INTEGRITY=enforced  publishers may hold
//                                                         direct final-CAS grants
// With direct uploads 'mediated' (the default for any host not proven live),
// the scenario below runs its uploads through a REAL artifactd control listener:
// the publisher receives only artifactd's scoped bearer grant, artifactd hashes
// the bytes and writes them with its own storage credentials.
// OWA_TEST_REQUIRE_PROVIDERS (test-harness only) turns a would-be skip into a
// failure for the listed providers, so CI can prove a case ran.
const PROVIDERS = [
  { name: 'Cloudflare R2', provider: 'R2', region: 'auto' },
  { name: 'MinIO', provider: 'MINIO', region: 'us-east-1' }
];

function configuration(entry) {
  const resolved = providerConfiguration(entry);
  if (!resolved.options) return resolved;
  return { ...resolved, runId: randomUUID(), options: { ...resolved.options, addressingStyle: 'path' } };
}

const bytesOf = text => Buffer.from(text, 'utf8');
const flipped = bytes => Buffer.from(bytes.map(b => b ^ 0xff)); // same length, every byte different
function manifestFor(bytes, { size = bytes.length } = {}) {
  const manifest = {
    specVersion: 'owa.dev/v1', artifactType: 'application/vnd.openwebartifact.site.v1+json', entrypoint: '/index.html',
    files: [{ path: '/index.html', digest: sha256(bytes), size, mediaType: 'text/html' }],
    access: { visibility: 'public' }, lifecycle: { expiresAt: null }
  };
  validateManifest(manifest);
  return manifest;
}

for (const entry of PROVIDERS) {
  const { skip, fail, options, runId } = configuration(entry);
  test(`${entry.name}: live commit-boundary integrity in an isolated prefix`, { skip, timeout: 240_000 }, async t => {
    if (fail) assert.fail(fail); // Required by OWA_TEST_REQUIRE_PROVIDERS but unconfigured.
    const root = await mkdtemp(join(tmpdir(), 'owa-integrity-live-'));
    const store = new S3BlobStore({ ...options, prefix: `owa-integrity-integration/${runId}` });
    const metadata = new FilesystemMetadataStore(root), leases = new FilesystemLeaseStore(root);
    const created = new Set();
    const direct = store.canCreateSafeDirectUpload();
    const fast = store.checksumEvidence === 'enforced' ? 'provider-checksum' : 'rehash';
    t.diagnostic(`${entry.name}: addressing=${options.addressingStyle} region=${options.region} checksumEvidence=${store.checksumEvidence} directUploadIntegrity=${store.directUploadIntegrity} (${direct ? 'direct storage grants' : 'artifactd-mediated uploads'}) node=${process.version}`);
    const m = meterRequests(new URL(options.endpoint).host);
    /** Write bytes with NO checksum header, as a pre-change server or external tool would. */
    const rawPut = (d, body) => store.signedFetch('PUT', store.key(d), { body }).then(async r => { await r.arrayBuffer(); created.add(d); return r.status; });
    const grantPut = (grant, body, headers = grant.headers) => fetch(grant.url, { method: 'PUT', headers, body }).then(async r => { await r.arrayBuffer(); return r.status; });

    // A REAL control listener for the mediated path. Secrets are in-memory only.
    let control = null, controlOrigin = null;
    const authSecret = randomBytes(32).toString('hex'), uploadSecret = randomBytes(32).toString('hex');
    const token = createToken({ secret: authSecret, jti: `live-${runId}`, exp: Math.floor(Date.now() / 1000) + 900, sites: ['live', 'fresh'], capabilities: ['plan', 'upload', 'commit', 'activate'] });
    const api = (slug, operation, manifest) => fetch(`${controlOrigin}/v1/sites/${slug}/publish/${operation}`, {
      method: 'POST', headers: { 'content-type': 'application/json', authorization: `Bearer ${token}` },
      body: JSON.stringify({ manifest, artifactDigest: artifactDigest(manifest) })
    }).then(async r => ({ status: r.status, body: await r.json() }));
    /** Relay bytes to an artifactd grant, exactly as the CLI does for a local bearer grant. */
    const relay = (grant, body) => fetch(grant.url, { method: 'PUT', headers: { authorization: `Bearer ${token}` }, body }).then(async r => { await r.arrayBuffer(); return r.status; });
    function assertMediated(grant, digest, slug) {
      assert.equal(grant.digest, digest); assert.equal(grant.method, 'PUT');
      assert.equal(grant.authorization, 'bearer', 'the marked local bearer grant the CLI already knows');
      assert.ok(!Object.hasOwn(grant, 'headers'), 'no storage grant headers');
      const url = new URL(grant.url);
      assert.equal(url.origin, controlOrigin, 'same control origin — no storage URL leaves artifactd');
      assert.equal(url.pathname, `/v1/uploads/${encodeURIComponent(digest)}`);
      assert.deepEqual([...url.searchParams.keys()].sort(), ['expires', 'sig', 'site'], 'local signed expiry/site query only');
      assert.equal(url.searchParams.get('site'), slug);
      assert.ok(![...url.searchParams.keys()].some(k => /^x-amz-/i.test(k)), 'not a presigned storage URL');
    }

    const cleanup = async () => {
      if (control?.listening) await new Promise(resolve => { control.closeAllConnections(); control.close(() => resolve()); });
      for (const d of created) await store.delete(d).catch(() => {});
      await rm(root, { recursive: true, force: true });
    };

    try {
      await withRequestLimits({ signal: t.signal, cleanup, run: async () => {
        if (!direct) {
          control = createControlServer({ blobs: store, metadata, leases, uploadSecret, auth: { secret: authSecret } });
          control.listen(0, '127.0.0.1'); await once(control, 'listening');
          controlOrigin = `http://127.0.0.1:${control.address().port}`;
        }

        // ===== A. GATE 1: a wrong submitted size cannot mutate a valid shared object =====
        const shared = bytesOf('live integrity: valid bytes shared by two sites');
        const sharedDigest = sha256(shared);
        assert.equal(await rawPut(sharedDigest, shared), 200);
        const siteA = await commitManifest({ slug: 'site-a', manifest: manifestFor(shared), blobs: store, metadata });
        const siteASnapshot = JSON.stringify({ site: await metadata.getSite('site-a'), releases: await metadata.listAllReleases(siteA.site.id) });
        const before = m.snapshot();
        let code = null, grants = 0;
        try { await planManifest({ manifest: manifestFor(shared, { size: shared.length + 1 }), blobs: store, leases, uploadFactory: async () => { grants++; return {}; } }); } catch (error) { code = error.code; }
        assert.equal(code, 'OWA_BLOB_INTEGRITY', 'a lying manifest fails the plan');
        assert.equal(grants, 0, 'no repair grant for a valid object');
        assert.equal(m.since(before, 'DELETE'), 0, 'zero deletes');
        assert.equal(m.since(before, 'PUT'), 0, 'zero writes');
        assert.ok(Buffer.from(await store.get(sharedDigest)).equals(shared), 'the shared object is byte-identical');
        assert.equal(JSON.stringify({ site: await metadata.getSite('site-a'), releases: await metadata.listAllReleases(siteA.site.id) }), siteASnapshot, 'site A release metadata and active pointer unchanged');
        assert.equal(await metadata.getSite('site-b'), null);

        // ===== B. genuinely corrupt object: non-destructive repair =====
        const good = bytesOf('live integrity: the correct committed bytes');
        const wrong = flipped(good);
        const digest = sha256(good);
        assert.equal(await rawPut(digest, wrong), 200, 'arrange: corrupt same-length bytes planted without a checksum');
        code = null;
        try { await commitManifest({ slug: 'live', manifest: manifestFor(good), blobs: store, metadata }); } catch (error) { code = error.code; }
        assert.equal(code, 'OWA_BLOB_INTEGRITY', 'wrong-content object cannot be committed');
        assert.equal(await metadata.getSite('live'), null, 'no site record was created');
        const mid = m.snapshot();

        if (direct) {
          const plan = await planManifest({ manifest: manifestFor(good), blobs: store, leases, uploadFactory: (d, o) => store.createUpload(d, { expires: 600, ...o }) });
          assert.equal(plan.reused, 0, 'a proven-corrupt object is never reported reusable');
          assert.equal(plan.uploads.length, 1);
          assert.equal(m.since(mid, 'DELETE'), 0, 'plan is non-destructive: no DELETE');
          assert.equal(await store.has(digest), true, 'the corrupt object is left in place for the repair upload');
          const repair = plan.uploads[0];
          assert.deepEqual(repair.headers, uploadHeadersFor(digest, { repair: true }), 'a REPAIR grant: checksum-bound, without create-once');
          assert.ok(!Object.hasOwn(repair, 'authorization'), 'a direct storage grant forwards no bearer');

          // The provider enforces the repair grant exactly like a normal grant.
          assert.equal(await grantPut(repair, wrong), 400, 'wrong bytes under the repair grant: rejected by the provider');
          const omitted = await grantPut(repair, good, {});
          assert.ok(omitted === 403 || omitted === 400, `omitting the signed checksum header invalidates the grant (R2: 403 SignatureDoesNotMatch, MinIO: 400 AccessDenied; got ${omitted})`);
          assert.equal(await grantPut(repair, good), 200, 'correct bytes replace the corrupt object');
          created.add(digest);
          assert.ok(Buffer.from(await store.get(digest)).equals(good));

          assert.deepEqual(await store.verifyBlob({ digest, size: good.length }), { ok: true, method: fast });
          const preCommit = m.snapshot();
          const { release } = await commitManifest({ slug: 'live', manifest: manifestFor(good), blobs: store, metadata });
          assert.equal(release.artifactDigest, artifactDigest(manifestFor(good)));
          if (fast === 'provider-checksum') assert.equal(m.since(preCommit, 'GET'), 0, 'commit transferred zero payload bytes');

          // Repair-grant replay after commit: wrong bytes fail; correct bytes are harmless.
          assert.equal(await grantPut(repair, wrong), 400, 'still-valid REPAIR grant cannot write wrong bytes after commit');
          assert.equal(await grantPut(repair, good), 200, 'replaying the repair grant with the same correct bytes is harmless');
          assert.ok(Buffer.from(await store.get(digest)).equals(good), 'committed bytes are byte-identical after both replays');
        } else {
          const planned = await api('live', 'plan', manifestFor(good));
          assert.equal(planned.status, 200);
          assert.equal(planned.body.reused, 0, 'a proven-corrupt object is never reported reusable');
          assert.equal(planned.body.uploads.length, 1);
          assert.equal(m.since(mid, 'DELETE'), 0, 'plan is non-destructive: no DELETE');
          assert.equal(m.since(mid, 'PUT'), 0, 'plan minted nothing on storage');
          assert.equal(await store.has(digest), true, 'the corrupt object is left in place for the repair upload');
          const repair = planned.body.uploads[0];
          assertMediated(repair, digest, 'live');

          assert.equal(await relay(repair, wrong), 400, 'wrong repair bytes: rejected by artifactd');
          assert.equal(m.since(mid, 'PUT'), 0, 'wrong bytes never reached the provider');
          assert.ok(Buffer.from(await store.get(digest)).equals(wrong), 'still the corrupt bytes: nothing was written');
          assert.equal(await relay(repair, good), 204, 'correct bytes: artifactd hashed them, then wrote through put()');
          assert.equal(m.since(mid, 'PUT'), 1, 'exactly one provider write, by artifactd');
          created.add(digest);
          assert.ok(Buffer.from(await store.get(digest)).equals(good));

          assert.deepEqual(await store.verifyBlob({ digest, size: good.length }), { ok: true, method: fast });
          const preCommit = m.snapshot();
          const committed = await api('live', 'commit', manifestFor(good));
          assert.equal(committed.status, 201);
          assert.equal(committed.body.artifactDigest, artifactDigest(manifestFor(good)));
          if (fast === 'provider-checksum') assert.equal(m.since(preCommit, 'GET'), 0, 'commit transferred zero payload bytes');

          // Replay of the still-valid artifactd grant after commit: the digest check still holds.
          const postCommit = m.snapshot();
          assert.equal(await relay(repair, wrong), 400, 'post-commit replay with wrong bytes: rejected before storage');
          assert.equal(m.since(postCommit, 'PUT'), 0, 'no corrupt write reached the provider');
          assert.equal(await relay(repair, good), 204, 'post-commit replay with the correct bytes: harmless');
          assert.equal(m.since(postCommit, 'PUT'), 1);
          assert.ok(Buffer.from(await store.get(digest)).equals(good), 'committed bytes are byte-identical after both replays');
        }

        // ===== C. missing object via a normal grant: post-commit replay cannot corrupt =====
        const fresh = bytesOf('live integrity: brand-new object via a normal grant');
        const freshDigest = sha256(fresh);
        if (direct) {
          const normalPlan = await planManifest({ manifest: manifestFor(fresh), blobs: store, leases, uploadFactory: (d, o) => store.createUpload(d, { expires: 600, ...o }) });
          const normal = normalPlan.uploads[0];
          assert.deepEqual(normal.headers, uploadHeadersFor(freshDigest), 'a NORMAL grant is checksum-bound and create-once');
          assert.equal(await grantPut(normal, flipped(fresh)), 400, 'wrong bytes rejected');
          assert.equal(await grantPut(normal, fresh), 200);
          created.add(freshDigest);
          await commitManifest({ slug: 'fresh', manifest: manifestFor(fresh), blobs: store, metadata });
          const replay = await grantPut(normal, flipped(fresh));
          assert.ok(replay === 412 || replay === 400, `still-valid normal grant cannot corrupt committed CAS (HTTP ${replay})`);
        } else {
          const start = m.snapshot();
          const planned = await api('fresh', 'plan', manifestFor(fresh));
          assert.equal(planned.status, 200); assert.equal(planned.body.uploads.length, 1);
          const normal = planned.body.uploads[0];
          assertMediated(normal, freshDigest, 'fresh');
          assert.equal(await relay(normal, flipped(fresh)), 400, 'wrong bytes rejected by artifactd');
          assert.equal(m.since(start, 'PUT'), 0, 'wrong bytes never reached the provider');
          assert.equal(await relay(normal, fresh), 204);
          assert.equal(m.since(start, 'PUT'), 1);
          created.add(freshDigest);
          assert.equal((await api('fresh', 'commit', manifestFor(fresh))).status, 201);
          const postCommit = m.snapshot();
          assert.equal(await relay(normal, flipped(fresh)), 400, 'still-valid artifactd grant cannot corrupt committed CAS');
          assert.equal(m.since(postCommit, 'PUT'), 0);
        }
        assert.ok(Buffer.from(await store.get(freshDigest)).equals(fresh));

        // ===== D. identical re-publish reuses; no payload re-download where evidence is trusted =====
        const gets = m.counts.methods.GET ?? 0;
        const again = await planManifest({ manifest: manifestFor(good), blobs: store, leases, uploadFactory: async () => { throw new Error('must not upload'); } });
        assert.equal(again.reused, 1); assert.equal(again.uploads.length, 0);
        if (fast === 'provider-checksum') assert.equal((m.counts.methods.GET ?? 0) - gets, 0, 're-plan verified by HEAD evidence only');

        // ===== E. a legacy object without evidence is verified by streaming rehash =====
        const legacy = bytesOf('live integrity: legacy object without checksum evidence');
        const legacyDigest = sha256(legacy);
        assert.equal(await rawPut(legacyDigest, legacy), 200);
        assert.deepEqual(await store.verifyBlob({ digest: legacyDigest, size: legacy.length }), { ok: true, method: 'rehash' });
        let legacyReason = null;
        try { await store.verifyBlob({ digest: legacyDigest, size: legacy.length + 1 }); } catch (error) { legacyReason = `${error.code}/${error.reason}`; }
        assert.equal(legacyReason, 'OWA_BLOB_INTEGRITY/size', 'a wrong declared size on a valid legacy object is attributed to the manifest');

        t.diagnostic(`${entry.name} (${direct ? 'direct' : 'mediated'}) live requests by method: ${JSON.stringify(m.counts.methods)}; auth schemes: ${JSON.stringify(m.counts.schemes)}; OWA bearer to storage: ${m.counts.bearer}`);
        assert.equal(m.counts.bearer, 0, 'zero OWA bearer material reached the provider');
        assert.ok(Object.keys(m.counts.schemes).every(s => s === 'AWS4-HMAC-SHA256' || s === 'presigned'), 'storage credentials only');
        if (!direct) assert.ok(!Object.hasOwn(m.counts.schemes, 'presigned'), 'mediated mode: no presigned request reached the provider at all');
      } });
    } finally { m.restore(); }

    // cleanup already ran; the isolated prefix must be empty.
    assert.deepEqual(await store.listBlobs(), [], 'the isolated test prefix is empty after cleanup');
  });
}
