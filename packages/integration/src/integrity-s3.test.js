import test from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { artifactDigest, sha256, validateManifest } from '../../spec/src/index.js';
import { FilesystemLeaseStore, FilesystemMetadataStore } from '../../storage-filesystem/src/index.js';
import { S3BlobStore, uploadHeadersFor } from '../../storage-s3/src/index.js';
import { commitManifest, planManifest } from '../../core/src/index.js';
import { withRequestLimits } from './requests.js';

// Live commit-boundary integrity evidence (issue #10) against real S3-compatible
// services. Opt-in through the explicit OWA_TEST_* variables; never a fallback to
// artifactd's own configuration. A skipped case is not evidence.
//
// Every object lives under a UUID-isolated prefix that is emptied at the end.
// Only aggregate counts, statuses and digests are reported — never a URL,
// signature, Authorization value or credential.
//
// OWA_TEST_<PROVIDER>_CHECKSUM_EVIDENCE may be set to `enforced` once a provider
// has been PROVEN (by the probe) to validate x-amz-checksum-sha256 against the
// bytes it stores; otherwise the store's conservative default applies.
const PROVIDERS = [
  { name: 'Cloudflare R2', provider: 'R2', region: 'auto' },
  { name: 'MinIO', provider: 'MINIO', region: 'us-east-1' }
];

function configuration(entry) {
  const prefix = `OWA_TEST_${entry.provider}_`;
  const required = ['ENDPOINT', 'BUCKET', 'ACCESS_KEY_ID', 'SECRET_ACCESS_KEY'];
  const missing = required.filter(key => !process.env[prefix + key]);
  if (missing.length) return { skip: `set ${missing.map(key => prefix + key).join(', ')}` };
  return {
    runId: randomUUID(),
    options: {
      endpoint: process.env[prefix + 'ENDPOINT'], bucket: process.env[prefix + 'BUCKET'],
      region: process.env[prefix + 'REGION'] || entry.region,
      accessKeyId: process.env[prefix + 'ACCESS_KEY_ID'], secretAccessKey: process.env[prefix + 'SECRET_ACCESS_KEY'],
      sessionToken: process.env[prefix + 'SESSION_TOKEN'] || null, addressingStyle: 'path',
      checksumEvidence: process.env[prefix + 'CHECKSUM_EVIDENCE'] || undefined
    }
  };
}

const bytesOf = text => Buffer.from(text, 'utf8');
function manifestFor(bytes, { size = bytes.length } = {}) {
  const manifest = {
    specVersion: 'owa.dev/v1', artifactType: 'application/vnd.openwebartifact.site.v1+json', entrypoint: '/index.html',
    files: [{ path: '/index.html', digest: sha256(bytes), size, mediaType: 'text/html' }],
    access: { visibility: 'public' }, lifecycle: { expiresAt: null }
  };
  validateManifest(manifest);
  return manifest;
}

/** Count provider requests by method and Authorization scheme. Records nothing else. */
function meter(endpointHost) {
  const counts = { methods: {}, schemes: {}, bearer: 0 };
  const real = globalThis.fetch;
  globalThis.fetch = async (url, options = {}) => {
    const target = String(url);
    if (new URL(target).host === endpointHost) {
      const method = (options.method ?? 'GET').toUpperCase();
      counts.methods[method] = (counts.methods[method] ?? 0) + 1;
      const auth = new Headers(options.headers ?? {}).get('authorization');
      const scheme = auth ? auth.split(' ')[0] : (target.includes('X-Amz-Signature=') ? 'presigned' : 'none');
      counts.schemes[scheme] = (counts.schemes[scheme] ?? 0) + 1;
      if (/^bearer$/i.test(scheme) || /owa1\./.test(target)) counts.bearer++;
    }
    return real(url, options);
  };
  return { counts, snapshot: () => ({ ...counts.methods }), restore: () => { globalThis.fetch = real; } };
}

for (const entry of PROVIDERS) {
  const { skip, options, runId } = configuration(entry);
  test(`${entry.name}: live commit-boundary integrity in an isolated prefix`, { skip, timeout: 240_000 }, async t => {
    const root = await mkdtemp(join(tmpdir(), 'owa-integrity-live-'));
    const store = new S3BlobStore({ ...options, prefix: `owa-integrity-integration/${runId}` });
    const metadata = new FilesystemMetadataStore(root), leases = new FilesystemLeaseStore(root);
    const created = new Set();
    const fast = store.checksumEvidence === 'enforced' ? 'provider-checksum' : 'rehash';
    t.diagnostic(`${entry.name}: addressing=${options.addressingStyle} region=${options.region} checksumEvidence=${store.checksumEvidence} node=${process.version}`);
    const m = meter(new URL(options.endpoint).host);
    /** Write bytes with NO checksum header, as a pre-change server or external tool would. */
    const rawPut = (d, body) => store.signedFetch('PUT', store.key(d), { body }).then(async r => { await r.arrayBuffer(); created.add(d); return r.status; });
    const grantPut = (grant, body, headers = grant.headers) => fetch(grant.url, { method: 'PUT', headers, body }).then(async r => { await r.arrayBuffer(); return r.status; });
    const cleanup = async () => { m.restore(); for (const d of created) await store.delete(d).catch(() => {}); await rm(root, { recursive: true, force: true }); };

    await withRequestLimits({ signal: t.signal, cleanup, run: async () => {
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
      assert.equal((m.counts.methods.DELETE ?? 0) - (before.DELETE ?? 0), 0, 'zero deletes');
      assert.equal((m.counts.methods.PUT ?? 0) - (before.PUT ?? 0), 0, 'zero writes');
      assert.ok(Buffer.from(await store.get(sharedDigest)).equals(shared), 'the shared object is byte-identical');
      assert.equal(JSON.stringify({ site: await metadata.getSite('site-a'), releases: await metadata.listAllReleases(siteA.site.id) }), siteASnapshot, 'site A release metadata and active pointer unchanged');
      assert.equal(await metadata.getSite('site-b'), null);

      // ===== B. genuinely corrupt object: non-destructive repair =====
      const good = bytesOf('live integrity: the correct committed bytes');
      const wrong = Buffer.from(good.map(b => b ^ 0xff)); // same length, every byte different
      const digest = sha256(good);
      assert.equal(await rawPut(digest, wrong), 200, 'arrange: corrupt same-length bytes planted without a checksum');
      code = null;
      try { await commitManifest({ slug: 'live', manifest: manifestFor(good), blobs: store, metadata }); } catch (error) { code = error.code; }
      assert.equal(code, 'OWA_BLOB_INTEGRITY', 'wrong-content object cannot be committed');
      assert.equal(await metadata.getSite('live'), null, 'no site record was created');

      const mid = m.snapshot();
      const plan = await planManifest({ manifest: manifestFor(good), blobs: store, leases, uploadFactory: (d, o) => store.createUpload(d, { expires: 600, ...o }) });
      assert.equal(plan.reused, 0, 'a proven-corrupt object is never reported reusable');
      assert.equal(plan.uploads.length, 1);
      assert.equal((m.counts.methods.DELETE ?? 0) - (mid.DELETE ?? 0), 0, 'plan is non-destructive: no DELETE');
      assert.equal(await store.has(digest), true, 'the corrupt object is left in place for the repair upload');
      const repair = plan.uploads[0];
      assert.deepEqual(repair.headers, uploadHeadersFor(digest, { repair: true }), 'a REPAIR grant: checksum-bound, without create-once');

      // The provider enforces the repair grant exactly like a normal grant.
      assert.equal(await grantPut(repair, wrong), 400, 'wrong bytes under the repair grant: rejected by the provider');
      const omitted = await grantPut(repair, good, {});
      assert.ok(omitted === 403 || omitted === 400, `omitting the signed checksum header invalidates the grant (R2: 403 SignatureDoesNotMatch, MinIO: 400 AccessDenied; got ${omitted})`);
      assert.equal(await grantPut(repair, good), 200, 'correct bytes replace the corrupt object');
      created.add(digest);
      assert.ok(Buffer.from(await store.get(digest)).equals(good));

      // Verification evidence, then commit with no payload transfer on an enforced provider.
      assert.deepEqual(await store.verifyBlob({ digest, size: good.length }), { ok: true, method: fast });
      const preCommit = m.snapshot();
      const { release } = await commitManifest({ slug: 'live', manifest: manifestFor(good), blobs: store, metadata });
      assert.equal(release.artifactDigest, artifactDigest(manifestFor(good)));
      if (fast === 'provider-checksum') assert.equal((m.counts.methods.GET ?? 0) - (preCommit.GET ?? 0), 0, 'commit transferred zero payload bytes');

      // Repair-grant replay after commit: wrong bytes fail; correct bytes are harmless.
      assert.equal(await grantPut(repair, wrong), 400, 'still-valid REPAIR grant cannot write wrong bytes after commit');
      assert.equal(await grantPut(repair, good), 200, 'replaying the repair grant with the same correct bytes is harmless');
      assert.ok(Buffer.from(await store.get(digest)).equals(good), 'committed bytes are byte-identical after both replays');

      // ===== C. normal create-once grant: post-commit replay cannot corrupt =====
      const fresh = bytesOf('live integrity: brand-new object via a normal grant');
      const freshDigest = sha256(fresh);
      const normalPlan = await planManifest({ manifest: manifestFor(fresh), blobs: store, leases, uploadFactory: (d, o) => store.createUpload(d, { expires: 600, ...o }) });
      const normal = normalPlan.uploads[0];
      assert.deepEqual(normal.headers, uploadHeadersFor(freshDigest), 'a NORMAL grant is checksum-bound and create-once');
      assert.equal(await grantPut(normal, Buffer.from(fresh.map(b => b ^ 0xff))), 400, 'wrong bytes rejected');
      assert.equal(await grantPut(normal, fresh), 200);
      created.add(freshDigest);
      await commitManifest({ slug: 'fresh', manifest: manifestFor(fresh), blobs: store, metadata });
      const replay = await grantPut(normal, Buffer.from(fresh.map(b => b ^ 0xff)));
      assert.ok(replay === 412 || replay === 400, `still-valid normal grant cannot corrupt committed CAS (HTTP ${replay})`);
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

      t.diagnostic(`${entry.name} live requests by method: ${JSON.stringify(m.counts.methods)}; auth schemes: ${JSON.stringify(m.counts.schemes)}; OWA bearer to storage: ${m.counts.bearer}`);
      assert.equal(m.counts.bearer, 0, 'zero OWA bearer material reached the provider');
      assert.ok(Object.keys(m.counts.schemes).every(s => s === 'AWS4-HMAC-SHA256' || s === 'presigned'), 'storage credentials only');
    } });

    // cleanup already ran; the isolated prefix must be empty.
    assert.deepEqual(await store.listBlobs(), [], 'the isolated test prefix is empty after cleanup');
  });
}
