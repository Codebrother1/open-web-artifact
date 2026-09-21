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

// Live commit-boundary integrity evidence (issue #10) against a real S3/R2
// service. Opt-in through the explicit OWA_TEST_* variables; never a fallback to
// artifactd's own configuration. A skipped case is not evidence.
//
// Every object lives under a UUID-isolated prefix that is emptied at the end.
// Only aggregate counts, statuses and digests are reported — never a URL,
// signature, Authorization value or credential.
const PROVIDERS = [{ name: 'Cloudflare R2', provider: 'R2', region: 'auto' }];

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
      sessionToken: process.env[prefix + 'SESSION_TOKEN'] || null, addressingStyle: 'path'
    }
  };
}

const bytesOf = text => Buffer.from(text, 'utf8');
function single(bytes) {
  const manifest = {
    specVersion: 'owa.dev/v1', artifactType: 'application/vnd.openwebartifact.site.v1+json', entrypoint: '/index.html',
    files: [{ path: '/index.html', digest: sha256(bytes), size: bytes.length, mediaType: 'text/html' }],
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
  return { counts, restore: () => { globalThis.fetch = real; } };
}

for (const entry of PROVIDERS) {
  const { skip, options, runId } = configuration(entry);
  test(`${entry.name}: live commit-boundary integrity in an isolated prefix`, { skip, timeout: 180_000 }, async t => {
    const root = await mkdtemp(join(tmpdir(), 'owa-integrity-live-'));
    const store = new S3BlobStore({ ...options, prefix: `owa-integrity-integration/${runId}` });
    const metadata = new FilesystemMetadataStore(root), leases = new FilesystemLeaseStore(root);
    const created = new Set();
    const good = bytesOf('live integrity: the correct committed bytes');
    const wrong = Buffer.from(good.map(b => b ^ 0xff)); // same length, every byte different
    const digest = sha256(good);
    const legacyGood = bytesOf('live integrity: legacy object without checksum evidence');
    const legacyDigest = sha256(legacyGood);
    const m = meter(new URL(options.endpoint).host);
    /** Write bytes with NO checksum header, as a pre-change server or external tool would. */
    const rawPut = (d, body) => store.signedFetch('PUT', store.key(d), { body }).then(async r => { await r.arrayBuffer(); created.add(d); return r.status; });
    const grantPut = (grant, body, headers = grant.headers) => fetch(grant.url, { method: 'PUT', headers, body }).then(async r => { await r.arrayBuffer(); return r.status; });

    async function cleanup() {
      m.restore();
      for (const d of created) await store.delete(d).catch(() => {});
      await rm(root, { recursive: true, force: true });
    }

    await withRequestLimits({ signal: t.signal, cleanup, run: async () => {
      // --- 1. a CORRUPT object already sits at the CAS key (no evidence) ------
      assert.equal(await rawPut(digest, wrong), 200, 'arrange: corrupt same-length bytes planted without a checksum');

      // --- 2. commit refuses it, and no site/release appears ---------------------
      let code = null;
      try { await commitManifest({ slug: 'live', manifest: single(good), blobs: store, metadata }); } catch (error) { code = error.code; }
      assert.equal(code, 'OWA_BLOB_INTEGRITY', 'wrong-content object cannot be committed');
      assert.equal(await metadata.getSite('live'), null, 'no site record was created');

      // --- 3. plan repairs: not reusable, object removed, grant issued ----------
      const plan = await planManifest({ manifest: single(good), blobs: store, leases, uploadFactory: d => store.createUpload(d, { expires: 600 }) });
      assert.equal(plan.reused, 0, 'a proven-corrupt object is never reported reusable');
      assert.equal(plan.uploads.length, 1);
      assert.equal(await store.has(digest), false, 'the corrupt object was deleted so a create-once upload can replace it');
      const grant = plan.uploads[0];
      assert.deepEqual(grant.headers, uploadHeadersFor(digest), 'grant carries exactly the integrity-binding headers');

      // --- 4. the provider enforces the grant -----------------------------------
      assert.equal(await grantPut(grant, wrong), 400, 'wrong bytes under the checksum-bound grant: rejected by the provider');
      assert.equal(await grantPut(grant, good, { 'if-none-match': '*' }), 403, 'omitting the signed checksum header invalidates the grant');
      assert.equal(await grantPut(grant, good), 200, 'correct bytes with the exact headers: accepted');
      created.add(digest);
      assert.equal(await grantPut(grant, good), 412, 'the same grant cannot write again, even the same bytes');

      // --- 5. evidence is retrievable without a download, then commit succeeds ---
      assert.deepEqual(await store.verifyBlob({ digest, size: good.length }), { ok: true, method: 'provider-checksum' }, 'provider SHA-256 evidence verifies with a HEAD alone');
      const before = { ...m.counts.methods };
      const { release } = await commitManifest({ slug: 'live', manifest: single(good), blobs: store, metadata });
      assert.equal(release.artifactDigest, artifactDigest(single(good)));
      assert.equal((m.counts.methods.GET ?? 0) - (before.GET ?? 0), 0, 'commit transferred zero payload bytes');

      // --- 6. POST-COMMIT TOCTOU: the still-valid grant is replayed -------------
      assert.equal(await grantPut(grant, wrong), 412, 'still-valid grant cannot corrupt the committed object');
      assert.ok(Buffer.from(await store.get(digest)).equals(good), 'committed bytes are byte-identical after the replay');

      // --- 7. identical re-publish reuses with no payload re-download -----------
      const gets = m.counts.methods.GET ?? 0;
      const again = await planManifest({ manifest: single(good), blobs: store, leases, uploadFactory: async () => { throw new Error('must not upload'); } });
      assert.equal(again.reused, 1); assert.equal(again.uploads.length, 0);
      assert.equal((m.counts.methods.GET ?? 0) - gets, 0, 're-plan verified by HEAD evidence only');

      // --- 8. a legacy object without evidence is verified by streaming rehash ---
      assert.equal(await rawPut(legacyDigest, legacyGood), 200);
      assert.deepEqual(await store.verifyBlob({ digest: legacyDigest, size: legacyGood.length }), { ok: true, method: 'rehash' }, 'no evidence falls back to a definitive rehash');
      let legacyCode = null;
      try { await store.verifyBlob({ digest: legacyDigest, size: legacyGood.length + 1 }); } catch (error) { legacyCode = error.code; }
      assert.equal(legacyCode, 'OWA_BLOB_INTEGRITY', 'declared size is checked against the real object');

      t.diagnostic(`live requests by method: ${JSON.stringify(m.counts.methods)}; auth schemes: ${JSON.stringify(m.counts.schemes)}; OWA bearer to storage: ${m.counts.bearer}`);
      assert.equal(m.counts.bearer, 0, 'zero OWA bearer material reached the provider');
      assert.ok(Object.keys(m.counts.schemes).every(s => s === 'AWS4-HMAC-SHA256' || s === 'presigned'), 'storage credentials only');
    } });

    // cleanup already ran; the isolated prefix must be empty.
    assert.deepEqual(await store.listBlobs(), [], 'the isolated test prefix is empty after cleanup');
  });
}
