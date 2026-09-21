import test from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { artifactDigest, sha256, validateManifest } from '../../spec/src/index.js';
import { FilesystemLeaseStore, FilesystemMetadataStore } from '../../storage-filesystem/src/index.js';
import { S3BlobStore } from '../../storage-s3/src/index.js';
import { collectGarbage } from '../../gc/src/index.js';
import { withRequestLimits } from './requests.js';

// Live GC validation against a real S3/R2-compatible service. Opt-in through the
// same explicit OWA_TEST_* variables as the publishing suite; never a fallback
// to artifactd's own OWA_S3_* configuration. A skipped case is not evidence.
//
// Every object this test creates lives under a UUID-isolated prefix of its own,
// separate from the publishing suite's prefix, so a GC bug cannot reach another
// run's objects — and so the "neighbouring keys survive" assertion is real.
const PROVIDERS = [{ name: 'Cloudflare R2', provider: 'R2', region: 'auto' }];
const NOW = new Date('2026-06-01T12:00:00.000Z');

function configuration(entry) {
  const prefix = `OWA_TEST_${entry.provider}_`;
  const required = ['ENDPOINT', 'BUCKET', 'ACCESS_KEY_ID', 'SECRET_ACCESS_KEY'];
  const missing = required.filter(key => !process.env[prefix + key]);
  if (missing.length) return { skip: `set ${missing.map(key => prefix + key).join(', ')}` };
  return {
    runId: randomUUID(),
    options: {
      endpoint: process.env[prefix + 'ENDPOINT'],
      bucket: process.env[prefix + 'BUCKET'],
      region: process.env[prefix + 'REGION'] || entry.region,
      accessKeyId: process.env[prefix + 'ACCESS_KEY_ID'],
      secretAccessKey: process.env[prefix + 'SECRET_ACCESS_KEY'],
      sessionToken: process.env[prefix + 'SESSION_TOKEN'] || null,
      addressingStyle: 'path'
    }
  };
}

const bytesOf = text => Buffer.from(text, 'utf8');

function manifestFor(files) {
  const manifest = {
    specVersion: 'owa.dev/v1',
    artifactType: 'application/vnd.openwebartifact.site.v1+json',
    entrypoint: files[0].path,
    files: files.map(file => ({
      path: file.path, digest: sha256(bytesOf(file.text)),
      size: Buffer.byteLength(file.text), mediaType: 'text/html'
    })),
    access: { visibility: 'public' },
    lifecycle: { expiresAt: null }
  };
  validateManifest(manifest);
  return manifest;
}

for (const entry of PROVIDERS) {
  const { skip, options, runId } = configuration(entry);
  test(`${entry.name}: live mark/sweep GC inside an isolated prefix`, { skip, timeout: 180_000 }, async t => {
    const root = await mkdtemp(join(tmpdir(), 'owa-gc-live-'));
    // Two sibling prefixes under one isolated run root. GC is pointed at ONLY
    // the first; the second stands in for unrelated bucket contents.
    const base = `owa-gc-integration/${runId}`;
    const store = new S3BlobStore({ ...options, prefix: `${base}/managed` });
    const neighbour = new S3BlobStore({ ...options, prefix: `${base}/neighbour` });
    const metadata = new FilesystemMetadataStore(root);
    // The lease store and the collector MUST share a clock. A fixed lease clock
    // with a wall-clock collector would make every lease look already expired.
    const leases = new FilesystemLeaseStore(root);

    const created = [];
    async function put(target, text) {
      const digest = sha256(bytesOf(text));
      await target.put(digest, bytesOf(text));
      created.push([target, digest]);
      return digest;
    }

    async function cleanup() {
      const errors = [];
      for (const [target, digest] of created) {
        try { await target.delete(digest); } catch { errors.push(digest); }
      }
      await rm(root, { recursive: true, force: true });
      if (errors.length) throw new Error(`Live GC cleanup failed for ${errors.length} object(s); remove prefix ${base} manually`);
    }

    await withRequestLimits({ signal: t.signal, cleanup, run: async () => {
      // --- arrange: one referenced blob, one leased blob, one true orphan ----
      const referenced = await put(store, 'live gc: referenced by a release');
      const leased = await put(store, 'live gc: protected by a publish lease');
      const orphan = await put(store, 'live gc: a true orphan');
      const outside = await put(neighbour, 'live gc: unrelated neighbouring object');

      const manifest = manifestFor([{ path: '/index.html', text: 'live gc: referenced by a release' }]);
      const site = { id: `s_${sha256(bytesOf(runId)).slice(7, 27)}`, slug: 'gclive', activeReleaseId: null, createdAt: NOW.toISOString() };
      const releaseId = `r_${sha256(bytesOf(`${runId}:r`)).slice(7, 27)}`;
      site.activeReleaseId = releaseId;
      await metadata.saveSite(site);
      await metadata.saveRelease(site.id, { id: releaseId, artifactDigest: artifactDigest(manifest), createdAt: NOW.toISOString(), manifest });
      await leases.refresh([leased], { ttlSeconds: 3600 });

      // 1. real ListObjectsV2 reaches the provider and sees exactly our prefix.
      const listed = await store.listBlobs();
      assert.deepEqual(listed.map(object => object.digest).sort(), [referenced, leased, orphan].sort(),
        'live listing returns exactly the managed-prefix objects');
      t.diagnostic(`live list: ${listed.length} objects under ${base}/managed`);

      // Grace 0 with a clock just after upload: the production 24h default is
      // untouched, this run simply does not wait a day for its own objects.
      const gcNow = () => new Date(Date.now() + 1000);
      const common = { blobs: store, metadata, leases, now: gcNow, graceSeconds: 0 };

      // 2/3. dry run identifies only the orphan and deletes nothing.
      const dry = await collectGarbage({ ...common });
      assert.equal(dry.mode, 'dry-run');
      assert.deepEqual(dry.candidateDigests, [orphan], 'only the true orphan is a candidate');
      assert.equal(dry.referencedSkipped, 1, 'the released blob is marked');
      assert.equal(dry.leasedSkipped, 1, 'the leased blob is protected');
      assert.equal(dry.deleted, 0);
      for (const digest of [referenced, leased, orphan]) {
        assert.equal(await store.has(digest), true, 'dry run must delete nothing');
      }

      // 4/5/6. apply deletes only the orphan.
      const applied = await collectGarbage({ ...common, apply: true });
      assert.equal(applied.mode, 'apply');
      assert.equal(applied.deleted, 1);
      assert.equal(await store.has(referenced), true, 'the release-referenced blob survives apply');
      assert.equal(await store.has(leased), true, 'the leased blob survives apply');
      assert.equal(await store.has(orphan), false, 'the orphan is reclaimed');

      // 7. nothing outside the configured prefix was touched.
      assert.equal(await neighbour.has(outside), true, 'a neighbouring prefix is never a GC candidate');
      assert.deepEqual((await neighbour.listBlobs()).map(object => object.digest), [outside]);

      // The release record is still intact after a live apply.
      const stored = await metadata.getRelease(site.id, releaseId);
      assert.equal(stored.artifactDigest, artifactDigest(manifest), 'live GC does not touch release metadata');
      t.diagnostic(`live apply: deleted ${applied.deleted}, referenced kept ${applied.referencedSkipped}, leased kept ${applied.leasedSkipped}`);
    } });

    // 8/9. cleanup already ran; confirm the isolated prefix is empty.
    const remaining = [...(await store.listBlobs()), ...(await neighbour.listBlobs())];
    assert.deepEqual(remaining, [], 'the isolated test prefix is empty after cleanup');
  });
}
