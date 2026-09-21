import test from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { once } from 'node:events';
import { mkdtemp, mkdir, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { packDirectory, publishDirectory } from '../../core/src/index.js';
import { artifactDigest, canonicalJson, sha256 } from '../../spec/src/index.js';
import { FilesystemBlobStore, FilesystemMetadataStore } from '../../storage-filesystem/src/index.js';
import { S3BlobStore } from '../../storage-s3/src/index.js';
import { createArtifactServer } from '../../server/src/index.js';
import { meterRequests, withRequestLimits } from './requests.js';

// These explicit opt-in variables never fall back to artifactd's OWA_S3_* settings.
// OWA_TEST_<PROVIDER>_DIRECT_UPLOAD_INTEGRITY=enforced asserts a provider PROVEN
// to enforce the direct final-CAS grant contract; otherwise the store's default
// applies (R2 auto-enforced; any other host mediated, so uploads travel through
// artifactd, which hashes the bytes before writing them with its own credentials).
const cases = [
  { name: 'MinIO path-style', provider: 'MINIO', style: 'path', endpoint: 'ENDPOINT', region: 'us-east-1' },
  { name: 'MinIO virtual-host', provider: 'MINIO', style: 'virtual', endpoint: 'VIRTUAL_ENDPOINT', region: 'us-east-1' },
  { name: 'Cloudflare R2 path-style', provider: 'R2', style: 'path', endpoint: 'ENDPOINT', region: 'auto' }
];

function configuration(entry) {
  const prefix = `OWA_TEST_${entry.provider}_`;
  const required = [entry.endpoint, 'BUCKET', 'ACCESS_KEY_ID', 'SECRET_ACCESS_KEY'];
  const missing = required.filter(key => !process.env[prefix + key]);
  if (missing.length) return { skip: `set ${missing.map(key => prefix + key).join(', ')}` };
  return { options: {
    endpoint: process.env[prefix + entry.endpoint],
    bucket: process.env[prefix + 'BUCKET'],
    region: process.env[prefix + 'REGION'] || entry.region,
    accessKeyId: process.env[prefix + 'ACCESS_KEY_ID'],
    secretAccessKey: process.env[prefix + 'SECRET_ACCESS_KEY'],
    sessionToken: process.env[prefix + 'SESSION_TOKEN'] || null,
    addressingStyle: entry.style,
    prefix: `owa-integration/${entry.provider.toLowerCase()}/${entry.style}/${randomUUID()}`,
    checksumEvidence: process.env[prefix + 'CHECKSUM_EVIDENCE'] || undefined,
    directUploadIntegrity: process.env[prefix + 'DIRECT_UPLOAD_INTEGRITY'] || undefined
  } };
}

function validateEndpoint(options) {
  let url;
  try { url = new URL(options.endpoint); } catch { throw new Error('Integration endpoint must be an absolute HTTP(S) URL'); }
  assert.ok(['http:', 'https:'].includes(url.protocol), 'Integration endpoint must use HTTP(S)');
  assert.ok(!url.username && !url.password && !url.search && !url.hash && url.pathname === '/',
    'Integration endpoint must be an origin, without credentials, path, query, or fragment');
}

async function post(base, slug, operation, packed, status) {
  const res = await fetch(`${base}/v1/sites/${slug}/publish/${operation}`, {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ manifest: packed.manifest, artifactDigest: packed.artifactDigest, activate: true })
  });
  // Do not print provider error bodies: they can echo signed URLs or credentials.
  assert.equal(res.status, status, `${operation} HTTP status`);
  return res.json();
}

function verifyUpload(upload, packed, store, base) {
  assert.equal(upload.method, 'PUT');
  assert.ok(packed.blobs.has(upload.digest), 'Plan must request a manifest blob');
  const url = new URL(upload.url);
  if (!store.canCreateSafeDirectUpload()) {
    // Mediated: artifactd's own local grant (legacy unscoped shape in dev auth).
    // No storage URL, credential or grant header leaves artifactd.
    assert.equal(url.origin, base, 'mediated grant targets the artifactd origin');
    assert.equal(url.pathname, `/v1/uploads/${encodeURIComponent(upload.digest)}`);
    assert.deepEqual([...url.searchParams.keys()].sort(), ['expires', 'sig'], 'local signed grant only');
    assert.ok(!Object.hasOwn(upload, 'headers'), 'no storage grant headers');
    assert.ok(![...url.searchParams.keys()].some(k => /^x-amz-/i.test(k)), 'not a presigned storage URL');
    return;
  }
  const endpoint = new URL(store.endpoint);
  assert.equal(url.protocol, endpoint.protocol);
  assert.equal(url.port, endpoint.port);
  // Assert the addressing shape independently of S3BlobStore.urlForKey().
  const key = `${store.prefix}/blobs/sha256/${upload.digest.slice('sha256:'.length)}`;
  assert.equal(url.hostname, store.addressingStyle === 'path' ? endpoint.hostname : `${store.bucket}.${endpoint.hostname}`);
  assert.equal(url.pathname, store.addressingStyle === 'path' ? `/${store.bucket}/${key}` : `/${key}`);
  assert.equal(url.searchParams.get('X-Amz-Algorithm'), 'AWS4-HMAC-SHA256');
  assert.equal(url.searchParams.get('X-Amz-SignedHeaders'), 'host;if-none-match;x-amz-checksum-sha256', 'grant is checksum-bound and create-once');
  assert.deepEqual(upload.headers, { 'x-amz-checksum-sha256': Buffer.from(upload.digest.slice('sha256:'.length), 'hex').toString('base64'), 'if-none-match': '*' });
  assert.match(url.searchParams.get('X-Amz-Signature'), /^[0-9a-f]{64}$/);
  assert.equal(url.searchParams.get('X-Amz-Expires'), String(upload.expiresIn));
  // Boolean assertions keep credential values out of failure diagnostics.
  assert.ok(url.searchParams.get('X-Amz-Credential')?.startsWith(`${store.accessKeyId}/`), 'Credential ID must match configuration');
  assert.ok(url.searchParams.get('X-Amz-Credential')?.endsWith(`/${store.region}/s3/aws4_request`), 'Credential scope must match region');
  if (store.sessionToken) assert.ok(url.searchParams.get('X-Amz-Security-Token') === store.sessionToken, 'Session token must be signed');
}

async function verifyServed(base, slug, packed) {
  for (const file of packed.manifest.files) {
    const path = file.path === packed.manifest.entrypoint ? '/' : file.path;
    const res = await fetch(`${base}${path}?site=${slug}`);
    assert.equal(res.status, 200, `Serve ${path} HTTP status`);
    const bytes = new Uint8Array(await res.arrayBuffer());
    assert.deepEqual(bytes, packed.blobs.get(file.digest), `Serve ${path} bytes`);
    assert.equal(sha256(bytes), file.digest);
    assert.equal(res.headers.get('content-type'), file.mediaType);
    assert.equal(res.headers.get('etag'), `"${file.digest}"`);
  }
}

for (const entry of cases) {
  const { skip, options } = configuration(entry);
  test(`${entry.name}: plan -> presigned PUT -> commit -> serve`, { skip }, async t => {
    validateEndpoint(options);
    const store = new S3BlobStore(options);
    const direct = store.canCreateSafeDirectUpload();
    const attempted = new Set();
    const root = await mkdtemp(join(tmpdir(), 'owa-live-s3-'));
    let server;
    t.diagnostic(`Isolated object prefix: ${store.prefix}`);
    t.diagnostic(`${entry.name}: checksumEvidence=${store.checksumEvidence} directUploadIntegrity=${store.directUploadIntegrity} (${direct ? 'direct storage grants' : 'artifactd-mediated uploads'}) node=${process.version}`);
    const m = meterRequests(new URL(options.endpoint).host);
    t.after(() => m.restore());

    async function cleanup() {
      const errors = [];
      try {
        if (server?.listening) {
          const closed = once(server, 'close');
          server.close();
          server.closeAllConnections();
          await closed;
        }
        // Delete only this run's attempted uploads, never list or empty a bucket.
        for (const digest of attempted) {
          try {
            const res = await store.signedFetch('DELETE', store.key(digest));
            await res.arrayBuffer();
            assert.ok(res.ok || res.status === 404, `Cleanup DELETE HTTP status ${res.status}`);
            assert.equal(await store.has(digest), false, 'Cleanup must remove the test blob');
          } catch {
            errors.push(new Error(`Cleanup failed for ${store.key(digest)}; remove this run's prefix manually`));
          }
        }
      } finally {
        await rm(root, { recursive: true, force: true });
      }
      if (errors.length) throw new AggregateError(errors, 'Integration object cleanup failed');
    }

    // Sequential requests still use real fetch, including adapter HEAD/GET/DELETE.
    await withRequestLimits({ signal: t.signal, cleanup, run: async () => {
      const directory = join(root, 'site');
      await mkdir(join(directory, 'assets'), { recursive: true });
      await writeFile(join(directory, 'index.html'), '<h1>OWA integration v1</h1>');
      await writeFile(join(directory, 'assets', 'app.js'), 'console.log("owa integration");\n');
      await writeFile(join(directory, 'assets', 'copy.js'), 'console.log("owa integration");\n');
      await writeFile(join(directory, 'assets', 'bytes.bin'), Buffer.from([0, 1, 127, 128, 254, 255]));
      const localBlobs = new FilesystemBlobStore(join(root, 'local'));
      const localMetadata = new FilesystemMetadataStore(join(root, 'local'));
      const remoteMetadata = new FilesystemMetadataStore(join(root, 'remote'));
      server = createArtifactServer({ blobs: store, metadata: remoteMetadata, auth: { mode: 'dev' } });
      server.listen(0, '127.0.0.1');
      await once(server, 'listening');
      const base = `http://127.0.0.1:${server.address().port}`;
      const slug = 'integration';
      const first = await packDirectory(directory);
      assert.equal(first.manifest.files.length, 4);
      assert.equal(first.blobs.size, 3, 'Duplicate files share a blob');
      const releases = [];

      async function publish(packed, expectedUploads, expectedReused, expectedDigests) {
        const plan = await post(base, slug, 'plan', packed, 200);
        assert.equal(plan.artifactDigest, packed.artifactDigest);
        assert.equal(plan.uploads.length, expectedUploads);
        assert.equal(plan.reused, expectedReused);
        assert.deepEqual(plan.uploads.map(u => u.digest).sort(), [...expectedDigests].sort());
        let uploaded = 0;
        const grants = [];
        for (const upload of plan.uploads) {
          verifyUpload(upload, packed, store, base);
          attempted.add(upload.digest); // Also clean up a PUT whose response is lost.
          const bytes = Buffer.from(packed.blobs.get(upload.digest));
          const headers = upload.headers ?? {};
          const before = m.snapshot();
          // Same-length WRONG bytes with the grant's own headers. Direct: the
          // PROVIDER must refuse them, because the checksum is validated against
          // the payload. Mediated: artifactd refuses them before any storage write.
          const wrong = await fetch(upload.url, { method: upload.method, headers, body: Buffer.from(bytes.map(b => b ^ 0xff)) });
          await wrong.arrayBuffer();
          assert.equal(wrong.status, 400, `${direct ? 'Provider' : 'artifactd'} rejects wrong bytes (HTTP ${wrong.status})`);
          if (!direct) assert.equal(m.since(before, 'PUT'), 0, 'wrong bytes never reached the provider');
          const put = await fetch(upload.url, { method: upload.method, headers, body: bytes });
          await put.arrayBuffer();
          assert.ok(put.ok, `${direct ? 'Direct' : 'Mediated'} PUT HTTP status ${put.status}`);
          if (!direct) assert.equal(m.since(before, 'PUT'), 1, 'exactly one provider write, by artifactd, after its digest check');
          uploaded++;
          grants.push({ upload, bytes });
        }
        assert.equal(uploaded, expectedUploads, `Actual ${direct ? 'direct' : 'mediated'} upload count`);
        const commit = await post(base, slug, 'commit', packed, 201);
        // POST-COMMIT TOCTOU: the still-valid grants must not be able to corrupt
        // the committed object. Direct: create-once fails first; checksum would
        // too. Mediated: artifactd's digest check fails; nothing reaches storage.
        for (const { upload, bytes } of grants) {
          const before = m.snapshot();
          const again = await fetch(upload.url, { method: upload.method, headers: upload.headers ?? {}, body: Buffer.from(bytes.map(b => b ^ 0xff)) });
          await again.arrayBuffer();
          if (direct) assert.ok(again.status === 412 || again.status === 400, `Still-valid grant cannot overwrite committed CAS (HTTP ${again.status})`);
          else { assert.equal(again.status, 400, 'still-valid artifactd grant cannot corrupt committed CAS'); assert.equal(m.since(before, 'PUT'), 0, 'no corrupt write reached the provider'); }
          assert.ok(Buffer.from(await store.get(upload.digest)).equals(bytes), 'committed bytes are unchanged after the reuse attempt');
        }
        assert.equal(commit.artifactDigest, packed.artifactDigest);
        assert.equal(commit.activeReleaseId, commit.releaseId);
        assert.ok(!releases.some(r => r.id === commit.releaseId), 'Each commit creates an immutable release');

        const local = await publishDirectory({ directory, slug, blobs: localBlobs, metadata: localMetadata });
        assert.equal(local.uploaded, expectedUploads);
        assert.equal(local.reused, expectedReused);
        assert.equal(local.release.artifactDigest, commit.artifactDigest, 'Filesystem and S3 artifact identities match');
        const site = await remoteMetadata.getSite(slug);
        const remote = await remoteMetadata.getRelease(site.id, commit.releaseId);
        assert.equal(artifactDigest(remote.manifest), commit.artifactDigest);
        assert.equal(canonicalJson(remote.manifest), canonicalJson(local.release.manifest));
        assert.deepEqual(remote.manifest, packed.manifest);
        releases.push(remote);
        // Later commits must not mutate earlier release manifests or identities.
        for (const release of releases) assert.deepEqual(await remoteMetadata.getRelease(site.id, release.id), release);
        await verifyServed(base, slug, packed);
        t.diagnostic(`${expectedUploads} uploaded, ${expectedReused} reused; filesystem/S3 identity ${commit.artifactDigest}`);
      }

      // Commit must fail before missing blobs have reached the object store.
      const missing = await post(base, slug, 'commit', first, 500);
      assert.equal(missing.code, 'OWA_BLOB_MISSING',
        'Commit must reject a missing blob without exposing provider error bodies');
      assert.equal(await remoteMetadata.getSite(slug), null);
      await publish(first, 3, 0, first.blobs.keys());
      const identical = await packDirectory(directory);
      assert.equal(identical.artifactDigest, first.artifactDigest);
      await publish(identical, 0, 3, []);
      await writeFile(join(directory, 'index.html'), '<h1>OWA integration v2</h1>');
      const changed = await packDirectory(directory);
      assert.notEqual(changed.artifactDigest, first.artifactDigest);
      const newDigests = [...changed.blobs.keys()].filter(digest => !first.blobs.has(digest));
      assert.equal(newDigests.length, 1);
      await publish(changed, 1, 2, newDigests);
      t.diagnostic(`${entry.name} (${direct ? 'direct' : 'mediated'}) live requests by method: ${JSON.stringify(m.counts.methods)}; auth schemes: ${JSON.stringify(m.counts.schemes)}; OWA bearer to storage: ${m.counts.bearer}`);
      assert.equal(m.counts.bearer, 0, 'zero OWA bearer material reached the provider');
      if (!direct) assert.ok(!Object.hasOwn(m.counts.schemes, 'presigned'), 'mediated mode: no presigned request reached the provider');
    } });
  });
}
