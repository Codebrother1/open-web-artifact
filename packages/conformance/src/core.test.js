import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, readFile, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { once } from 'node:events';
import { FilesystemBlobStore, FilesystemMetadataStore } from '../../storage-filesystem/src/index.js';
import { S3BlobStore } from '../../storage-s3/src/index.js';
import { activateRelease, commitManifest, packDirectory, publishDirectory, resolveRequestPath } from '../../core/src/index.js';
import { artifactDigest, canonicalJson } from '../../spec/src/index.js';
import { createArtifactServer } from '../../server/src/index.js';

test('canonical JSON is stable across object insertion order', () => {
  const a = { z: 1, a: { y: true, x: 'ok' }, list: [3, 2, 1] };
  const b = { list: [3, 2, 1], a: { x: 'ok', y: true }, z: 1 };
  assert.equal(canonicalJson(a), canonicalJson(b));
  assert.equal(artifactDigest(a), artifactDigest(b));
});

test('packDirectory is content addressed and deterministic', async () => {
  const root = await mkdtemp(join(tmpdir(), 'owa-site-'));
  await writeFile(join(root, 'index.html'), '<h1>Hello</h1>');
  const a = await packDirectory(root), b = await packDirectory(root);
  assert.equal(a.artifactDigest, b.artifactDigest);
  assert.equal(a.manifest.files.length, 1);
  assert.equal(a.manifest.files[0].path, '/index.html');
});

test('publish deduplicates blobs and activation rolls back without upload', async () => {
  const siteDir = await mkdtemp(join(tmpdir(), 'owa-site-'));
  const dataDir = await mkdtemp(join(tmpdir(), 'owa-data-'));
  await writeFile(join(siteDir, 'index.html'), 'v1');
  const blobs = new FilesystemBlobStore(dataDir), metadata = new FilesystemMetadataStore(dataDir);
  const v1 = await publishDirectory({ directory: siteDir, slug: 'demo', blobs, metadata });
  assert.equal(v1.uploaded, 1);
  const same = await publishDirectory({ directory: siteDir, slug: 'demo', blobs, metadata });
  assert.equal(same.uploaded, 0);
  assert.equal(same.reused, 1);
  await writeFile(join(siteDir, 'index.html'), 'v2');
  const v2 = await publishDirectory({ directory: siteDir, slug: 'demo', blobs, metadata });
  assert.equal(v2.uploaded, 1);
  await activateRelease(metadata, 'demo', v1.release.id);
  const site = await metadata.getSite('demo');
  assert.equal(site.activeReleaseId, v1.release.id);
});

test('commit rejects a manifest if referenced blobs are missing', async () => {
  const siteDir = await mkdtemp(join(tmpdir(), 'owa-site-'));
  const dataDir = await mkdtemp(join(tmpdir(), 'owa-data-'));
  await writeFile(join(siteDir, 'index.html'), 'missing');
  const packed = await packDirectory(siteDir);
  const blobs = new FilesystemBlobStore(dataDir), metadata = new FilesystemMetadataStore(dataDir);
  await assert.rejects(
    commitManifest({ slug: 'demo', manifest: packed.manifest, expectedArtifactDigest: packed.artifactDigest, blobs, metadata }),
    /Missing blob/
  );
});

test('request path resolves entrypoint and assets and rejects traversal', async () => {
  const root = await mkdtemp(join(tmpdir(), 'owa-site-'));
  await mkdir(join(root, 'assets'));
  await writeFile(join(root, 'index.html'), 'ok');
  await writeFile(join(root, 'assets', 'x.js'), 'x');
  const { manifest } = await packDirectory(root);
  assert.equal(resolveRequestPath(manifest, '/').path, '/index.html');
  assert.equal(resolveRequestPath(manifest, '/assets/x.js').path, '/assets/x.js');
  assert.equal(resolveRequestPath(manifest, '/%2e%2e/secret'), null);
});

test('S3 presigned PUT is deterministic and S3-compatible', () => {
  const store = new S3BlobStore({
    endpoint: 'https://example.r2.cloudflarestorage.com',
    bucket: 'artifacts',
    region: 'auto',
    accessKeyId: 'TESTACCESS',
    secretAccessKey: 'testsecret',
    now: () => new Date('2026-09-20T16:00:00.000Z')
  });
  const digest = `sha256:${'a'.repeat(64)}`;
  const url = new URL(store.presign('PUT', store.key(digest), { expires: 900 }));
  assert.equal(url.pathname, `/artifacts/owa/blobs/sha256/${'a'.repeat(64)}`);
  assert.equal(url.searchParams.get('X-Amz-Algorithm'), 'AWS4-HMAC-SHA256');
  assert.equal(url.searchParams.get('X-Amz-Expires'), '900');
  assert.match(url.searchParams.get('X-Amz-Signature'), /^[0-9a-f]{64}$/);
});

test('HTTP plan -> upload -> commit publishes without sending file bytes in commit', async () => {
  const siteDir = await mkdtemp(join(tmpdir(), 'owa-site-'));
  const dataDir = await mkdtemp(join(tmpdir(), 'owa-data-'));
  await writeFile(join(siteDir, 'index.html'), '<h1>remote</h1>');
  await writeFile(join(siteDir, 'app.js'), 'console.log("ok")');
  const packed = await packDirectory(siteDir);
  const blobs = new FilesystemBlobStore(dataDir), metadata = new FilesystemMetadataStore(dataDir);
  const server = createArtifactServer({ blobs, metadata, uploadSecret: 'test-secret' });
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  const address = server.address();
  const base = `http://127.0.0.1:${address.port}`;
  try {
    const planRes = await fetch(`${base}/v1/sites/remote/publish/plan`, {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ manifest: packed.manifest, artifactDigest: packed.artifactDigest })
    });
    assert.equal(planRes.status, 200);
    const plan = await planRes.json();
    assert.equal(plan.uploads.length, 2);
    for (const upload of plan.uploads) {
      const body = packed.blobs.get(upload.digest);
      const put = await fetch(upload.url, { method: 'PUT', body: Buffer.from(body) });
      assert.equal(put.status, 204);
    }
    const commitRes = await fetch(`${base}/v1/sites/remote/publish/commit`, {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ manifest: packed.manifest, artifactDigest: packed.artifactDigest })
    });
    assert.equal(commitRes.status, 201);
    const commit = await commitRes.json();
    assert.equal(commit.artifactDigest, packed.artifactDigest);

    const page = await fetch(`${base}/?site=remote`);
    assert.equal(page.status, 200);
    assert.equal(await page.text(), '<h1>remote</h1>');

    const secondPlan = await fetch(`${base}/v1/sites/remote/publish/plan`, {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ manifest: packed.manifest, artifactDigest: packed.artifactDigest })
    }).then(r => r.json());
    assert.equal(secondPlan.uploads.length, 0);
    assert.equal(secondPlan.reused, 2);
  } finally {
    server.close();
    await once(server, 'close');
  }
});

import { readOciLayout, writeOciLayout } from '../../transport-oci/src/index.js';

test('OCI layout round-trips the exact OWA artifact and blobs', async () => {
  const siteDir = await mkdtemp(join(tmpdir(), 'owa-site-'));
  const layoutDir = await mkdtemp(join(tmpdir(), 'owa-oci-'));
  await mkdir(join(siteDir, 'assets'));
  await writeFile(join(siteDir, 'index.html'), '<h1>OCI</h1>');
  await writeFile(join(siteDir, 'assets', 'app.js'), 'console.log("oci")');
  const packed = await packDirectory(siteDir);
  const written = await writeOciLayout({ manifest: packed.manifest, blobs: packed.blobs, output: layoutDir, ref: 'demo' });
  assert.equal(written.artifactDigest, packed.artifactDigest);
  assert.match(written.ociManifestDigest, /^sha256:[0-9a-f]{64}$/);
  assert.notEqual(written.ociManifestDigest, written.artifactDigest);
  const imported = await readOciLayout({ input: layoutDir, ref: 'demo' });
  assert.equal(imported.artifactDigest, packed.artifactDigest);
  assert.deepEqual(imported.manifest, packed.manifest);
  assert.equal(imported.blobs.size, packed.blobs.size);
  for (const [digest, data] of packed.blobs) assert.deepEqual(Buffer.from(imported.blobs.get(digest)), Buffer.from(data));
});

test('S3 SigV4 matches the published AWS presign test vector', () => {
  const store = new S3BlobStore({
    endpoint: 'https://s3.amazonaws.com',
    bucket: 'examplebucket',
    region: 'us-east-1',
    accessKeyId: 'AKIAIOSFODNN7EXAMPLE',
    secretAccessKey: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
    prefix: '',
    addressingStyle: 'virtual',
    now: () => new Date('2013-05-24T00:00:00.000Z')
  });
  const url = new URL(store.presign('GET', 'test.txt', { expires: 86400 }));
  assert.equal(url.host, 'examplebucket.s3.amazonaws.com');
  assert.equal(url.pathname, '/test.txt');
  assert.equal(url.searchParams.get('X-Amz-Signature'), 'aeeed9bbccd4d02ee5c0109b86d86835f995330da4c265957d157751f604d404');
});

test('published canonicalization test vector remains stable', async () => {
  const root = new URL('../../../docs/test-vectors/basic/', import.meta.url);
  const manifest = JSON.parse(await readFile(new URL('manifest.json', root), 'utf8'));
  const canonical = await readFile(new URL('canonical.json', root), 'utf8');
  const expectedDigest = (await readFile(new URL('artifact-digest.txt', root), 'utf8')).trim();
  assert.equal(canonicalJson(manifest), canonical);
  assert.equal(artifactDigest(manifest), expectedDigest);
});

test('packer rejects symlinks so artifacts cannot read outside their root', async () => {
  const root = await mkdtemp(join(tmpdir(), 'owa-site-'));
  const outside = join(await mkdtemp(join(tmpdir(), 'owa-secret-')), 'secret.txt');
  await writeFile(join(root, 'index.html'), 'ok');
  await writeFile(outside, 'secret');
  await symlink(outside, join(root, 'secret-link'));
  await assert.rejects(packDirectory(root), /Symlinks are not supported/);
});
