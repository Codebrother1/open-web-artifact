import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash, randomUUID } from 'node:crypto';
import { mkdir, mkdtemp, readFile, readdir, rm, stat, symlink, utimes, writeFile } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  FilesystemBlobStore, FilesystemLeaseStore, FilesystemMetadataStore
} from '../../storage-filesystem/src/index.js';
import { S3BlobStore, decodeXmlText } from '../../storage-s3/src/index.js';
import { PUBLISH_LEASE_TTL_SECONDS, commitManifest, planManifest, publishDirectory } from '../../core/src/index.js';
import { artifactDigest, canonicalJson, validateManifest } from '../../spec/src/index.js';
import { DEFAULT_GRACE_SECONDS, GcError, collectGarbage, formatReport } from '../src/index.js';

const HOUR = 3600 * 1000;
const NOW = new Date('2026-06-01T12:00:00.000Z');
const clock = () => NOW;
const digestOf = bytes => `sha256:${createHash('sha256').update(bytes).digest('hex')}`;

function manifestFor(files, { expiresAt = null } = {}) {
  const manifest = {
    specVersion: 'owa.dev/v1',
    artifactType: 'application/vnd.openwebartifact.site.v1+json',
    entrypoint: files[0].path,
    files: files.map(file => ({
      path: file.path, digest: digestOf(Buffer.from(file.text, 'utf8')),
      size: Buffer.byteLength(file.text), mediaType: file.mediaType ?? 'text/html'
    })),
    access: { visibility: 'public' },
    lifecycle: { expiresAt }
  };
  validateManifest(manifest);
  return manifest;
}

/** A filesystem environment with real stores and an injectable clock. */
async function env(t) {
  const root = await mkdtemp(join(tmpdir(), 'owa-gc-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  const blobs = new FilesystemBlobStore(root);
  const metadata = new FilesystemMetadataStore(root);
  const leases = new FilesystemLeaseStore(root, { now: clock });
  let siteCounter = 0;

  /** Write a blob and backdate it so grace-period behavior is deterministic. */
  async function writeBlob(text, { ageHours = 48 } = {}) {
    const bytes = Buffer.from(text, 'utf8');
    const digest = digestOf(bytes);
    await blobs.put(digest, bytes);
    const when = new Date(NOW.getTime() - ageHours * HOUR);
    await utimes(blobs.path(digest), when, when);
    return digest;
  }

  async function addRelease(slug, files, { active = true, expiresAt = null } = {}) {
    const manifest = manifestFor(files, { expiresAt });
    const id = `s_${createHash('sha256').update(slug).digest('hex').slice(0, 20)}`;
    const releaseId = `r_${createHash('sha256').update(`${slug}:${siteCounter++}`).digest('hex').slice(0, 20)}`;
    const existing = await metadata.getSite(slug);
    const site = existing ?? { id, slug, activeReleaseId: null, createdAt: NOW.toISOString() };
    if (active) site.activeReleaseId = releaseId;
    await metadata.saveSite(site);
    await metadata.saveRelease(site.id, {
      id: releaseId, artifactDigest: artifactDigest(manifest), createdAt: NOW.toISOString(), manifest
    });
    return { site, releaseId, manifest };
  }

  const run = options => collectGarbage({ blobs, metadata, leases, now: clock, ...options });
  return { root, blobs, metadata, leases, writeBlob, addRelease, run };
}

// ------------------------------------------------------ retention roots ---

test('1-5. every stored release is a root and its blobs always survive', async t => {
  const e = await env(t);
  // Active, inactive, a very old rollback target, and an already-expired
  // lifecycle release. None of these may ever become a candidate.
  const active = await e.writeBlob('active release body');
  const inactive = await e.writeBlob('inactive release body');
  const rollback = await e.writeBlob('ancient rollback body', { ageHours: 24 * 365 * 3 });
  const expired = await e.writeBlob('expired lifecycle body');
  const shared = await e.writeBlob('shared across two releases');

  await e.addRelease('alpha', [{ path: '/index.html', text: 'inactive release body' }, { path: '/s.html', text: 'shared across two releases' }], { active: false });
  await e.addRelease('alpha', [{ path: '/index.html', text: 'active release body' }, { path: '/s.html', text: 'shared across two releases' }], { active: true });
  await e.addRelease('beta', [{ path: '/index.html', text: 'ancient rollback body' }], { active: false });
  await e.addRelease('gamma', [{ path: '/index.html', text: 'expired lifecycle body' }], { active: true, expiresAt: '2020-01-01T00:00:00.000Z' });

  const report = await e.run({ apply: true });
  assert.equal(report.candidates, 0, 'no release-referenced blob may be a candidate');
  assert.equal(report.deleted, 0);
  assert.equal(report.releasesScanned, 4, 'all four releases are roots');
  // 5. six file references across four releases, but the digest shared by the
  // two alpha releases is marked once, so five unique digests are marked.
  assert.equal(report.releaseDigestsMarked, 5, 'shared content collapses to one mark');
  for (const digest of [active, inactive, rollback, expired, shared]) {
    assert.equal(await e.blobs.has(digest), true, `${digest} must survive`);
  }
});

test('release records, active pointers and manifests are never modified by GC', async t => {
  const e = await env(t);
  await e.writeBlob('kept');
  await e.writeBlob('orphan to delete');
  const { site, releaseId, manifest } = await e.addRelease('alpha', [{ path: '/index.html', text: 'kept' }]);

  const before = await e.metadata.getRelease(site.id, releaseId);
  const beforeSite = await e.metadata.getSite('alpha');
  const report = await e.run({ apply: true });
  assert.equal(report.deleted, 1, 'only the orphan goes');

  const after = await e.metadata.getRelease(site.id, releaseId);
  const afterSite = await e.metadata.getSite('alpha');
  assert.deepEqual(after, before, 'the release record is byte-for-byte untouched');
  assert.deepEqual(afterSite, beforeSite, 'the active pointer is untouched');
  assert.equal(canonicalJson(after.manifest), canonicalJson(manifest), 'canonical bytes unchanged');
  assert.equal(artifactDigest(after.manifest), before.artifactDigest, 'artifact digest unchanged');
  assert.ok(!JSON.stringify(after).includes('lease'), 'no lease/GC field enters a release record');
  assert.ok(!JSON.stringify(after.manifest).includes('lease'), 'no lease/GC field enters a manifest');
});

// -------------------------------------------------------- orphan basics ---

test('6-9. orphan lifecycle: candidate, dry-run keeps, apply deletes, young is spared', async t => {
  const e = await env(t);
  const orphan = await e.writeBlob('a true orphan', { ageHours: 48 });
  const young = await e.writeBlob('too young to collect', { ageHours: 1 });

  const dry = await e.run({});
  assert.equal(dry.mode, 'dry-run');
  assert.equal(dry.candidates, 1, '6. only the aged orphan is a candidate');
  assert.deepEqual(dry.candidateDigests, [orphan]);
  assert.equal(dry.youngSkipped, 1, '9. the young object is skipped');
  assert.equal(dry.deleted, 0);
  assert.equal(await e.blobs.has(orphan), true, '7. dry run deletes nothing');
  assert.equal(await e.blobs.has(young), true);
  assert.match(formatReport(dry), /Dry run: nothing was deleted/);

  const applied = await e.run({ apply: true });
  assert.equal(applied.mode, 'apply');
  assert.equal(applied.deleted, 1, '8. apply deletes the orphan');
  assert.equal(await e.blobs.has(orphan), false);
  assert.equal(await e.blobs.has(young), true, '9. the young object still survives apply');
});

test('the grace period is honored exactly at the boundary', async t => {
  const e = await env(t);
  const justInside = await e.writeBlob('older than grace', { ageHours: 25 });
  const justOutside = await e.writeBlob('younger than grace', { ageHours: 23 });
  const report = await e.run({ graceSeconds: DEFAULT_GRACE_SECONDS });
  assert.deepEqual(report.candidateDigests, [justInside]);
  assert.equal(report.youngSkipped, 1);
  assert.equal(justOutside.length > 0, true);
});

// -------------------------------------------------------------- leases ---

test('10-12. leases protect unreferenced blobs, expire, and never shorten', async t => {
  const e = await env(t);
  const leased = await e.writeBlob('protected by an in-flight publish');

  await e.leases.refresh([leased], { ttlSeconds: 3600 });
  const protectedRun = await e.run({ apply: true });
  assert.equal(protectedRun.leasedSkipped, 1, '10. an unexpired lease protects the orphan');
  assert.equal(protectedRun.deleted, 0);
  assert.equal(await e.blobs.has(leased), true);

  // 12. a shorter re-plan must not shorten existing protection.
  await e.leases.refresh([leased], { ttlSeconds: 60 });
  const stored = (await e.leases.list()).find(lease => lease.digest === leased);
  assert.equal(stored.expiresAt.getTime(), NOW.getTime() + 3600 * 1000, 'protection is never shortened');
  // A longer re-plan does extend it.
  await e.leases.refresh([leased], { ttlSeconds: 7200 });
  const extended = (await e.leases.list()).find(lease => lease.digest === leased);
  assert.equal(extended.expiresAt.getTime(), NOW.getTime() + 7200 * 1000, 'protection extends');

  // 11. once expired it protects nothing.
  const later = new Date(NOW.getTime() + 8000 * 1000);
  const afterExpiry = await collectGarbage({
    blobs: e.blobs, metadata: e.metadata, leases: e.leases, apply: true, now: () => later
  });
  assert.equal(afterExpiry.deleted, 1, '11. an expired lease does not protect forever');
  assert.equal(await e.blobs.has(leased), false);
});

test('13-15. plan leases every unique manifest digest, including already-present blobs', async t => {
  const e = await env(t);
  // One blob already exists (so the plan will report it reusable), one does not,
  // and two manifest paths share identical content.
  const present = await e.writeBlob('already in storage');
  const manifest = manifestFor([
    { path: '/index.html', text: 'already in storage' },
    { path: '/new.html', text: 'not yet uploaded' },
    { path: '/copy.html', text: 'not yet uploaded' }
  ]);

  const plan = await planManifest({
    manifest, blobs: e.blobs, leases: e.leases,
    uploadFactory: async digest => ({ digest, method: 'PUT', url: 'https://storage.invalid/x', expiresIn: 900 })
  });
  assert.equal(plan.reused, 1, 'the present blob is reported reusable');
  assert.equal(plan.uploads.length, 1, '15. duplicate content yields one upload');

  const leased = await e.leases.list();
  const digests = leased.map(lease => lease.digest).sort();
  const expected = [...new Set(manifest.files.map(file => file.digest))].sort();
  assert.deepEqual(digests, expected, '13/14. every unique digest is leased, present ones included');
  assert.equal(leased.length, 2, '15. one lease per unique digest, not per file path');
  assert.ok(digests.includes(present), '14. the already-present blob is leased too');

  // The whole point: the reusable blob cannot be collected between plan and commit.
  const report = await e.run({ apply: true });
  assert.equal(report.deleted, 0, 'nothing in an in-flight publish is collectible');
  assert.equal(report.leasedSkipped, 1, 'the present blob was protected by its lease');
});

test('the default publish lease is far longer than an upload grant', () => {
  assert.equal(PUBLISH_LEASE_TTL_SECONDS, 86_400);
  assert.ok(PUBLISH_LEASE_TTL_SECONDS > 900 * 10, 'must outlive the 900s direct-upload grant');
});

test('the local publishDirectory path takes the same lease protection', async t => {
  const e = await env(t);
  const directory = join(e.root, 'site');
  await mkdir(directory, { recursive: true });
  await writeFile(join(directory, 'index.html'), '<h1>local publish</h1>');

  await publishDirectory({ directory, slug: 'local', blobs: e.blobs, metadata: e.metadata, leases: e.leases });
  const leased = await e.leases.list();
  assert.equal(leased.length, 1, 'the trusted local publisher is not left racing GC unprotected');
  assert.equal(leased[0].digest, digestOf(Buffer.from('<h1>local publish</h1>', 'utf8')));
});

// ------------------------------------------------------------ race model ---

test('16-17. protection created after the first scan is caught by the final re-mark', async t => {
  await t.test('16. a new lease prevents deletion', async t2 => {
    const e = await env(t2);
    const orphan = await e.writeBlob('orphan that gets leased mid-run');
    const report = await e.run({
      apply: true,
      // Deterministic hook: runs after candidates are computed, before any delete.
      beforeSweep: async () => { await e.leases.refresh([orphan], { ttlSeconds: 3600 }); }
    });
    assert.equal(report.candidates, 1, 'it WAS a candidate at first scan');
    assert.equal(report.raceSkipped, 1, 'the re-check caught the new lease');
    assert.equal(report.deleted, 0);
    assert.equal(await e.blobs.has(orphan), true, 'the blob survives');
  });

  await t.test('17. a new release reference prevents deletion', async t2 => {
    const e = await env(t2);
    const orphan = await e.writeBlob('orphan that gets committed mid-run');
    const report = await e.run({
      apply: true,
      beforeSweep: async () => {
        await e.addRelease('late', [{ path: '/index.html', text: 'orphan that gets committed mid-run' }]);
      }
    });
    assert.equal(report.candidates, 1);
    assert.equal(report.raceSkipped, 1, 'the re-check caught the new release');
    assert.equal(report.deleted, 0);
    assert.equal(await e.blobs.has(orphan), true);
  });
});

// ------------------------------------------------------- fail-closed ----

test('18-21. malformed metadata or lease state aborts before any delete', async t => {
  const cases = [
    ['18. malformed site record', async e => {
      await writeFile(join(e.root, 'sites', 's_'.padEnd(22, 'a'), 'site.json'), '{ not json', 'utf8').catch(async () => {
        await mkdir(join(e.root, 'sites', `s_${'a'.repeat(20)}`), { recursive: true });
        await writeFile(join(e.root, 'sites', `s_${'a'.repeat(20)}`, 'site.json'), '{ not json', 'utf8');
      });
    }],
    ['18b. unexpected directory under sites/', async e => {
      await mkdir(join(e.root, 'sites', 'not-a-site-id'), { recursive: true });
    }],
    ['19. malformed release record', async e => {
      const { site } = await e.addRelease('alpha', [{ path: '/index.html', text: 'kept' }]);
      await writeFile(join(e.root, 'sites', site.id, 'releases', `r_${'b'.repeat(20)}.json`), '{ truncated', 'utf8');
    }],
    ['20. stored release whose manifest no longer validates', async e => {
      const { site } = await e.addRelease('alpha', [{ path: '/index.html', text: 'kept' }]);
      const bad = { id: `r_${'c'.repeat(20)}`, artifactDigest: `sha256:${'0'.repeat(64)}`,
        createdAt: NOW.toISOString(), manifest: { specVersion: 'owa.dev/v1', files: 'not an array' } };
      await writeFile(join(e.root, 'sites', site.id, 'releases', `${bad.id}.json`), JSON.stringify(bad), 'utf8');
    }],
    ['20b. release whose artifactDigest disagrees with its manifest', async e => {
      const { site } = await e.addRelease('alpha', [{ path: '/index.html', text: 'kept' }]);
      const manifest = manifestFor([{ path: '/index.html', text: 'tampered' }]);
      const bad = { id: `r_${'d'.repeat(20)}`, artifactDigest: `sha256:${'1'.repeat(64)}`,
        createdAt: NOW.toISOString(), manifest };
      await writeFile(join(e.root, 'sites', site.id, 'releases', `${bad.id}.json`), JSON.stringify(bad), 'utf8');
    }],
    ['21. malformed lease record', async e => {
      await mkdir(join(e.root, 'gc-leases', 'sha256'), { recursive: true });
      await writeFile(join(e.root, 'gc-leases', 'sha256', `${'e'.repeat(64)}.json`), '{ bad', 'utf8');
    }],
    ['21b. lease record whose digest does not match its filename', async e => {
      await mkdir(join(e.root, 'gc-leases', 'sha256'), { recursive: true });
      await writeFile(join(e.root, 'gc-leases', 'sha256', `${'f'.repeat(64)}.json`),
        JSON.stringify({ digest: `sha256:${'0'.repeat(64)}`, expiresAt: NOW.toISOString() }), 'utf8');
    }]
  ];

  for (const [name, corrupt] of cases) {
    await t.test(name, async t2 => {
      const e = await env(t2);
      const orphan = await e.writeBlob('an orphan that must NOT be deleted');
      let deleted = 0;
      const guarded = { ...e.blobs, listBlobs: () => e.blobs.listBlobs(), path: d => e.blobs.path(d),
        has: d => e.blobs.has(d), delete: async d => { deleted++; return e.blobs.delete(d); } };
      await corrupt(e);
      await assert.rejects(
        () => collectGarbage({ blobs: guarded, metadata: e.metadata, leases: e.leases, apply: true, now: clock }),
        error => error instanceof GcError && typeof error.code === 'string');
      assert.equal(deleted, 0, 'no delete may be attempted when metadata cannot be trusted');
      assert.equal(await e.blobs.has(orphan), true, 'the orphan survives a failed run');
    });
  }
});

test('22-24. storage failures abort or stay idempotent, and never leak a provider body', async t => {
  const e = await env(t);
  const orphan = await e.writeBlob('orphan');

  await t.test('22. a listing failure aborts before any delete', async () => {
    let deleted = 0;
    const failing = {
      listBlobs: async () => { throw Object.assign(new Error('provider said <Error>secret-bucket</Error>'), { code: 'OWA_GC_LIST_FAILED' }); },
      delete: async () => { deleted++; }
    };
    await assert.rejects(
      () => collectGarbage({ blobs: failing, metadata: e.metadata, leases: e.leases, apply: true, now: clock }),
      error => error instanceof GcError && error.code === 'OWA_GC_LIST_FAILED'
        && !error.message.includes('secret-bucket'));
    assert.equal(deleted, 0);
  });

  await t.test('23. a delete failure is redacted to a fixed code', async () => {
    const failing = {
      listBlobs: () => e.blobs.listBlobs(),
      delete: async () => { throw new Error('AccessDenied: key=owa/blobs/... X-Amz-Signature=deadbeef'); }
    };
    await assert.rejects(
      () => collectGarbage({ blobs: failing, metadata: e.metadata, leases: e.leases, apply: true, now: clock }),
      error => error instanceof GcError && error.code === 'OWA_GC_DELETE_FAILED'
        && !/X-Amz-Signature|AccessDenied/.test(error.message));
  });

  await t.test('24. deleting an already-missing blob is idempotent', async () => {
    await e.blobs.delete(orphan);
    await e.blobs.delete(orphan); // second delete must not throw
    assert.equal(await e.blobs.has(orphan), false);
  });
});

// ------------------------------------------------- filesystem enumeration ---

test('25-27. filesystem enumeration stays inside the blob root and ignores strangers', async t => {
  const e = await env(t);
  const real = await e.writeBlob('a genuine blob');

  // Unrelated files in and around the blob namespace.
  const outside = join(e.root, 'outside-secret.txt');
  await writeFile(outside, 'must never be touched', 'utf8');
  await writeFile(join(e.root, 'blobs', 'sha256', 'not-a-digest.txt'), 'stray', 'utf8');
  await writeFile(join(e.root, 'blobs', 'sha256', `${'z'.repeat(64)}`), 'bad hex', 'utf8');
  await mkdir(join(e.root, 'blobs', 'sha512'), { recursive: true });
  await writeFile(join(e.root, 'blobs', 'sha512', `${'a'.repeat(64)}`), 'wrong algorithm', 'utf8');
  await mkdir(join(e.root, 'blobs', 'sha256', `${'b'.repeat(64)}.d`), { recursive: true });

  // 26. a symlink named like a valid digest, pointing outside the root.
  const escape = join(e.root, 'blobs', 'sha256', 'c'.repeat(64));
  await symlink(outside, escape);

  const listed = await e.blobs.listBlobs();
  assert.deepEqual(listed.map(entry => entry.digest), [real], '25/26/27. only the genuine blob is enumerated');

  const report = await e.run({ apply: true, graceSeconds: 0 });
  assert.equal(report.deleted, 1, 'only the real orphan blob is deleted');
  assert.equal(existsSync(outside), true, '27. an unrelated file outside the root is untouched');
  assert.equal(existsSync(escape), true, '26. the symlink itself is not followed or deleted');
  assert.equal(existsSync(join(e.root, 'blobs', 'sha256', 'not-a-digest.txt')), true, '27. strays are left alone');
  assert.equal(existsSync(join(e.root, 'blobs', 'sha512', `${'a'.repeat(64)}`)), true, 'another algorithm is out of scope');

  // The escape target's content is intact.
  assert.equal((await stat(outside)).size, Buffer.byteLength('must never be touched'));
});

test('a digest outside the blob root cannot be deleted through the store', async t => {
  const e = await env(t);
  for (const bad of ['sha256:../../etc/passwd', 'sha256:' + 'g'.repeat(64), 'not-a-digest', '', 'sha512:' + 'a'.repeat(64)]) {
    await assert.rejects(() => e.blobs.delete(bad), error => error.code === 'OWA_GC_INVALID_DIGEST');
  }
});

// -------------------------------------------------- publish compatibility ---

test('36-40. plan/upload/commit, dedup, digests, release shape and rollback are unchanged', async t => {
  const e = await env(t);
  const directory = join(e.root, 'site');
  await mkdir(join(directory, 'assets'), { recursive: true });
  await writeFile(join(directory, 'index.html'), '<h1>v1</h1>');
  await writeFile(join(directory, 'assets', 'a.js'), 'console.log(1);\n');
  await writeFile(join(directory, 'assets', 'b.js'), 'console.log(1);\n'); // duplicate content

  const first = await publishDirectory({ directory, slug: 'demo', blobs: e.blobs, metadata: e.metadata, leases: e.leases });
  assert.equal(first.uploaded, 2, '36. duplicate content still uploads one blob');
  assert.equal(first.reused, 0);

  const second = await publishDirectory({ directory, slug: 'demo', blobs: e.blobs, metadata: e.metadata, leases: e.leases });
  assert.equal(second.uploaded, 0, '37. identical re-publish uploads zero blobs');
  assert.equal(second.reused, 2);
  assert.equal(second.release.artifactDigest, first.release.artifactDigest, '38. artifact digest unchanged');

  // 39. release record shape is exactly what it was before GC existed.
  assert.deepEqual(Object.keys(second.release).sort(), ['artifactDigest', 'createdAt', 'id', 'manifest']);
  assert.ok(!Object.hasOwn(second.release, 'leases'), 'no GC field on a release record');

  // 40. rollback to the first release still works and is untouched by GC.
  const site = await e.metadata.getSite('demo');
  const releases = await e.metadata.listAllReleases(site.id);
  assert.equal(releases.length, 2);
  await e.run({ apply: true, graceSeconds: 0 });
  const after = await e.metadata.listAllReleases(site.id);
  assert.deepEqual(after.map(r => r.id).sort(), releases.map(r => r.id).sort(), 'GC deleted no release');
  for (const release of after) {
    assert.equal(await e.blobs.has(release.manifest.files[0].digest), true, 'rollback target blobs survive');
  }
});

test('commit does not need to clean up leases: release marking already wins', async t => {
  const e = await env(t);
  const manifest = manifestFor([{ path: '/index.html', text: 'committed content' }]);
  await e.blobs.put(manifest.files[0].digest, Buffer.from('committed content', 'utf8'));
  await e.leases.refresh([manifest.files[0].digest], { ttlSeconds: 60 });
  await commitManifest({
    slug: 'demo', manifest, expectedArtifactDigest: artifactDigest(manifest),
    blobs: e.blobs, metadata: e.metadata
  });
  // Long after the lease expires, the release keeps the blob alive.
  const later = new Date(NOW.getTime() + 10 * 24 * HOUR);
  const report = await collectGarbage({ blobs: e.blobs, metadata: e.metadata, leases: e.leases, apply: true, now: () => later });
  assert.equal(report.deleted, 0);
  assert.equal(await e.blobs.has(manifest.files[0].digest), true);
});

test('expired lease records are pruned only on apply, never during a dry run', async t => {
  const e = await env(t);
  await e.leases.refresh([digestOf(Buffer.from('x'))], { ttlSeconds: 60 });
  const later = new Date(NOW.getTime() + 3600 * 1000);

  const dry = await collectGarbage({ blobs: e.blobs, metadata: e.metadata, leases: e.leases, now: () => later, pruneExpiredLeases: true });
  assert.equal(dry.expiredLeasesCleaned, 0, 'a dry run performs no destructive mutation at all');
  assert.equal((await e.leases.list()).length, 1);

  const applied = await collectGarbage({ blobs: e.blobs, metadata: e.metadata, leases: e.leases, apply: true, now: () => later, pruneExpiredLeases: true });
  assert.equal(applied.expiredLeasesCleaned, 1);
  assert.equal((await e.leases.list()).length, 0);
});

test('the report never contains a credential, URL or provider body', async t => {
  const e = await env(t);
  await e.writeBlob('orphan');
  const report = await e.run({});
  const text = `${JSON.stringify(report)}\n${formatReport(report)}`;
  assert.ok(!/Bearer |owa1\.|X-Amz-|Signature=|AKIA|secretAccessKey|https?:\/\//.test(text),
    'operator output carries only counts, bytes and digests');
});

test('GC refuses to run against a store without operational support', async t => {
  const e = await env(t);
  await assert.rejects(
    () => collectGarbage({ blobs: { has: async () => false }, metadata: e.metadata, now: clock }),
    error => error instanceof GcError && error.code === 'OWA_GC_INVALID_CONFIG');
  await assert.rejects(
    () => collectGarbage({ blobs: e.blobs, metadata: e.metadata, graceSeconds: -1, now: clock }),
    error => error instanceof GcError && error.code === 'OWA_GC_INVALID_CONFIG');
});

// ------------------------------------------------------------ S3 / R2 ----

/** An S3BlobStore whose HTTP layer is replaced by a scripted responder. */
function s3Fixture({ pages = [], onRequest = () => {}, prefix = 'owa' } = {}) {
  const requests = [];
  const store = new S3BlobStore({
    endpoint: 'https://acct.r2.cloudflarestorage.com', bucket: 'bucket',
    region: 'auto', accessKeyId: 'AKIDEXAMPLE', secretAccessKey: 'wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY',
    prefix, now: () => NOW
  });
  const realFetch = globalThis.fetch;
  let page = 0;
  globalThis.fetch = async (url, options) => {
    // `raw` is the exact string handed to fetch. Assertions about encoding MUST
    // use it: URL.searchParams decodes "+" and "%20" to the same value and would
    // hide a signed-vs-transmitted mismatch.
    const record = { raw: String(url), url: new URL(String(url)), method: options.method, headers: options.headers };
    requests.push(record);
    onRequest(record);
    if (options.method === 'GET') {
      const body = pages[Math.min(page++, pages.length - 1)] ?? '<ListBucketResult><IsTruncated>false</IsTruncated></ListBucketResult>';
      return { ok: true, status: 200, text: async () => body, arrayBuffer: async () => new ArrayBuffer(0) };
    }
    return { ok: true, status: 204, text: async () => '', arrayBuffer: async () => new ArrayBuffer(0) };
  };
  return { store, requests, restore: () => { globalThis.fetch = realFetch; } };
}

const contents = (key, { size = 10, modified = '2026-05-01T00:00:00.000Z' } = {}) =>
  `<Contents><Key>${key}</Key><Size>${size}</Size><LastModified>${modified}</LastModified></Contents>`;

test('28-30. S3 listing is prefix-confined and ignores malformed or neighbouring keys', async t => {
  const good = 'a'.repeat(64);
  const fixture = s3Fixture({
    pages: [`<ListBucketResult>
      ${contents(`owa/blobs/sha256/${good}`)}
      ${contents('owa/blobs/sha256/not-hex')}
      ${contents(`owa/blobs/sha256/${good}/nested`)}
      ${contents(`owa/blobs/sha512/${good}`)}
      ${contents(`owa-other/blobs/sha256/${'b'.repeat(64)}`)}
      ${contents('unrelated/customer-data.csv')}
      ${contents(`owa/blobs/sha256/${'C'.repeat(64)}`)}
      <IsTruncated>false</IsTruncated></ListBucketResult>`]
  });
  t.after(fixture.restore);

  const listed = await fixture.store.listBlobs();
  assert.deepEqual(listed.map(entry => entry.digest), [`sha256:${good}`],
    '28/29/30. only exact OWA blob keys under the configured prefix are eligible');

  const query = fixture.requests[0].url.searchParams;
  assert.equal(query.get('prefix'), 'owa/blobs/sha256/', '28. listing is scoped to the OWA blob prefix');
  assert.equal(query.get('list-type'), '2');
});

// Fixed vector: botocore S3SigV4Auth signing the exact page-2 request below
// (same credentials, region, fixed NOW, decoded token) produced this header.
// It is pinned here so the signature is checked against an independent
// implementation on every run, not only against our own signer.
const PAGE2_TOKEN = '1/abc+def=ghi & jkl';
const PAGE2_RAW_QUERY = 'continuation-token=1%2Fabc%2Bdef%3Dghi%20%26%20jkl&list-type=2&max-keys=1000&prefix=owa%2Fblobs%2Fsha256%2F';
const PAGE2_AUTHORIZATION = 'AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20260601/auto/s3/aws4_request, SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature=8493cebfc4643d8f8dc656316524be5c42b657081f8aba4c1be497689af68015';

test('31-32. ListObjectsV2 pagination decodes the XML token and transmits exactly what it signed', async t => {
  const first = 'a'.repeat(64), second = 'b'.repeat(64);
  // The token contains every character that a form encoder and an RFC 3986
  // encoder disagree on (space, +), characters that must be escaped (=, /), and
  // an ampersand, which the provider MUST XML-escape in the response body.
  const escaped = PAGE2_TOKEN.replace(/&/g, '&amp;');
  assert.notEqual(escaped, PAGE2_TOKEN, 'the fixture really exercises XML entity decoding');
  const fixture = s3Fixture({
    pages: [
      `<ListBucketResult>${contents(`owa/blobs/sha256/${first}`)}<IsTruncated>true</IsTruncated><NextContinuationToken>${escaped}</NextContinuationToken></ListBucketResult>`,
      `<ListBucketResult>${contents(`owa/blobs/sha256/${second}`)}<IsTruncated>false</IsTruncated></ListBucketResult>`
    ]
  });
  t.after(fixture.restore);

  const listed = await fixture.store.listBlobs();
  assert.deepEqual(listed.map(entry => entry.digest).sort(), [`sha256:${first}`, `sha256:${second}`].sort(),
    '31. both pages are returned');
  assert.equal(fixture.requests.length, 2, 'exactly two list calls');
  assert.equal(fixture.requests[0].url.searchParams.get('continuation-token'), null);

  const page2 = fixture.requests[1];
  // The decoded, ORIGINAL opaque token is what the logical request carries.
  assert.equal(page2.url.searchParams.get('continuation-token'), PAGE2_TOKEN,
    '32. &amp; was decoded back to & before the token was reused');

  // RAW bytes on the wire. This is the assertion that catches a signed-"%20",
  // transmitted-"+" mismatch, which searchParams.get() above cannot see.
  const rawQuery = page2.raw.slice(page2.raw.indexOf('?') + 1);
  assert.equal(rawQuery, PAGE2_RAW_QUERY, 'the wire query is the exact RFC 3986 canonical string');
  assert.ok(rawQuery.includes('%20'), 'space is %20');
  assert.ok(!rawQuery.includes('+'), 'space is never "+" and + itself is escaped');
  assert.ok(rawQuery.includes('%2B'), '+ is %2B');
  assert.ok(rawQuery.includes('%3D'), '= is %3D');
  assert.ok(rawQuery.includes('%2F'), '/ is %2F');
  assert.ok(rawQuery.includes('%26'), '& is %26 (and not the literal &amp;)');
  assert.ok(!rawQuery.includes('amp'), 'no XML entity text leaks onto the wire');

  // Independent verification: the header botocore produced for this exact request.
  assert.equal(page2.headers.authorization, PAGE2_AUTHORIZATION,
    'SigV4 over the transmitted query matches an independent implementation');
});

test('decodeXmlText decodes the standard entities and numeric references, and fails closed otherwise', () => {
  assert.equal(decodeXmlText('a&amp;b&lt;c&gt;d&quot;e&apos;f'), 'a&b<c>d"e\'f');
  assert.equal(decodeXmlText('&#65;&#x42;&#x1F600;'), 'AB\u{1F600}');
  assert.equal(decodeXmlText('plain text, no references'), 'plain text, no references');
  assert.equal(decodeXmlText(''), '');
  // Every one of these is malformed character data and must throw, never guess.
  for (const bad of ['a&b', 'a&amp', '&bogus;', '&;', '&#;', '&#x;', '&#xZZ;', '&#0;', '&#xD800;', '&#x110000;', 'a<b', '&amp;&']) {
    assert.throws(() => decodeXmlText(bad), error => error.code === 'OWA_GC_LIST_FAILED', `must reject ${JSON.stringify(bad)}`);
  }
});

test('a malformed XML token fails the listing closed: no wrong request, no loop, no delete', async t => {
  const fixture = s3Fixture({
    pages: [
      `<ListBucketResult>${contents(`owa/blobs/sha256/${'a'.repeat(64)}`)}<IsTruncated>true</IsTruncated><NextContinuationToken>broken &amp token</NextContinuationToken></ListBucketResult>`,
      `<ListBucketResult><IsTruncated>false</IsTruncated></ListBucketResult>`
    ]
  });
  t.after(fixture.restore);
  await assert.rejects(() => fixture.store.listBlobs(), error => error.code === 'OWA_GC_LIST_FAILED');
  assert.equal(fixture.requests.length, 1, 'no second request is issued with a guessed token');
  assert.equal(fixture.requests.filter(request => request.method === 'DELETE').length, 0, 'nothing is deleted');

  // Through the collector: an unparseable listing must abort before any delete,
  // even in apply mode, rather than sweep from an incomplete candidate set.
  // A FRESH fixture, so the collector meets the malformed page itself.
  fixture.restore();
  const again = s3Fixture({
    pages: [`<ListBucketResult>${contents(`owa/blobs/sha256/${'a'.repeat(64)}`)}<IsTruncated>true</IsTruncated><NextContinuationToken>broken &amp token</NextContinuationToken></ListBucketResult>`]
  });
  t.after(again.restore);
  const root = await mkdtemp(join(tmpdir(), 'owa-gc-xml-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  const metadata = new FilesystemMetadataStore(root);
  await assert.rejects(
    () => collectGarbage({ blobs: again.store, metadata, apply: true, graceSeconds: 0, now: () => NOW }),
    error => error instanceof GcError && error.code === 'OWA_GC_LIST_FAILED');
  assert.equal(again.requests.length, 1, 'the collector issued one list call and stopped');
  assert.equal(again.requests.filter(request => request.method === 'DELETE').length, 0, 'still nothing deleted');
});

test('an XML-escaped <Key> is decoded before prefix validation, so an & in the prefix still matches', async t => {
  const hex = 'c'.repeat(64);
  const fixture = s3Fixture({
    prefix: 'owa&gc',
    pages: [`<ListBucketResult>${contents(`owa&amp;gc/blobs/sha256/${hex}`)}<IsTruncated>false</IsTruncated></ListBucketResult>`]
  });
  t.after(fixture.restore);
  const listed = await fixture.store.listBlobs();
  assert.deepEqual(listed.map(entry => entry.digest), [`sha256:${hex}`], 'the escaped key matched its real prefix');
  // The prefix query parameter itself is RFC 3986 encoded on the wire.
  const rawQuery = fixture.requests[0].raw.slice(fixture.requests[0].raw.indexOf('?') + 1);
  assert.ok(rawQuery.includes('prefix=owa%26gc%2Fblobs%2Fsha256%2F'), 'the & in the prefix is %26 on the wire');
});

test('a truncated listing with no continuation token fails closed', async t => {
  const fixture = s3Fixture({
    pages: [`<ListBucketResult>${contents(`owa/blobs/sha256/${'a'.repeat(64)}`)}<IsTruncated>true</IsTruncated></ListBucketResult>`]
  });
  t.after(fixture.restore);
  await assert.rejects(() => fixture.store.listBlobs(), error => error.code === 'OWA_GC_LIST_FAILED');
});

test('33-34. S3 DELETE is signed with storage credentials and carries no OWA bearer', async t => {
  const fixture = s3Fixture({});
  t.after(fixture.restore);
  const digest = `sha256:${'a'.repeat(64)}`;
  await fixture.store.delete(digest);

  const request = fixture.requests.at(-1);
  assert.equal(request.method, 'DELETE');
  assert.equal(request.url.pathname, `/bucket/owa/blobs/sha256/${'a'.repeat(64)}`, '33. exact key only');
  assert.equal(request.url.search, '', 'no query material on a delete');
  const auth = request.headers.authorization;
  assert.ok(auth.startsWith('AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/'), '33. storage SigV4 only');
  assert.ok(!/^Bearer /i.test(auth) && !/owa1\./.test(JSON.stringify(request.headers)),
    '34. no OWA bearer is ever sent to storage');
});

test('S3 delete is idempotent for a missing key and redacts provider bodies', async t => {
  const realFetch = globalThis.fetch;
  t.after(() => { globalThis.fetch = realFetch; });
  const store = new S3BlobStore({
    endpoint: 'https://acct.r2.cloudflarestorage.com', bucket: 'bucket', region: 'auto',
    accessKeyId: 'AKIDEXAMPLE', secretAccessKey: 'wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY', now: () => NOW
  });
  globalThis.fetch = async () => ({ ok: false, status: 404, text: async () => '', arrayBuffer: async () => new ArrayBuffer(0) });
  await store.delete(`sha256:${'a'.repeat(64)}`); // 404 must not throw

  globalThis.fetch = async () => ({ ok: false, status: 403, text: async () => '<Error><Code>AccessDenied</Code><Key>secret</Key></Error>', arrayBuffer: async () => new ArrayBuffer(0) });
  await assert.rejects(() => store.delete(`sha256:${'a'.repeat(64)}`),
    error => error.code === 'OWA_GC_DELETE_FAILED' && !/AccessDenied|secret/.test(error.message));
});

test('35. a session token is signed for list and delete when configured', async t => {
  const realFetch = globalThis.fetch;
  t.after(() => { globalThis.fetch = realFetch; });
  const seen = [];
  globalThis.fetch = async (url, options) => {
    seen.push(options.headers);
    return { ok: true, status: 200, text: async () => '<ListBucketResult><IsTruncated>false</IsTruncated></ListBucketResult>', arrayBuffer: async () => new ArrayBuffer(0) };
  };
  const store = new S3BlobStore({
    endpoint: 'https://acct.r2.cloudflarestorage.com', bucket: 'bucket', region: 'auto',
    accessKeyId: 'AKIDEXAMPLE', secretAccessKey: 'wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY',
    sessionToken: 'session-token-value', now: () => NOW
  });
  await store.listBlobs();
  await store.delete(`sha256:${'a'.repeat(64)}`);
  for (const headers of seen) {
    assert.equal(headers['x-amz-security-token'], 'session-token-value');
    assert.ok(headers.authorization.includes('x-amz-security-token'), 'the token is part of SignedHeaders');
  }
});

test('S3 GC operations leave existing publish presigning untouched', async t => {
  const store = new S3BlobStore({
    endpoint: 'https://acct.r2.cloudflarestorage.com', bucket: 'bucket', region: 'auto',
    accessKeyId: 'AKIDEXAMPLE', secretAccessKey: 'wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY', now: () => NOW
  });
  // Fixed expectation: the publish grant shape must not drift because GC now
  // shares the signer. Query names, order and the signed-headers set are pinned.
  const url = new URL(await store.presign('PUT', store.key(`sha256:${'a'.repeat(64)}`), { expires: 900 }));
  assert.deepEqual([...url.searchParams.keys()].sort(),
    ['X-Amz-Algorithm', 'X-Amz-Credential', 'X-Amz-Date', 'X-Amz-Expires', 'X-Amz-SignedHeaders', 'X-Amz-Signature'].sort());
  assert.equal(url.searchParams.get('X-Amz-SignedHeaders'), 'host');
  assert.equal(url.searchParams.get('X-Amz-Expires'), '900');
  assert.match(url.searchParams.get('X-Amz-Signature'), /^[0-9a-f]{64}$/);
});

// ------------------------------------------- ancestor symlink escapes ----

/**
 * Regression for GC following a symlinked ANCESTOR directory out of the data
 * root. lstat() on the final digest entry was never enough: readdir()/rm()
 * follow a symlink at `<root>/blobs`, and lexical isInside() still sees a path
 * spelled under <root> while the filesystem resolved elsewhere. Every case
 * below plants real-looking content OUTSIDE the root and proves it is never
 * enumerated, never trusted, and never modified — byte for byte.
 */
async function externalTree(t) {
  const outside = await mkdtemp(join(tmpdir(), 'owa-gc-outside-'));
  t.after(() => rm(outside, { recursive: true, force: true }));
  return outside;
}
const bytesAt = async path => (await readFile(path)).toString('utf8');

test('blobs-root symlink: GC fails closed and never touches the external tree', async t => {
  const e = await env(t);
  const outside = await externalTree(t);
  const hex = 'a'.repeat(64);
  await mkdir(join(outside, 'sha256'), { recursive: true });
  const external = join(outside, 'sha256', hex);
  await writeFile(external, 'PRECIOUS EXTERNAL DATA', 'utf8');
  // <root>/blobs -> <outside>. Nothing else exists under the root.
  await symlink(outside, join(e.root, 'blobs'));

  await assert.rejects(() => e.blobs.listBlobs(), error => error.code === 'OWA_GC_LIST_FAILED',
    'a symlinked blob root is not enumerable');

  let deletes = 0;
  const guarded = Object.create(e.blobs);
  guarded.delete = async digest => { deletes++; return e.blobs.delete(digest); };
  await assert.rejects(
    () => collectGarbage({ blobs: guarded, metadata: e.metadata, leases: e.leases, apply: true, graceSeconds: 0, now: clock }),
    error => error instanceof GcError && error.code === 'OWA_GC_LIST_FAILED');
  assert.equal(deletes, 0, 'apply aborted before any delete call');

  // A direct delete of the "digest" the external file spells must also refuse.
  await assert.rejects(() => e.blobs.delete(`sha256:${hex}`), error => error.code === 'OWA_GC_DELETE_FAILED');

  assert.equal(existsSync(external), true, 'the external file still exists');
  assert.equal(await bytesAt(external), 'PRECIOUS EXTERNAL DATA', 'the external bytes are unchanged');
  assert.equal((await readdir(join(outside, 'sha256'))).length, 1, 'nothing was added or removed outside');
});

test('blobs/sha256 symlink: the namespace directory itself is never followed', async t => {
  const e = await env(t);
  const outside = await externalTree(t);
  const hex = 'b'.repeat(64);
  const external = join(outside, hex);
  await writeFile(external, 'ALSO PRECIOUS', 'utf8');
  await mkdir(join(e.root, 'blobs'), { recursive: true }); // real blobs dir …
  await symlink(outside, join(e.root, 'blobs', 'sha256')); // … but sha256 is a link out

  await assert.rejects(() => e.blobs.listBlobs(), error => error.code === 'OWA_GC_LIST_FAILED');
  await assert.rejects(() => e.blobs.delete(`sha256:${hex}`), error => error.code === 'OWA_GC_DELETE_FAILED');
  assert.equal(await bytesAt(external), 'ALSO PRECIOUS', 'external bytes unchanged');
});

test('lease-directory symlink: --prune-expired-leases cannot rm an external JSON', async t => {
  for (const shape of ['gc-leases', 'gc-leases/sha256']) {
    await t.test(`${shape} -> external`, async t2 => {
      const e = await env(t2);
      const outside = await externalTree(t2);
      // A valid-looking, already-EXPIRED lease record living outside the root.
      const hex = 'c'.repeat(64);
      const leaseDir = shape === 'gc-leases' ? join(outside, 'sha256') : outside;
      await mkdir(leaseDir, { recursive: true });
      const external = join(leaseDir, `${hex}.json`);
      const record = JSON.stringify({ digest: `sha256:${hex}`, expiresAt: '2000-01-01T00:00:00.000Z', updatedAt: '2000-01-01T00:00:00.000Z' });
      await writeFile(external, record, 'utf8');
      if (shape === 'gc-leases') {
        await symlink(outside, join(e.root, 'gc-leases'));
      } else {
        await mkdir(join(e.root, 'gc-leases'), { recursive: true });
        await symlink(outside, join(e.root, 'gc-leases', 'sha256'));
      }

      await assert.rejects(() => e.leases.list(), error => error.code === 'OWA_GC_LEASE_UNREADABLE',
        'a symlinked lease namespace is not readable lease state');
      await assert.rejects(() => e.leases.pruneExpired(), error => /OWA_GC_LEASE_/.test(error.code));
      await assert.rejects(
        () => collectGarbage({ blobs: e.blobs, metadata: e.metadata, leases: e.leases, apply: true, graceSeconds: 0, pruneExpiredLeases: true, now: clock }),
        error => error instanceof GcError, 'apply with pruning aborts');

      assert.equal(existsSync(external), true, 'the external lease-looking file still exists');
      assert.equal(await bytesAt(external), record, 'its bytes are unchanged');
      // Writing a lease must not go through the link either.
      await assert.rejects(() => e.leases.refresh([`sha256:${'d'.repeat(64)}`], { ttlSeconds: 60 }),
        error => error.code === 'OWA_GC_LEASE_UNREADABLE');
      assert.equal((await readdir(leaseDir)).length, 1, 'nothing was written outside the root');
    });
  }
});

test('release-directory symlink: external release JSON is never a trusted root and apply aborts', async t => {
  const e = await env(t);
  const outside = await externalTree(t);
  // A real site under the root, then its releases directory replaced by a link
  // to an external tree holding a perfectly plausible release record.
  const orphan = await e.writeBlob('orphan that must survive an aborted run');
  const { site } = await e.addRelease('alpha', [{ path: '/index.html', text: 'real release' }]);
  const releasesDir = join(e.root, 'sites', site.id, 'releases');
  await rm(releasesDir, { recursive: true, force: true });
  const plausible = manifestFor([{ path: '/index.html', text: 'external plausible release' }]);
  const externalRelease = join(outside, `r_${'e'.repeat(20)}.json`);
  await writeFile(externalRelease, JSON.stringify({
    id: `r_${'e'.repeat(20)}`, artifactDigest: artifactDigest(plausible), createdAt: NOW.toISOString(), manifest: plausible
  }), 'utf8');
  await symlink(outside, releasesDir);

  await assert.rejects(() => e.metadata.listAllReleases(site.id), error => error.code === 'OWA_GC_METADATA_MALFORMED',
    'a symlinked releases directory is malformed metadata');

  let deletes = 0;
  const guarded = Object.create(e.blobs);
  guarded.delete = async digest => { deletes++; return e.blobs.delete(digest); };
  await assert.rejects(
    () => collectGarbage({ blobs: guarded, metadata: e.metadata, leases: e.leases, apply: true, graceSeconds: 0, now: clock }),
    error => error instanceof GcError && error.code === 'OWA_GC_METADATA_MALFORMED');
  assert.equal(deletes, 0, 'zero blob deletes were attempted');
  assert.equal(await e.blobs.has(orphan), true, 'even a true orphan survives an aborted run');
  assert.equal(existsSync(externalRelease), true, 'the external release file is untouched');
});

test('sites-root symlink is rejected the same way', async t => {
  const e = await env(t);
  const outside = await externalTree(t);
  await symlink(outside, join(e.root, 'sites'));
  await assert.rejects(() => e.metadata.listSites(), error => error.code === 'OWA_GC_METADATA_MALFORMED');
});

test('ordinary real directories still enumerate and delete normally after the guard', async t => {
  const e = await env(t);
  const orphan = await e.writeBlob('ordinary orphan');
  const kept = await e.writeBlob('ordinary kept');
  await e.addRelease('alpha', [{ path: '/index.html', text: 'ordinary kept' }]);
  await e.leases.refresh([kept], { ttlSeconds: 60 });
  assert.equal((await e.blobs.listBlobs()).length, 2, 'real directories enumerate');
  assert.equal((await e.leases.list()).length, 1, 'real lease directories list');
  const report = await e.run({ apply: true });
  assert.equal(report.deleted, 1, 'real orphan is deleted');
  assert.equal(await e.blobs.has(orphan), false);
  assert.equal(await e.blobs.has(kept), true);
  await e.blobs.delete(orphan); // already gone: still idempotent
});

// ------------------------------------------- lease-record symlink ---------

/**
 * A lease RECORD that is a symlink must fail closed, not be skipped. The
 * ancestor guards already stop GC from following a symlinked lease directory;
 * this covers the last position — the record itself. The danger is not that
 * GC deletes through the link (it never rm()s a non-regular file) but that a
 * silently skipped record can be an ACTIVE lease, so its digest vanishes from
 * the protection set and the blob it protects becomes a deletion candidate.
 */
test('a symlinked lease record fails closed: an active external lease is never silently dropped', async t => {
  const e = await env(t);
  const outside = await externalTree(t);
  // An aged orphan that a valid, UNEXPIRED lease should protect.
  const orphan = await e.writeBlob('orphan protected only by a symlinked lease', { ageHours: 48 });
  const record = JSON.stringify({
    digest: orphan, expiresAt: new Date(NOW.getTime() + 3600 * 1000).toISOString(), updatedAt: NOW.toISOString()
  });
  const external = join(outside, 'lease.json');
  await writeFile(external, record, 'utf8');
  await mkdir(join(e.root, 'gc-leases', 'sha256'), { recursive: true });
  await symlink(external, join(e.root, 'gc-leases', 'sha256', `${orphan.slice('sha256:'.length)}.json`));

  // The unsafe behavior would be list() skipping it and active() omitting the
  // digest. Both must instead reject with the existing malformed-lease code.
  await assert.rejects(() => e.leases.list(), error => error.code === 'OWA_GC_LEASE_MALFORMED',
    'a symlinked record is malformed lease state, not absent lease state');
  await assert.rejects(() => e.leases.active(NOW), error => error.code === 'OWA_GC_LEASE_MALFORMED');

  let deletes = 0;
  const guarded = Object.create(e.blobs);
  guarded.delete = async digest => { deletes++; return e.blobs.delete(digest); };
  await assert.rejects(
    () => collectGarbage({ blobs: guarded, metadata: e.metadata, leases: e.leases, apply: true, pruneExpiredLeases: true, now: clock }),
    error => error instanceof GcError && error.code === 'OWA_GC_LEASE_MALFORMED');
  assert.equal(deletes, 0, 'GC aborted before any blob delete');
  assert.equal(await e.blobs.has(orphan), true, 'the blob the lease protects survives');
  assert.equal(existsSync(external), true, 'the external lease file still exists');
  assert.equal(await bytesAt(external), record, 'the external lease bytes are byte-identical');
  // Dry run reports the failure too, rather than a misleading candidate set.
  await assert.rejects(() => collectGarbage({ blobs: e.blobs, metadata: e.metadata, leases: e.leases, now: clock }),
    error => error instanceof GcError && error.code === 'OWA_GC_LEASE_MALFORMED');
});

test('a directory named like a lease record also fails closed', async t => {
  const e = await env(t);
  const orphan = await e.writeBlob('orphan beside a directory-shaped lease', { ageHours: 48 });
  await mkdir(join(e.root, 'gc-leases', 'sha256', `${'f'.repeat(64)}.json`), { recursive: true });
  await assert.rejects(() => e.leases.list(), error => error.code === 'OWA_GC_LEASE_MALFORMED');
  let deletes = 0;
  const guarded = Object.create(e.blobs);
  guarded.delete = async digest => { deletes++; return e.blobs.delete(digest); };
  await assert.rejects(
    () => collectGarbage({ blobs: guarded, metadata: e.metadata, leases: e.leases, apply: true, now: clock }),
    error => error instanceof GcError && error.code === 'OWA_GC_LEASE_MALFORMED');
  assert.equal(deletes, 0);
  assert.equal(await e.blobs.has(orphan), true);
});

test('non-json neighbours in the lease namespace are still ignored, not fatal', async t => {
  const e = await env(t);
  await e.leases.refresh([digestOf(Buffer.from('x'))], { ttlSeconds: 60 });
  await writeFile(join(e.root, 'gc-leases', 'sha256', 'README.txt'), 'operator note', 'utf8');
  await symlink('/nonexistent/target', join(e.root, 'gc-leases', 'sha256', 'stray-link'));
  assert.equal((await e.leases.list()).length, 1, 'only the real lease record counts; strangers are ignored');
});
