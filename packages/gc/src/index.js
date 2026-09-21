// Conservative mark/sweep garbage collection for unreferenced blob objects.
//
// This is a STORAGE OPERATIONS tool. It does not change artifact identity,
// manifests, canonical JSON, release records, activation, auth, origin
// isolation, MCP or OCI, and it is never exposed over HTTP.
//
// RETENTION RULE: every stored release is a GC root — active, inactive,
// superseded rollback targets, and releases whose lifecycle.expiresAt is
// already in the past. This collector NEVER deletes a release record and
// implements no release pruning. See docs/gc.md.

import { uniqueFileDigests } from '../../core/src/index.js';
import { artifactDigest, validateManifest } from '../../spec/src/index.js';

/** Conservative default: an object must be idle for 24 hours to be a candidate. */
export const DEFAULT_GRACE_SECONDS = 86_400;

const CODES = new Set([
  'OWA_GC_METADATA_UNREADABLE',
  'OWA_GC_METADATA_MALFORMED',
  'OWA_GC_MANIFEST_INVALID',
  'OWA_GC_LEASE_MALFORMED',
  'OWA_GC_LEASE_UNREADABLE',
  'OWA_GC_LIST_FAILED',
  'OWA_GC_DELETE_FAILED',
  'OWA_GC_INVALID_DIGEST',
  'OWA_GC_INVALID_CONFIG'
]);

/**
 * Fixed-shape GC failure. Only a known code is ever surfaced, so a provider
 * body, signed URL, credential or stack can never reach operator output.
 */
export class GcError extends Error {
  constructor(code) {
    const safe = CODES.has(code) ? code : 'OWA_GC_DELETE_FAILED';
    super(`garbage collection failed: ${safe}`);
    this.name = 'GcError';
    this.code = safe;
  }
}

/** Re-throw any storage/metadata failure as a fixed GC code, dropping the cause. */
function asGcError(error, fallback) {
  const code = typeof error?.code === 'string' && CODES.has(error.code) ? error.code : fallback;
  return new GcError(code);
}

/**
 * Build the release mark set.
 *
 * Every release of every site is a root. Enumeration and validation both fail
 * closed: if a single site, release or manifest cannot be read and validated,
 * this throws and the caller must abort. Skipping an unreadable release would
 * silently drop its digests from the mark set and delete live blobs.
 */
export async function markReleaseDigests(metadata) {
  let sites;
  try { sites = await metadata.listSites(); }
  catch (error) { throw asGcError(error, 'OWA_GC_METADATA_UNREADABLE'); }

  const marked = new Set();
  let releases = 0;
  for (const site of sites) {
    let stored;
    try { stored = await metadata.listAllReleases(site.id); }
    catch (error) { throw asGcError(error, 'OWA_GC_METADATA_UNREADABLE'); }
    for (const release of stored) {
      releases++;
      // Validate with the existing spec validator; a stored release whose
      // manifest no longer validates means the metadata cannot be trusted.
      try { validateManifest(release.manifest); }
      catch { throw new GcError('OWA_GC_MANIFEST_INVALID'); }
      // Self-consistency only. This re-derives identity from metadata already
      // held; it does NOT read or rehash blob bytes (that is issue #10).
      if (artifactDigest(release.manifest) !== release.artifactDigest) {
        throw new GcError('OWA_GC_METADATA_MALFORMED');
      }
      // Duplicate content across files and across releases collapses naturally.
      for (const digest of uniqueFileDigests(release.manifest)) marked.add(digest);
    }
  }
  return { sites: sites.length, releases, marked };
}

/** Digests protected by an unexpired publish lease at `asOf`. */
async function markLeasedDigests(leases, asOf) {
  if (!leases) return new Set();
  try { return await leases.active(asOf); }
  catch (error) { throw asGcError(error, 'OWA_GC_LEASE_MALFORMED'); }
}

/**
 * Run a collection pass.
 *
 * Algorithm:
 *   1. record the scan start time;
 *   2. mark every digest referenced by every stored release (fails closed);
 *   3. mark every digest under an unexpired lease (fails closed);
 *   4. enumerate blob objects, confined to the OWA blob namespace;
 *   5. a candidate is unreferenced AND unleased AND older than the grace cutoff;
 *   6. dry run (the default) stops here and mutates nothing;
 *   7. apply re-marks releases and leases, skips anything newly protected, and
 *      only then deletes.
 *
 * `beforeSweep` is an injectable hook that runs between the two marks, so the
 * race window can be tested deterministically instead of with sleeps.
 */
export async function collectGarbage({
  blobs,
  metadata,
  leases = null,
  apply = false,
  graceSeconds = DEFAULT_GRACE_SECONDS,
  now = () => new Date(),
  beforeSweep = null,
  pruneExpiredLeases = false
} = {}) {
  if (!blobs || !metadata) throw new GcError('OWA_GC_INVALID_CONFIG');
  if (!Number.isSafeInteger(graceSeconds) || graceSeconds < 0) throw new GcError('OWA_GC_INVALID_CONFIG');
  if (typeof blobs.listBlobs !== 'function' || typeof blobs.delete !== 'function') throw new GcError('OWA_GC_INVALID_CONFIG');

  const startedAt = now();
  if (!(startedAt instanceof Date) || !Number.isFinite(startedAt.getTime())) throw new GcError('OWA_GC_INVALID_CONFIG');
  const cutoff = new Date(startedAt.getTime() - graceSeconds * 1000);

  // --- mark -----------------------------------------------------------------
  const { sites, releases, marked } = await markReleaseDigests(metadata);
  const leased = await markLeasedDigests(leases, startedAt);

  // --- enumerate ------------------------------------------------------------
  let objects;
  try { objects = await blobs.listBlobs(); }
  catch (error) { throw asGcError(error, 'OWA_GC_LIST_FAILED'); }

  const report = {
    mode: apply ? 'apply' : 'dry-run',
    startedAt: startedAt.toISOString(),
    graceSeconds,
    graceCutoff: cutoff.toISOString(),
    sitesScanned: sites,
    releasesScanned: releases,
    releaseDigestsMarked: marked.size,
    activeLeases: leased.size,
    blobsScanned: objects.length,
    bytesScanned: 0,
    referencedSkipped: 0,
    leasedSkipped: 0,
    youngSkipped: 0,
    candidates: 0,
    candidateBytes: 0,
    deleted: 0,
    deletedBytes: 0,
    raceSkipped: 0,
    expiredLeasesCleaned: 0,
    candidateDigests: []
  };

  const candidates = [];
  for (const object of objects) {
    report.bytesScanned += object.size;
    if (marked.has(object.digest)) { report.referencedSkipped++; continue; }
    if (leased.has(object.digest)) { report.leasedSkipped++; continue; }
    // Strictly newer than the cutoff is "young": equal age is collectible.
    if (object.lastModified > cutoff) { report.youngSkipped++; continue; }
    candidates.push(object);
    report.candidateBytes += object.size;
    report.candidateDigests.push(object.digest);
  }
  report.candidates = candidates.length;

  // --- dry run --------------------------------------------------------------
  // Zero destructive mutation: no blob delete, and no lease pruning either.
  if (!apply) return report;

  // --- final re-mark --------------------------------------------------------
  // Everything above succeeded, so metadata and storage were both readable.
  // Recompute protection now: anything referenced or leased since the first
  // scan must survive. This runs BEFORE the first delete, never after.
  if (beforeSweep) await beforeSweep(report);
  const { marked: marked2 } = await markReleaseDigests(metadata);
  const leased2 = await markLeasedDigests(leases, now());

  for (const object of candidates) {
    if (marked2.has(object.digest) || leased2.has(object.digest)) { report.raceSkipped++; continue; }
    try { await blobs.delete(object.digest); }
    catch (error) { throw asGcError(error, 'OWA_GC_DELETE_FAILED'); }
    report.deleted++;
    report.deletedBytes += object.size;
  }

  if (pruneExpiredLeases && leases && typeof leases.pruneExpired === 'function') {
    try { report.expiredLeasesCleaned = await leases.pruneExpired(now()); }
    catch (error) { throw asGcError(error, 'OWA_GC_LEASE_MALFORMED'); }
  }
  return report;
}

/** Operator-facing text report. Contains only counts, bytes and digests. */
export function formatReport(report) {
  const lines = [
    `mode:                    ${report.mode}`,
    `grace:                   ${report.graceSeconds}s (cutoff ${report.graceCutoff})`,
    `sites scanned:           ${report.sitesScanned}`,
    `releases scanned:        ${report.releasesScanned}`,
    `release digests marked:  ${report.releaseDigestsMarked}`,
    `active publish leases:   ${report.activeLeases}`,
    `blobs scanned:           ${report.blobsScanned} (${report.bytesScanned} bytes)`,
    `referenced (skipped):    ${report.referencedSkipped}`,
    `leased (skipped):        ${report.leasedSkipped}`,
    `younger than grace:      ${report.youngSkipped}`,
    `orphan candidates:       ${report.candidates} (${report.candidateBytes} bytes)`,
    `deleted:                 ${report.deleted} (${report.deletedBytes} bytes)`,
    `skipped by re-check:     ${report.raceSkipped}`,
    `expired leases cleaned:  ${report.expiredLeasesCleaned}`
  ];
  if (report.candidateDigests.length) {
    lines.push('candidates:');
    for (const digest of report.candidateDigests) lines.push(`  ${digest}`);
  }
  if (report.mode === 'dry-run') lines.push('', 'Dry run: nothing was deleted. Re-run with --apply to reclaim.');
  return lines.join('\n');
}
