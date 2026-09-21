import { randomUUID } from 'node:crypto';
import { lstat, readdir, readFile } from 'node:fs/promises';
import { extname, relative, resolve, posix } from 'node:path';
import { OWA_MEDIA_TYPE, OWA_SPEC_VERSION, artifactDigest, owaError, sha256, validateManifest } from '../../spec/src/index.js';

function mediaType(path) {
  const ext = extname(path).toLowerCase();
  return ({
    '.html':'text/html; charset=utf-8','.htm':'text/html; charset=utf-8','.js':'text/javascript; charset=utf-8',
    '.mjs':'text/javascript; charset=utf-8','.css':'text/css; charset=utf-8','.json':'application/json; charset=utf-8',
    '.svg':'image/svg+xml','.png':'image/png','.jpg':'image/jpeg','.jpeg':'image/jpeg','.webp':'image/webp',
    '.gif':'image/gif','.txt':'text/plain; charset=utf-8','.wasm':'application/wasm','.ico':'image/x-icon',
    '.xml':'application/xml; charset=utf-8','.pdf':'application/pdf','.woff':'font/woff','.woff2':'font/woff2'
  })[ext] ?? 'application/octet-stream';
}

async function walk(root, dir=root) {
  const out=[];
  for (const name of (await readdir(dir)).sort()) {
    const full=resolve(dir,name); const s=await lstat(full);
    if (s.isSymbolicLink()) throw owaError('OWA_SYMLINK', `Symlinks are not supported in artifacts: ${full}`);
    if (s.isDirectory()) out.push(...await walk(root,full)); else if (s.isFile()) out.push(full);
  }
  return out;
}

export async function packDirectory(directory, entrypoint='/index.html') {
  const root=resolve(directory); const blobs=new Map(); const files=[];
  for (const filename of await walk(root)) {
    const data=new Uint8Array(await readFile(filename)); const digest=sha256(data);
    const path='/' + relative(root,filename).split('\\').join('/');
    blobs.set(digest,data); files.push({path,digest,size:data.byteLength,mediaType:mediaType(path)});
  }
  files.sort((a,b)=>a.path.localeCompare(b.path));
  const manifest={specVersion:OWA_SPEC_VERSION,artifactType:OWA_MEDIA_TYPE,entrypoint,files,access:{visibility:'unlisted'},lifecycle:{expiresAt:null}};
  validateManifest(manifest);
  return {manifest,artifactDigest:artifactDigest(manifest),blobs};
}

export function uniqueFileDigests(manifest) {
  return [...new Set(manifest.files.map(file => file.digest))];
}

/**
 * Default publish-lease lifetime: 24 hours.
 *
 * Deliberately far longer than the 900-second direct-upload grant, because the
 * lease must outlive the whole plan -> upload -> commit window (including
 * retries and a re-issued grant), not just one presigned URL. It is still
 * bounded: a client that waits longer than this before committing may find an
 * otherwise-unreferenced blob collected and must re-plan.
 */
export const PUBLISH_LEASE_TTL_SECONDS = 86_400;

/**
 * Protect every unique digest in a validated manifest for the publish window.
 *
 * ALL unique digests are leased, including ones already present in storage.
 * Leasing only the missing uploads would be unsafe: a digest that is currently
 * an orphan can be reported as reusable by the plan and then collected before
 * commit, so the client would be told it need not upload and commit would fail.
 * Leases are operational state only: nothing here touches the manifest,
 * canonical JSON, artifact digest, release record or any HTTP response body.
 */
async function leaseManifestDigests(leases, manifest, ttlSeconds) {
  if (!leases) return;
  await leases.refresh(uniqueFileDigests(manifest), { ttlSeconds });
}

// ---------------------------------------------------------------------------
// Commit-boundary blob integrity (issue #10).
//
// HOST INVARIANT: a release MUST NOT be persisted or activated unless every
// unique referenced blob has been STRONGLY verified against BOTH its manifest
// SHA-256 digest and its declared byte size. Existence, key naming, size alone,
// ETag alone, or caller-supplied metadata never count. This is a host storage
// rule: manifest schema, canonical JSON, artifact digest and release identity
// are untouched. See docs/integrity.md.
// ---------------------------------------------------------------------------

export const INTEGRITY_CODES = Object.freeze(['OWA_BLOB_MISSING', 'OWA_BLOB_INTEGRITY', 'OWA_BLOB_UNVERIFIED']);

/**
 * Fixed-shape integrity failure. Carries a digest only — never a storage key,
 * filesystem path, provider body, signed URL or credential. Unknown codes
 * collapse to UNVERIFIED so a backend cannot invent a passing-looking failure.
 */
export class IntegrityError extends Error {
  constructor(code, digest = null) {
    const safe = INTEGRITY_CODES.includes(code) ? code : 'OWA_BLOB_UNVERIFIED';
    const subject = typeof digest === 'string' ? ` ${digest}` : '';
    super(safe === 'OWA_BLOB_MISSING' ? `Missing blob${subject}`
      : safe === 'OWA_BLOB_INTEGRITY' ? `Blob integrity mismatch${subject}`
        : `Blob not verifiable${subject}`);
    this.name = 'IntegrityError';
    this.code = safe;
    this.digest = typeof digest === 'string' ? digest : null;
  }
}

/**
 * digest -> declared size, verified once per unique digest. One stored object
 * cannot satisfy two different declared sizes, so a manifest that declares the
 * same digest with conflicting sizes fails closed here — at commit/plan time,
 * without changing the portable manifest grammar.
 */
export function expectedBlobSizes(manifest) {
  const sizes = new Map();
  for (const file of manifest.files) {
    const prior = sizes.get(file.digest);
    if (prior !== undefined && prior !== file.size) throw new IntegrityError('OWA_BLOB_INTEGRITY', file.digest);
    sizes.set(file.digest, file.size);
  }
  return sizes;
}

/**
 * Ask the store for strong verification. Core does not know or care whether the
 * backend used local hashing, a provider-validated checksum, a streaming rehash
 * or some future storage-native proof; it only requires {ok:true, method}.
 * Stores without the contract fall back to an explicit read + SHA-256, which is
 * itself strong verification. Any failure becomes a fixed IntegrityError.
 */
export async function verifyStoredBlob(blobs, digest, size) {
  if (!Number.isSafeInteger(size) || size < 0) throw new IntegrityError('OWA_BLOB_UNVERIFIED', digest);
  if (typeof blobs.verifyBlob === 'function') {
    let result;
    try { result = await blobs.verifyBlob({ digest, size }); }
    catch (error) { throw new IntegrityError(error?.code, digest); }
    if (!result || result.ok !== true || typeof result.method !== 'string') throw new IntegrityError('OWA_BLOB_UNVERIFIED', digest);
    return result;
  }
  if (!(await blobs.has(digest))) throw new IntegrityError('OWA_BLOB_MISSING', digest);
  let bytes;
  try { bytes = await blobs.get(digest); } catch { throw new IntegrityError('OWA_BLOB_UNVERIFIED', digest); }
  if (bytes == null) throw new IntegrityError('OWA_BLOB_MISSING', digest);
  const body = Buffer.from(bytes);
  if (body.byteLength !== size || sha256(body) !== digest) throw new IntegrityError('OWA_BLOB_INTEGRITY', digest);
  return { ok: true, method: 'rehash' };
}

export async function planManifest({manifest, blobs, uploadFactory, leases=null, leaseTtlSeconds=PUBLISH_LEASE_TTL_SECONDS}) {
  validateManifest(manifest);
  const digest = artifactDigest(manifest);
  const sizes = expectedBlobSizes(manifest); // Conflicting sizes fail before any grant is minted.
  // Lease BEFORE probing existence: otherwise a blob could be collected between
  // the has() that reported it reusable and the lease that protects it.
  await leaseManifestDigests(leases, manifest, leaseTtlSeconds);
  const uploads=[]; let reused=0;
  for (const fileDigest of uniqueFileDigests(manifest)) {
    if (await blobs.has(fileDigest)) {
      // Integrity-aware reuse. "Present" is not "reusable": an existing object
      // with wrong bytes would otherwise be reported reusable forever, commit
      // would reject it forever, and the client could never repair it.
      try { await verifyStoredBlob(blobs, fileDigest, sizes.get(fileDigest)); reused++; continue; }
      catch (error) {
        if (!(error instanceof IntegrityError)) throw error;
        // UNVERIFIED (provider error, non-regular object) is not proof of
        // corruption: fail the plan rather than destroy a possibly-valid object.
        if (error.code === 'OWA_BLOB_UNVERIFIED') throw error;
        // INTEGRITY: proven wrong. Remove it so a fresh create-once grant can
        // replace it; the lease taken above keeps GC away from this digest.
        // MISSING: vanished between has() and verify — just grant an upload.
        if (error.code === 'OWA_BLOB_INTEGRITY') {
          if (typeof blobs.delete !== 'function') throw error;
          await blobs.delete(fileDigest);
        }
      }
    }
    uploads.push(await uploadFactory(fileDigest));
  }
  return {artifactDigest:digest,uploads,reused};
}

export async function commitManifest({slug,manifest,expectedArtifactDigest,blobs,metadata,activate=true}) {
  validateManifest(manifest);
  const digest=artifactDigest(manifest);
  if (expectedArtifactDigest && expectedArtifactDigest !== digest) throw new Error('Artifact digest does not match canonical manifest');
  // INTEGRITY GATE. Every unique blob is strongly verified against digest AND
  // declared size BEFORE any metadata is read or written. If this loop throws,
  // no site is created, no release is saved and no activation pointer moves.
  const sizes = expectedBlobSizes(manifest);
  for (const fileDigest of uniqueFileDigests(manifest)) await verifyStoredBlob(blobs, fileDigest, sizes.get(fileDigest));
  let site=await metadata.getSite(slug); if(!site) site=await metadata.createSite(slug);
  const release={id:`r_${randomUUID().replaceAll('-','').slice(0,20)}`,artifactDigest:digest,createdAt:new Date().toISOString(),manifest};
  await metadata.saveRelease(site.id,release);
  if (activate) { site.activeReleaseId=release.id; await metadata.saveSite(site); }
  return {site,release};
}

export async function publishDirectory({directory,slug,blobs,metadata,leases=null,leaseTtlSeconds=PUBLISH_LEASE_TTL_SECONDS}) {
  const packed=await packDirectory(directory); let uploaded=0,reused=0;
  // The local/trusted publisher races GC exactly like the HTTP path does, so it
  // takes the same lease protection rather than relying on being "internal".
  await leaseManifestDigests(leases,packed.manifest,leaseTtlSeconds);
  for(const [digest,data] of packed.blobs){
    if(await blobs.has(digest)){
      // Reuse only what verifies. A proven-corrupt object is rewritten with the
      // bytes just packed; an UNVERIFIED one (e.g. a non-regular filesystem
      // object) fails closed rather than being written through.
      try { await verifyStoredBlob(blobs,digest,data.byteLength); reused++; continue; }
      catch(error){ if(!(error instanceof IntegrityError)||error.code==='OWA_BLOB_UNVERIFIED') throw error; }
    }
    await blobs.put(digest,data);uploaded++;
  }
  const {site,release}=await commitManifest({slug,manifest:packed.manifest,expectedArtifactDigest:packed.artifactDigest,blobs,metadata});
  return {site,release,uploaded,reused};
}

export async function activateRelease(metadata,slug,releaseId){
  const site=await metadata.getSite(slug); if(!site) throw new Error('Site not found');
  const release=await metadata.getRelease(site.id,releaseId); if(!release) throw new Error('Release not found');
  site.activeReleaseId=release.id; await metadata.saveSite(site); return {site,release};
}

export function resolveRequestPath(manifest,urlPath){
  let decoded;
  try { decoded=decodeURIComponent(urlPath); } catch { return null; }
  if (decoded.includes('\\') || decoded.includes('\0')) return null;
  const raw='/' + decoded.replace(/^\/+/, '');
  const segments=raw.split('/');
  if (segments.some(segment => segment === '..')) return null;
  const normalized=posix.normalize(raw);
  const clean=normalized==='.'?'/':normalized;
  const direct=manifest.files.find(f=>f.path===clean || (clean==='/'&&f.path===manifest.entrypoint));
  if(direct) return direct;
  if(manifest.routing?.spaFallback) return manifest.files.find(f=>f.path===manifest.routing.spaFallback) ?? null;
  return null;
}
