import { lstat, mkdir, readFile, readdir, rm, writeFile } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { dirname, join, relative, resolve, sep } from 'node:path';
import { randomUUID } from 'node:crypto';

// Operational GC helpers. None of this is artifact state: no manifest, canonical
// JSON, artifact digest, release record or HTTP response is affected by it.
const DIGEST = /^sha256:[0-9a-f]{64}$/;
const HEX = /^[0-9a-f]{64}$/;
const SITE_ID = /^s_[0-9a-f]{20}$/;
const RELEASE_ID = /^r_[0-9a-f]{20}$/;
const SLUG = /^[a-z0-9][a-z0-9_-]{0,62}$/;

/** Fixed-shape operational failure: never carries a provider body or a path. */
export class StorageOperationError extends Error {
  constructor(code) {
    super(`storage operation failed: ${code}`);
    this.name = 'StorageOperationError';
    this.code = code;
  }
}

/**
 * Lexical containment only. This catches `..` and absolute-path tricks in a
 * spelled path, but it CANNOT see a symlink: `<root>/blobs -> /elsewhere` still
 * spells every child as `<root>/blobs/...`. It is kept as defense in depth and
 * is never the sole check before enumeration or deletion; see realDirectoryChain.
 */
function isInside(root, child) {
  const rel = relative(resolve(root), resolve(child));
  return rel !== '' && !rel.startsWith(`..${sep}`) && rel !== '..' && !resolve(child).startsWith(`${resolve(root)}${sep}..`);
}

/**
 * No-follow ancestor guard for GC-owned directories.
 *
 * Walks each path component BELOW the configured root and lstat()s it, so a
 * symlink in an operational directory position (`blobs`, `blobs/sha256`,
 * `gc-leases/sha256`, `sites/<id>/releases`, ...) is reported as a link and
 * rejected instead of being silently followed by readdir()/rm(). The root itself
 * is operator configuration and is not inspected. Returns 'ok' when every
 * component is a real directory, 'missing' when a component does not exist
 * (the caller decides whether absence is acceptable), and throws `code` for a
 * symlink, a non-directory, or any other lstat failure.
 *
 * This defends against PRE-EXISTING symlinks. Node has no openat/unlinkat-style
 * API, so a concurrent local attacker who can swap a directory for a symlink
 * between this check and the following operation is outside the reference
 * threat model; see docs/gc.md.
 */
async function realDirectoryChain(root, segments, code) {
  let current = root;
  for (const segment of segments) {
    current = join(current, segment);
    let stats;
    try { stats = await lstat(current); }
    catch (error) {
      if (error?.code === 'ENOENT') return 'missing';
      throw new StorageOperationError(code);
    }
    if (stats.isSymbolicLink() || !stats.isDirectory()) throw new StorageOperationError(code);
  }
  return 'ok';
}

/**
 * lstat() a destructive target and require a regular file, never a symlink or
 * directory. Returns null when the target is already absent (idempotent), the
 * stats otherwise, and throws `code` for anything that is not a plain file.
 */
async function regularFileOrMissing(path, code) {
  let stats;
  try { stats = await lstat(path); }
  catch (error) {
    if (error?.code === 'ENOENT') return null;
    throw new StorageOperationError(code);
  }
  if (stats.isSymbolicLink() || !stats.isFile()) throw new StorageOperationError(code);
  return stats;
}

async function writeJson(path,value){await mkdir(dirname(path),{recursive:true});await writeFile(path,JSON.stringify(value,null,2));}
async function readJson(path){if(!existsSync(path))return null;return JSON.parse(await readFile(path,'utf8'));}

export class FilesystemBlobStore{
  constructor(root){this.root=root;}
  path(digest){return join(this.root,'blobs',digest.replace(':','/'));}
  async has(digest){return existsSync(this.path(digest));}
  async put(digest,data){const p=this.path(digest);await mkdir(dirname(p),{recursive:true});await writeFile(p,data);}
  async get(digest){return new Uint8Array(await readFile(this.path(digest)));}

  /**
   * Enumerate OWA blob objects for GC. Only `<root>/blobs/sha256/<64 hex>` is
   * recognized. Entries are inspected with lstat, so a symlink is never followed
   * and can never make GC consider a file outside the blob root; anything that
   * is not a regular file with a valid digest name is ignored rather than
   * deleted. Unrelated neighbours therefore cannot become candidates.
   */
  async listBlobs(){
    const algorithms=join(this.root,'blobs');
    // FAIL CLOSED if `<root>/blobs` is a symlink: readdir() would follow it and
    // every later lexical check would still spell paths under <root>/blobs while
    // the filesystem resolved outside the configured data root.
    if(await realDirectoryChain(this.root,['blobs'],'OWA_GC_LIST_FAILED')==='missing')return [];
    const out=[];
    let entries;
    try { entries=await readdir(algorithms,{withFileTypes:true}); }
    catch { throw new StorageOperationError('OWA_GC_LIST_FAILED'); }
    for(const algorithm of entries){
      // The GC-owned namespace is exactly `blobs/sha256`. A symlink sitting in
      // that position is a misconfiguration and fails closed rather than being
      // followed or quietly enumerated as empty. Unrelated neighbours are ignored.
      if(algorithm.name==='sha256'&&algorithm.isSymbolicLink())throw new StorageOperationError('OWA_GC_LIST_FAILED');
      if(!algorithm.isDirectory()||algorithm.name!=='sha256')continue;
      const dir=join(algorithms,algorithm.name);
      await realDirectoryChain(this.root,['blobs','sha256'],'OWA_GC_LIST_FAILED');
      if(!isInside(this.root,dir))continue;
      let files;
      try { files=await readdir(dir,{withFileTypes:true}); }
      catch { throw new StorageOperationError('OWA_GC_LIST_FAILED'); }
      for(const file of files){
        if(!HEX.test(file.name))continue; // Not an OWA blob object.
        const full=join(dir,file.name);
        if(!isInside(this.root,full))continue;
        let stats;
        try { stats=await lstat(full); } catch { continue; }
        // lstat, not stat: a symlink is reported as a link and skipped outright.
        if(!stats.isFile())continue;
        out.push({digest:`sha256:${file.name}`,size:stats.size,lastModified:stats.mtime});
      }
    }
    return out;
  }

  /** Delete exactly one blob. Idempotent: a missing object is not an error. */
  async delete(digest){
    if(!DIGEST.test(digest))throw new StorageOperationError('OWA_GC_INVALID_DIGEST');
    const path=this.path(digest);
    if(!isInside(this.root,path))throw new StorageOperationError('OWA_GC_INVALID_DIGEST');
    // Every ancestor must be a real directory and the target a regular file.
    // rm() through a symlinked ancestor would unlink the EXTERNAL file.
    if(await realDirectoryChain(this.root,['blobs','sha256'],'OWA_GC_DELETE_FAILED')==='missing')return;
    if(await regularFileOrMissing(path,'OWA_GC_DELETE_FAILED')===null)return; // Idempotent.
    try { await rm(path,{force:true}); } catch { throw new StorageOperationError('OWA_GC_DELETE_FAILED'); }
  }
}

/**
 * Publish leases: bounded, non-artifact protection for digests involved in an
 * in-progress publish. Stored at `<root>/gc-leases/sha256/<hex>.json` holding
 * only { digest, expiresAt, updatedAt } — never a token, credential, signed URL,
 * request header or manifest. Nothing here is part of artifact identity.
 */
export class FilesystemLeaseStore{
  constructor(root,{now=()=>new Date()}={}){this.root=root;this.now=now;}
  path(digest){return join(this.root,'gc-leases','sha256',`${digest.slice('sha256:'.length)}.json`);}

  /**
   * Create or extend protection for each digest. Protection is NEVER shortened:
   * an existing lease that already reaches further into the future wins, so a
   * slow publish is not weakened by a later quick re-plan.
   */
  async refresh(digests,{ttlSeconds}){
    if(!Number.isSafeInteger(ttlSeconds)||ttlSeconds<=0)throw new StorageOperationError('OWA_GC_INVALID_LEASE_TTL');
    const at=this.now();
    const target=new Date(at.getTime()+ttlSeconds*1000);
    // A missing lease directory is created normally; a symlinked one is never
    // written through, so lease records cannot land outside the data root.
    await realDirectoryChain(this.root,['gc-leases','sha256'],'OWA_GC_LEASE_UNREADABLE');
    const written=[];
    for(const digest of new Set(digests)){
      if(!DIGEST.test(digest))throw new StorageOperationError('OWA_GC_INVALID_DIGEST');
      const path=this.path(digest);
      await regularFileOrMissing(path,'OWA_GC_LEASE_UNREADABLE'); // Never overwrite through a link.
      let expiresAt=target;
      const existing=await readJson(path).catch(()=>null);
      if(existing&&typeof existing.expiresAt==='string'){
        const current=new Date(existing.expiresAt);
        if(Number.isFinite(current.getTime())&&current>target)expiresAt=current;
      }
      await writeJson(path,{digest,expiresAt:expiresAt.toISOString(),updatedAt:at.toISOString()});
      written.push({digest,expiresAt});
    }
    return written;
  }

  /**
   * Every stored lease, validated. A malformed record throws rather than being
   * skipped: a lease that cannot be read is a lease that cannot be proven
   * expired, and GC must not delete on that basis.
   */
  async list(){
    const dir=join(this.root,'gc-leases','sha256');
    // FAIL CLOSED on a symlinked lease directory or ancestor: an external tree
    // must never be read as lease state, nor later pruned as if it were ours.
    if(await realDirectoryChain(this.root,['gc-leases','sha256'],'OWA_GC_LEASE_UNREADABLE')==='missing')return [];
    let files;
    try { files=await readdir(dir,{withFileTypes:true}); }
    catch { throw new StorageOperationError('OWA_GC_LEASE_UNREADABLE'); }
    const out=[];
    for(const file of files){
      // Unrelated neighbours that are not lease records are ignored. Anything
      // NAMED as a lease record must be a real regular file. Dirent.isFile() is
      // false for a symlink, a directory or any other object, and silently
      // skipping such an entry would drop a possibly-ACTIVE lease from the
      // protection set, turning a protected blob into a deletion candidate.
      // Fail closed instead; the entry is never followed or read.
      if(!file.name.endsWith('.json'))continue;
      if(!file.isFile())throw new StorageOperationError('OWA_GC_LEASE_MALFORMED');
      const hex=file.name.slice(0,-'.json'.length);
      if(!HEX.test(hex))throw new StorageOperationError('OWA_GC_LEASE_MALFORMED');
      let record;
      try { record=await readJson(join(dir,file.name)); }
      catch { throw new StorageOperationError('OWA_GC_LEASE_MALFORMED'); }
      const expiresAt=new Date(record?.expiresAt ?? NaN);
      if(!record||record.digest!==`sha256:${hex}`||typeof record.expiresAt!=='string'||!Number.isFinite(expiresAt.getTime())){
        throw new StorageOperationError('OWA_GC_LEASE_MALFORMED');
      }
      out.push({digest:record.digest,expiresAt});
    }
    return out;
  }

  /** Digests still protected at `asOf`. */
  async active(asOf=this.now()){
    return new Set((await this.list()).filter(lease=>lease.expiresAt>asOf).map(lease=>lease.digest));
  }

  /** Destructive: drop expired lease records. Never called during a dry run. */
  async pruneExpired(asOf=this.now()){
    let removed=0;
    const leases=await this.list(); // Already guarded against a symlinked namespace.
    // Re-verify immediately before the destructive pass, then require each
    // record to be a regular file: rm() must never reach through a link.
    if(await realDirectoryChain(this.root,['gc-leases','sha256'],'OWA_GC_LEASE_PRUNE_FAILED')==='missing')return 0;
    for(const lease of leases){
      if(lease.expiresAt>asOf)continue;
      const path=this.path(lease.digest);
      if(await regularFileOrMissing(path,'OWA_GC_LEASE_PRUNE_FAILED')===null)continue;
      try { await rm(path,{force:true}); removed++; }
      catch { throw new StorageOperationError('OWA_GC_LEASE_PRUNE_FAILED'); }
    }
    return removed;
  }
}

export class FilesystemMetadataStore{
  constructor(root){this.root=root;}
  siteIndex(slug){return join(this.root,'sites-by-slug',`${slug}.json`);}
  sitePath(id){return join(this.root,'sites',id,'site.json');}
  releasePath(siteId,id){return join(this.root,'sites',siteId,'releases',`${id}.json`);}
  async createSite(slug){const existing=await this.getSite(slug);if(existing)return existing;const site={id:`s_${randomUUID().replaceAll('-','').slice(0,20)}`,slug,activeReleaseId:null,createdAt:new Date().toISOString()};await writeJson(this.sitePath(site.id),site);await writeJson(this.siteIndex(slug),{id:site.id});return site;}
  async getSite(slug){const idx=await readJson(this.siteIndex(slug));return idx?readJson(this.sitePath(idx.id)):null;}
  async saveSite(site){await writeJson(this.sitePath(site.id),site);await writeJson(this.siteIndex(site.slug),{id:site.id});}
  async saveRelease(siteId,release){await writeJson(this.releasePath(siteId,release.id),release);}
  async getRelease(siteId,releaseId){return readJson(this.releasePath(siteId,releaseId));}
  async listReleases(siteId){const dir=join(this.root,'sites',siteId,'releases');if(!existsSync(dir))return[];const out=[];for(const n of await readdir(dir)){const r=await readJson(join(dir,n));if(r)out.push(r);}return out.sort((a,b)=>b.createdAt.localeCompare(a.createdAt));}

  /**
   * Every site, strictly validated, for GC root discovery.
   *
   * This FAILS CLOSED: an unexpected directory, an unreadable or malformed
   * record, or an inconsistent id/slug/pointer throws instead of being skipped.
   * Silently ignoring an unreadable site would silently drop its releases from
   * the mark set, and GC would then delete live blobs.
   */
  async listSites(){
    const dir=join(this.root,'sites');
    // FAIL CLOSED: a symlinked `sites` directory would let an external tree pose
    // as the release roots that decide what survives GC.
    if(await realDirectoryChain(this.root,['sites'],'OWA_GC_METADATA_MALFORMED')==='missing')return [];
    let entries;
    try { entries=await readdir(dir,{withFileTypes:true}); }
    catch { throw new StorageOperationError('OWA_GC_METADATA_UNREADABLE'); }
    const out=[];
    for(const entry of entries){
      if(!entry.isDirectory()||!SITE_ID.test(entry.name))throw new StorageOperationError('OWA_GC_METADATA_MALFORMED');
      const path=this.sitePath(entry.name);
      if(!isInside(this.root,path))throw new StorageOperationError('OWA_GC_METADATA_MALFORMED');
      let site;
      try { site=await readJson(path); }
      catch { throw new StorageOperationError('OWA_GC_METADATA_MALFORMED'); }
      if(!site||typeof site!=='object'||Array.isArray(site)
        ||site.id!==entry.name||!SLUG.test(String(site.slug??''))
        ||!(site.activeReleaseId===null||RELEASE_ID.test(String(site.activeReleaseId??'')))){
        throw new StorageOperationError('OWA_GC_METADATA_MALFORMED');
      }
      out.push(site);
    }
    return out;
  }

  /**
   * Every release for a site, strictly validated. ALL releases are returned —
   * active, inactive, superseded rollback targets and releases whose
   * lifecycle.expiresAt is in the past. Each one is a GC root.
   */
  async listAllReleases(siteId){
    if(!SITE_ID.test(String(siteId??'')))throw new StorageOperationError('OWA_GC_METADATA_MALFORMED');
    const dir=join(this.root,'sites',siteId,'releases');
    if(!isInside(this.root,dir))throw new StorageOperationError('OWA_GC_METADATA_MALFORMED');
    // FAIL CLOSED: `sites`, `sites/<id>` and `sites/<id>/releases` must all be
    // real directories. A symlinked releases directory is malformed metadata,
    // never a source of trusted roots, and apply aborts before any deletion.
    if(await realDirectoryChain(this.root,['sites',siteId,'releases'],'OWA_GC_METADATA_MALFORMED')==='missing')return [];
    let entries;
    try { entries=await readdir(dir,{withFileTypes:true}); }
    catch { throw new StorageOperationError('OWA_GC_METADATA_UNREADABLE'); }
    const out=[];
    for(const entry of entries){
      if(!entry.isFile()||!entry.name.endsWith('.json'))throw new StorageOperationError('OWA_GC_METADATA_MALFORMED');
      const id=entry.name.slice(0,-'.json'.length);
      if(!RELEASE_ID.test(id))throw new StorageOperationError('OWA_GC_METADATA_MALFORMED');
      const path=this.releasePath(siteId,id);
      if(!isInside(this.root,path))throw new StorageOperationError('OWA_GC_METADATA_MALFORMED');
      let release;
      try { release=await readJson(path); }
      catch { throw new StorageOperationError('OWA_GC_METADATA_MALFORMED'); }
      if(!release||typeof release!=='object'||Array.isArray(release)
        ||release.id!==id||typeof release.artifactDigest!=='string'
        ||!DIGEST.test(release.artifactDigest)
        ||!release.manifest||typeof release.manifest!=='object'||Array.isArray(release.manifest)){
        throw new StorageOperationError('OWA_GC_METADATA_MALFORMED');
      }
      out.push(release);
    }
    return out;
  }
}
