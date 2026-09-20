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

export async function planManifest({manifest, blobs, uploadFactory}) {
  validateManifest(manifest);
  const digest = artifactDigest(manifest);
  const uploads=[]; let reused=0;
  for (const fileDigest of uniqueFileDigests(manifest)) {
    if (await blobs.has(fileDigest)) { reused++; continue; }
    uploads.push(await uploadFactory(fileDigest));
  }
  return {artifactDigest:digest,uploads,reused};
}

export async function commitManifest({slug,manifest,expectedArtifactDigest,blobs,metadata,activate=true}) {
  validateManifest(manifest);
  const digest=artifactDigest(manifest);
  if (expectedArtifactDigest && expectedArtifactDigest !== digest) throw new Error('Artifact digest does not match canonical manifest');
  for (const fileDigest of uniqueFileDigests(manifest)) {
    if (!(await blobs.has(fileDigest))) throw new Error(`Missing blob ${fileDigest}`);
  }
  let site=await metadata.getSite(slug); if(!site) site=await metadata.createSite(slug);
  const release={id:`r_${randomUUID().replaceAll('-','').slice(0,20)}`,artifactDigest:digest,createdAt:new Date().toISOString(),manifest};
  await metadata.saveRelease(site.id,release);
  if (activate) { site.activeReleaseId=release.id; await metadata.saveSite(site); }
  return {site,release};
}

export async function publishDirectory({directory,slug,blobs,metadata}) {
  const packed=await packDirectory(directory); let uploaded=0,reused=0;
  for(const [digest,data] of packed.blobs){if(await blobs.has(digest))reused++;else{await blobs.put(digest,data);uploaded++;}}
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
