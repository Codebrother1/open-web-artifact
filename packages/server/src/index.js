import { createHmac, randomBytes, timingSafeEqual } from 'node:crypto';
import { createServer } from 'node:http';
import { mkdir } from 'node:fs/promises';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { FilesystemBlobStore, FilesystemMetadataStore } from '../../storage-filesystem/src/index.js';
import { S3BlobStore } from '../../storage-s3/src/index.js';
import { activateRelease, commitManifest, planManifest, resolveRequestPath } from '../../core/src/index.js';
import { sha256 } from '../../spec/src/index.js';
import { AuthError, createAuthorizer, isSiteScope } from './auth.js';
import { artifactHeaders, securityHeaders } from './security-profile.js';

function json(res,status,body){res.writeHead(status,{'content-type':'application/json; charset=utf-8'});res.end(JSON.stringify(body,null,2));}
async function readJson(req){let raw='';for await(const c of req)raw+=c;return JSON.parse(raw||'{}');}
async function readBytes(req){const chunks=[];for await(const c of req)chunks.push(c);return Buffer.concat(chunks);}
function validUploadSignature(actual, expected) {
  return typeof actual === 'string' && /^[0-9a-f]{64}(?![\s\S])/.test(actual)
    && timingSafeEqual(Buffer.from(actual, 'hex'), Buffer.from(expected, 'hex'));
}
function uploadSignature(secret, digest, expires, site = null) {
  const input = site === null ? `${digest}\n${expires}` : `owa-upload-v1\n${site}\n${digest}\n${expires}`;
  return createHmac('sha256', secret).update(input).digest('hex');
}
function routeSite(segment) {
  let site;
  try { site = decodeURIComponent(segment); } catch { return null; }
  return isSiteScope(site) ? site : null;
}
function safeSiteRecord(site, slug) {
  // Metadata remains operator-trusted; do not let an index redirect this request
  // into another site's namespace or a filesystem path outside the store.
  if (site && (site.slug !== slug || !/^s_[0-9a-f]{20}(?![\s\S])/.test(site.id))) throw new Error('Invalid site record');
  return site;
}

export async function createDefaultStores({dataDir=resolve(process.env.OWA_DATA_DIR??'.owa-data')}={}){
  await mkdir(dataDir,{recursive:true});
  const metadata=new FilesystemMetadataStore(dataDir);
  if((process.env.OWA_STORAGE??'filesystem')==='s3'){
    const blobs=new S3BlobStore({
      endpoint:process.env.OWA_S3_ENDPOINT,
      bucket:process.env.OWA_S3_BUCKET,
      region:process.env.OWA_S3_REGION??'auto',
      accessKeyId:process.env.OWA_S3_ACCESS_KEY_ID,
      secretAccessKey:process.env.OWA_S3_SECRET_ACCESS_KEY,
      sessionToken:process.env.OWA_S3_SESSION_TOKEN??null,
      prefix:process.env.OWA_S3_PREFIX??'owa',
      addressingStyle:process.env.OWA_S3_ADDRESSING_STYLE??'path'
    });
    return {blobs,metadata,storageKind:'s3'};
  }
  return {blobs:new FilesystemBlobStore(dataDir),metadata,storageKind:'filesystem'};
}

export function createArtifactServer({blobs,metadata,uploadSecret=randomBytes(32).toString('hex'),publicBaseUrl=null,auth={},audit=null}={}){
  if(!blobs||!metadata)throw new Error('blobs and metadata stores are required');
  const authorizer = createAuthorizer(auth); // Required by default; missing secret fails closed.
  if (audit !== null && typeof audit !== 'function') throw new AuthError('OWA_AUTH_CONFIG');
  if (typeof uploadSecret !== 'string' && !Buffer.isBuffer(uploadSecret)) throw new AuthError('OWA_AUTH_CONFIG');
  if (Buffer.byteLength(uploadSecret) < (authorizer.mode === 'required' ? 32 : 1)) throw new AuthError('OWA_AUTH_CONFIG');
  if (authorizer.mode === 'required' && Buffer.from(uploadSecret).equals(Buffer.from(auth.secret))) throw new AuthError('OWA_AUTH_CONFIG');
  // Copy this key too; it is independent of the bearer-signing key.
  const localKey = Buffer.from(uploadSecret);
  function authorize(req, site, capabilities) {
    const claims = authorizer.authorize(req, site, capabilities);
    req.auth = Object.freeze({ jti: claims?.jti ?? null, site });
    return claims;
  }
  function auditOperation(req, operation) {
    if (!audit || !req.auth?.jti) return;
    // No request object, headers, URLs, tokens, claims, or error causes reach hooks.
    try { Promise.resolve(audit(Object.freeze({ ...req.auth, operation }))).catch(() => {}); } catch {}
  }
  function uploadLifetime(claims) {
    const issuedAt = authorizer.now();
    const remaining = claims ? claims.exp - issuedAt : 900;
    if (remaining <= 0) throw new AuthError('OWA_AUTH_EXPIRED');
    const expiresIn = Math.min(900, remaining);
    return { expiresIn, expires: issuedAt + expiresIn };
  }
  return createServer(async(req,res)=>{
    // Install the profile before every route and auth failure. Auth's challenge
    // and no-store fields are added normally; this never replaces all headers.
    for (const [name,value] of Object.entries(securityHeaders())) res.setHeader(name,value);
    try{
    const target=req.url??'/';
    if(!target.startsWith('/')||target.includes('#'))return json(res,400,{error:'Invalid request target'});
    const queryIndex=target.indexOf('?');
    const rawPath=queryIndex<0?target:target.slice(0,queryIndex);
    const base=`http://${req.headers.host??'localhost'}`;
    const url=new URL(target,base);
    if(req.method==='GET'&&url.pathname==='/health')return json(res,200,{ok:true,spec:'owa.dev/v1'});

    const planMatch=url.pathname.match(/^\/v1\/sites\/([^/]+)\/publish\/plan$/);
    if(req.method==='POST'&&planMatch){
      const slug=routeSite(planMatch[1]);
      if (!slug) return json(res,400,{error:'Invalid site scope',code:'OWA_INVALID_SITE'});
      authorize(req,slug,['plan']);
      const body=await readJson(req);
      authorize(req,slug,['plan']); // A slow body cannot extend authorization.
      const origin=publicBaseUrl??base;
      const plan=await planManifest({manifest:body.manifest,blobs,uploadFactory:async digest=>{
        // Plan is not permission to mint storage grants. Check at each mint,
        // after asynchronous existence checks, including expiration at that time.
        const claims=authorize(req,slug,['plan','upload']);
        const {expiresIn,expires}=uploadLifetime(claims);
        if(typeof blobs.createUpload==='function')return blobs.createUpload(digest,{expires:expiresIn});
        const scoped=authorizer.mode==='required';
        const sig=uploadSignature(localKey,digest,expires,scoped?slug:null);
        return {digest,method:'PUT',url:`${origin}/v1/uploads/${encodeURIComponent(digest)}?expires=${expires}&sig=${sig}${scoped?`&site=${encodeURIComponent(slug)}`:''}`,expiresIn,
          ...(scoped?{authorization:'bearer'}:{})};
      }});
      authorize(req,slug,['plan']); // Includes fully deduplicated plans after HEADs.
      if(body.artifactDigest&&body.artifactDigest!==plan.artifactDigest)return json(res,400,{error:'artifactDigest does not match canonical manifest'});
      auditOperation(req,'plan');
      return json(res,200,{slug,...plan});
    }

    const uploadMatch=url.pathname.match(/^\/v1\/uploads\/(sha256%3A[0-9a-f]{64}|sha256:[0-9a-f]{64})$/i);
    if(req.method==='PUT'&&uploadMatch){
      if(typeof blobs.createUpload==='function')return json(res,404,{error:'direct S3 uploads do not pass through artifactd'});
      const scoped=authorizer.mode==='required';
      const sites=url.searchParams.getAll('site');
      if (scoped && (sites.length!==1 || !isSiteScope(sites[0]))) return json(res,400,{error:'Invalid upload scope',code:'OWA_INVALID_SITE'});
      if (!scoped && sites.length) return json(res,400,{error:'Invalid upload scope',code:'OWA_INVALID_SITE'});
      // Legacy local grants are usable only in explicitly selected loopback dev.
      authorize(req,scoped?sites[0]:'local',['upload']);
      const digest=decodeURIComponent(uploadMatch[1]).toLowerCase();
      const expiresValues=url.searchParams.getAll('expires'), signatures=url.searchParams.getAll('sig');
      const rawExpires=expiresValues[0], expires=Number(rawExpires);
      if(expiresValues.length!==1 || !/^[0-9]+(?![\s\S])/.test(rawExpires??'') || !Number.isSafeInteger(expires) || expires<=authorizer.now())return json(res,403,{error:'Upload grant expired or invalid',code:'OWA_UPLOAD_INVALID'});
      if(signatures.length!==1 || !validUploadSignature(signatures[0],uploadSignature(localKey,digest,expires,scoped?sites[0]:null)))return json(res,403,{error:'Invalid upload signature',code:'OWA_UPLOAD_INVALID'});
      const bytes=await readBytes(req);
      authorize(req,scoped?sites[0]:'local',['upload']); // Recheck after receiving a slow body.
      if (expires<=authorizer.now()) return json(res,403,{error:'Upload grant expired or invalid',code:'OWA_UPLOAD_INVALID'});
      if(sha256(bytes)!==digest)return json(res,400,{error:'blob digest mismatch'});
      await blobs.put(digest,new Uint8Array(bytes)); auditOperation(req,'upload'); res.writeHead(204); return res.end();
    }

    const commitMatch=url.pathname.match(/^\/v1\/sites\/([^/]+)\/publish\/commit$/);
    if(req.method==='POST'&&commitMatch){
      const slug=routeSite(commitMatch[1]);
      if (!slug) return json(res,400,{error:'Invalid site scope',code:'OWA_INVALID_SITE'});
      authorize(req,slug,['commit']);
      const body=await readJson(req);
      const activate=body.activate!==false; // Preserve the existing activation default.
      authorize(req,slug,activate?['commit','activate']:['commit']);
      safeSiteRecord(await metadata.getSite(slug),slug);
      const r=await commitManifest({slug,manifest:body.manifest,expectedArtifactDigest:body.artifactDigest,blobs,metadata,activate});
      auditOperation(req,'commit');
      return json(res,201,{slug:r.site.slug,releaseId:r.release.id,artifactDigest:r.release.artifactDigest,activeReleaseId:r.site.activeReleaseId});
    }

    const a=url.pathname.match(/^\/v1\/sites\/([^/]+)\/activate\/([^/]+)$/);
    if(req.method==='POST'&&a){
      const slug=routeSite(a[1]);
      if (!slug) return json(res,400,{error:'Invalid site scope',code:'OWA_INVALID_SITE'});
      authorize(req,slug,['activate']);
      let releaseId;
      try { releaseId=decodeURIComponent(a[2]); } catch { return json(res,400,{error:'Invalid release identifier'}); }
      if (!/^r_[0-9a-f]{20}(?![\s\S])/.test(releaseId)) return json(res,400,{error:'Invalid release identifier'});
      safeSiteRecord(await metadata.getSite(slug),slug);
      const r=await activateRelease(metadata,slug,releaseId); auditOperation(req,'activate');
      return json(res,200,{slug:r.site.slug,activeReleaseId:r.release.id});
    }
    const l=url.pathname.match(/^\/v1\/sites\/([^/]+)\/releases$/);
    if(req.method==='GET'&&l){
      const slug=routeSite(l[1]);
      if (!slug) return json(res,400,{error:'Invalid site scope',code:'OWA_INVALID_SITE'});
      authorize(req,slug,['read']);
      const site=safeSiteRecord(await metadata.getSite(slug),slug);
      if(!site)return json(res,404,{error:'site not found'});
      const releases=await metadata.listReleases(site.id); auditOperation(req,'read');
      return json(res,200,{site,releases});
    }
    const host=(req.headers.host??'').split(':')[0];const slug=host.endsWith('.localhost')?host.slice(0,-10):url.searchParams.get('site');
    if((req.method==='GET'||req.method==='HEAD')&&slug){
      if (!isSiteScope(slug)) return json(res,404,{error:'site or active release not found'});
      const site=safeSiteRecord(await metadata.getSite(slug),slug);if(!site?.activeReleaseId)return json(res,404,{error:'site or active release not found'});
      if (!/^r_[0-9a-f]{20}(?![\s\S])/.test(site.activeReleaseId)) throw new Error('Invalid active release');
      const release=await metadata.getRelease(site.id,site.activeReleaseId);if(!release)return json(res,404,{error:'release not found'});
      if(release.manifest.lifecycle?.expiresAt&&new Date(release.manifest.lifecycle.expiresAt)<=new Date())return json(res,410,{error:'artifact expired'});
      // Preserve the raw artifact pathname for the unchanged decode-once resolver;
      // WHATWG URL parsing must not erase traversal before its checks.
      const file=resolveRequestPath(release.manifest,rawPath);if(!file)return json(res,404,{error:'file not found'});
      const body=await blobs.get(file.digest);
      res.writeHead(200,{...artifactHeaders(file.mediaType),'content-length':String(body.byteLength),'etag':`"${file.digest}"`});
      return res.end(req.method==='HEAD'?undefined:Buffer.from(body));
    }
    return json(res,404,{error:'not found'});
  }catch(e){
    if (e instanceof AuthError) {
      if (e.status===401) res.setHeader('www-authenticate','Bearer realm="owa"');
      res.setHeader('cache-control','no-store');
      return json(res,e.status,{error:e.message,code:e.code});
    }
    // Only a fixed, recognized core failure is surfaced; provider errors and
    // nested causes can contain presigned URLs and must never be reflected.
    if (e instanceof Error && /^Missing blob sha256:[0-9a-f]{64}(?![\s\S])/.test(e.message)) return json(res,500,{error:'Missing blob',code:'OWA_BLOB_MISSING'});
    return json(res,500,{error:'Operation failed',code:'OWA_OPERATION_FAILED'});
  }});
}

async function main(){
  const mode=process.argv.includes('--dev')?'dev':(process.env.OWA_AUTH_MODE??'required');
  const auth={mode,secret:process.env.OWA_AUTH_SECRET};
  createAuthorizer(auth); // Fail before opening storage or a listener.
  const port=Number(process.env.PORT??7331); const stores=await createDefaultStores();
  const server=createArtifactServer({...stores,auth,publicBaseUrl:process.env.OWA_PUBLIC_BASE_URL??null});
  const host=mode==='dev'?'127.0.0.1':(process.env.HOST??'127.0.0.1');
  server.listen(port,host,()=>console.log(`artifactd (${stores.storageKind}, auth ${mode}) listening on port ${server.address().port}`));
  server.on('error',()=>{console.error('artifactd failed to listen');process.exitCode=1;});
}

if(process.argv[1]&&import.meta.url===pathToFileURL(resolve(process.argv[1])).href){
  try { await main(); } catch { console.error('artifactd startup failed; check authentication and storage configuration'); process.exitCode=1; }
}
