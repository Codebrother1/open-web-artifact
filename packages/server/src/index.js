import { createHmac, randomBytes } from 'node:crypto';
import { createServer } from 'node:http';
import { mkdir } from 'node:fs/promises';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { FilesystemBlobStore, FilesystemMetadataStore } from '../../storage-filesystem/src/index.js';
import { S3BlobStore } from '../../storage-s3/src/index.js';
import { activateRelease, commitManifest, planManifest, resolveRequestPath } from '../../core/src/index.js';
import { sha256 } from '../../spec/src/index.js';
import { artifactHeaders, securityHeaders } from './security-profile.js';

function json(res,status,body){res.writeHead(status,{'content-type':'application/json; charset=utf-8'});res.end(JSON.stringify(body,null,2));}
async function readJson(req){let raw='';for await(const c of req)raw+=c;return JSON.parse(raw||'{}');}
async function readBytes(req){const chunks=[];for await(const c of req)chunks.push(c);return Buffer.concat(chunks);}
function safeEqualString(a,b){if(typeof a!=='string'||typeof b!=='string'||a.length!==b.length)return false;let x=0;for(let i=0;i<a.length;i++)x|=a.charCodeAt(i)^b.charCodeAt(i);return x===0;}
function uploadSignature(secret,digest,expires){return createHmac('sha256',secret).update(`${digest}\n${expires}`).digest('hex');}
function safeSiteSelector(value){
  return typeof value==='string' && value.length>0 && value!=='.' && value!=='..' && !/[\/\\\0]/.test(value);
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

export function createArtifactServer({blobs,metadata,uploadSecret=randomBytes(32).toString('hex'),publicBaseUrl=null}={}){
  if(!blobs||!metadata)throw new Error('blobs and metadata stores are required');
  return createServer(async(req,res)=>{
    // One host-policy baseline for every application response, including control
    // responses and early errors. No artifact bytes or manifest fields change.
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
      const slug=decodeURIComponent(planMatch[1]); const body=await readJson(req);
      const origin=publicBaseUrl??base;
      const plan=await planManifest({manifest:body.manifest,blobs,uploadFactory:async digest=>{
        if(typeof blobs.createUpload==='function')return blobs.createUpload(digest,{expires:900});
        const expires=Math.floor(Date.now()/1000)+900; const sig=uploadSignature(uploadSecret,digest,expires);
        return {digest,method:'PUT',url:`${origin}/v1/uploads/${encodeURIComponent(digest)}?expires=${expires}&sig=${sig}`,expiresIn:900};
      }});
      if(body.artifactDigest&&body.artifactDigest!==plan.artifactDigest)return json(res,400,{error:'artifactDigest does not match canonical manifest'});
      return json(res,200,{slug,...plan});
    }

    const uploadMatch=url.pathname.match(/^\/v1\/uploads\/(sha256%3A[0-9a-f]{64}|sha256:[0-9a-f]{64})$/i);
    if(req.method==='PUT'&&uploadMatch){
      if(typeof blobs.createUpload==='function')return json(res,404,{error:'direct S3 uploads do not pass through artifactd'});
      const digest=decodeURIComponent(uploadMatch[1]).toLowerCase();
      const expires=Number(url.searchParams.get('expires')); const sig=url.searchParams.get('sig')??'';
      if(!Number.isSafeInteger(expires)||expires<Math.floor(Date.now()/1000))return json(res,403,{error:'upload URL expired'});
      if(!safeEqualString(sig,uploadSignature(uploadSecret,digest,expires)))return json(res,403,{error:'invalid upload signature'});
      const bytes=await readBytes(req); if(sha256(bytes)!==digest)return json(res,400,{error:'blob digest mismatch'});
      await blobs.put(digest,new Uint8Array(bytes)); res.writeHead(204); return res.end();
    }

    const commitMatch=url.pathname.match(/^\/v1\/sites\/([^/]+)\/publish\/commit$/);
    if(req.method==='POST'&&commitMatch){
      const slug=decodeURIComponent(commitMatch[1]); const body=await readJson(req);
      const r=await commitManifest({slug,manifest:body.manifest,expectedArtifactDigest:body.artifactDigest,blobs,metadata,activate:body.activate!==false});
      return json(res,201,{slug:r.site.slug,releaseId:r.release.id,artifactDigest:r.release.artifactDigest,activeReleaseId:r.site.activeReleaseId});
    }

    const a=url.pathname.match(/^\/v1\/sites\/([^/]+)\/activate\/([^/]+)$/);
    if(req.method==='POST'&&a){const r=await activateRelease(metadata,decodeURIComponent(a[1]),decodeURIComponent(a[2]));return json(res,200,{slug:r.site.slug,activeReleaseId:r.release.id});}
    const l=url.pathname.match(/^\/v1\/sites\/([^/]+)\/releases$/);
    if(req.method==='GET'&&l){const site=await metadata.getSite(decodeURIComponent(l[1]));if(!site)return json(res,404,{error:'site not found'});return json(res,200,{site,releases:await metadata.listReleases(site.id)});}

    const host=(req.headers.host??'').split(':')[0];const slug=host.endsWith('.localhost')?host.slice(0,-10):url.searchParams.get('site');
    if((req.method==='GET'||req.method==='HEAD')&&slug){
      // A site selector is one metadata key, never a path. Do not decode again:
      // URLSearchParams already decoded a query selector exactly once.
      if(!safeSiteSelector(slug))return json(res,404,{error:'site or active release not found'});
      const site=await metadata.getSite(slug);if(!site?.activeReleaseId)return json(res,404,{error:'site or active release not found'});
      const release=await metadata.getRelease(site.id,site.activeReleaseId);if(!release)return json(res,404,{error:'release not found'});
      if(release.manifest.lifecycle?.expiresAt&&new Date(release.manifest.lifecycle.expiresAt)<=new Date())return json(res,410,{error:'artifact expired'});
      // URL parsing would erase literal/encoded dot segments before validation.
      // Keep the existing resolver's decode-once behavior on the received path.
      const file=resolveRequestPath(release.manifest,rawPath);if(!file)return json(res,404,{error:'file not found'});
      const body=await blobs.get(file.digest);
      res.writeHead(200,{...artifactHeaders(file.mediaType),'content-length':String(body.byteLength),'etag':`"${file.digest}"`});
      return res.end(req.method==='HEAD'?undefined:Buffer.from(body));
    }
    return json(res,404,{error:'not found'});
  }catch(e){return json(res,500,{error:e instanceof Error?e.message:String(e)});}});
}

async function main(){
  const port=Number(process.env.PORT??7331); const stores=await createDefaultStores(); const server=createArtifactServer(stores);
  server.listen(port,()=>console.log(`artifactd (${stores.storageKind}) listening on http://localhost:${port}`));
}

if(process.argv[1]&&import.meta.url===pathToFileURL(resolve(process.argv[1])).href)await main();
