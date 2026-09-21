import { createHmac, randomBytes, timingSafeEqual } from 'node:crypto';
import { createServer } from 'node:http';
import { mkdir } from 'node:fs/promises';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { FilesystemBlobStore, FilesystemLeaseStore, FilesystemMetadataStore } from '../../storage-filesystem/src/index.js';
import { S3BlobStore } from '../../storage-s3/src/index.js';
import { IntegrityError, activateRelease, commitManifest, planManifest, resolveRequestPath } from '../../core/src/index.js';
import { sha256 } from '../../spec/src/index.js';
import { AuthError, createAuthorizer, isSiteScope } from './auth.js';
import { artifactHeaders, securityHeaders } from './security-profile.js';
import { ContentHostError, canonicalContentUrl, createHostBinding } from './content-host.js';

// Paths the content origin must never treat as artifact content, even via SPA
// fallback. Keeping this explicit stops a future control route from silently
// becoming reachable (or being masked by a 200) on the public origin.
const CONTROL_RESERVED_PATH = /^\/(?:v1(?:\/|(?![\s\S]))|health(?![\s\S]))/;

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
  // Operational GC state. Lives beside metadata, never inside an artifact.
  const leases=new FilesystemLeaseStore(dataDir);
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
    return {blobs,metadata,leases,storageKind:'s3'};
  }
  return {blobs:new FilesystemBlobStore(dataDir),metadata,leases,storageKind:'filesystem'};
}

/**
 * Shared request logic for every listener. Business logic lives here exactly
 * once; the exported factories below differ only in which dispatchers they
 * expose on an HTTP origin. See docs/origins.md for the route matrix.
 */
function createRuntime({blobs,metadata,leases=null,uploadSecret=randomBytes(32).toString('hex'),publicBaseUrl=null,auth={},audit=null,content=null}={}){
  if(!blobs||!metadata)throw new Error('blobs and metadata stores are required');
  const authorizer = createAuthorizer(auth); // Required by default; missing secret fails closed.
  if (audit !== null && typeof audit !== 'function') throw new AuthError('OWA_AUTH_CONFIG');
  if (typeof uploadSecret !== 'string' && !Buffer.isBuffer(uploadSecret)) throw new AuthError('OWA_AUTH_CONFIG');
  if (Buffer.byteLength(uploadSecret) < (authorizer.mode === 'required' ? 32 : 1)) throw new AuthError('OWA_AUTH_CONFIG');
  if (authorizer.mode === 'required' && Buffer.from(uploadSecret).equals(Buffer.from(auth.secret))) throw new AuthError('OWA_AUTH_CONFIG');
  // Copy this key too; it is independent of the bearer-signing key.
  const localKey = Buffer.from(uploadSecret);

  // Content-origin configuration is operator input only. It is validated once,
  // here, so a request can never introduce or widen a host->site binding.
  let binding = null, contentScheme = 'https', contentPort = null;
  if (content !== null) {
    if (typeof content !== 'object' || Array.isArray(content)) throw new AuthError('OWA_AUTH_CONFIG');
    binding = createHostBinding(content);
    contentScheme = content.scheme ?? 'https';
    contentPort = content.port ?? null;
    if (contentScheme !== 'http' && contentScheme !== 'https') throw new AuthError('OWA_AUTH_CONFIG');
    if (contentPort !== null && (!Number.isSafeInteger(contentPort) || contentPort < 1 || contentPort > 65535)) throw new AuthError('OWA_AUTH_CONFIG');
  }

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

  /**
   * Control plane. Unchanged from the shared-origin prototype: same routes, same
   * capability checks, same fixed error bodies, same activation default.
   */
  async function controlDispatch(req,res,url,rawPath,base){
    if(req.method==='GET'&&url.pathname==='/health'){json(res,200,{ok:true,spec:'owa.dev/v1'});return true;}

    const planMatch=url.pathname.match(/^\/v1\/sites\/([^/]+)\/publish\/plan$/);
    if(req.method==='POST'&&planMatch){
      const slug=routeSite(planMatch[1]);
      if (!slug) { json(res,400,{error:'Invalid site scope',code:'OWA_INVALID_SITE'}); return true; }
      authorize(req,slug,['plan']);
      const body=await readJson(req);
      authorize(req,slug,['plan']); // A slow body cannot extend authorization.
      const origin=publicBaseUrl??base;
      // `leases` is operational only: it changes no request or response field.
      const plan=await planManifest({manifest:body.manifest,blobs,leases,uploadFactory:async digest=>{
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
      if(body.artifactDigest&&body.artifactDigest!==plan.artifactDigest){json(res,400,{error:'artifactDigest does not match canonical manifest'});return true;}
      auditOperation(req,'plan');
      json(res,200,{slug,...plan});return true;
    }

    const uploadMatch=url.pathname.match(/^\/v1\/uploads\/(sha256%3A[0-9a-f]{64}|sha256:[0-9a-f]{64})$/i);
    if(req.method==='PUT'&&uploadMatch){
      if(typeof blobs.createUpload==='function'){json(res,404,{error:'direct S3 uploads do not pass through artifactd'});return true;}
      const scoped=authorizer.mode==='required';
      const sites=url.searchParams.getAll('site');
      if (scoped && (sites.length!==1 || !isSiteScope(sites[0]))) { json(res,400,{error:'Invalid upload scope',code:'OWA_INVALID_SITE'}); return true; }
      if (!scoped && sites.length) { json(res,400,{error:'Invalid upload scope',code:'OWA_INVALID_SITE'}); return true; }
      // Legacy local grants are usable only in explicitly selected loopback dev.
      authorize(req,scoped?sites[0]:'local',['upload']);
      const digest=decodeURIComponent(uploadMatch[1]).toLowerCase();
      const expiresValues=url.searchParams.getAll('expires'), signatures=url.searchParams.getAll('sig');
      const rawExpires=expiresValues[0], expires=Number(rawExpires);
      if(expiresValues.length!==1 || !/^[0-9]+(?![\s\S])/.test(rawExpires??'') || !Number.isSafeInteger(expires) || expires<=authorizer.now()){json(res,403,{error:'Upload grant expired or invalid',code:'OWA_UPLOAD_INVALID'});return true;}
      if(signatures.length!==1 || !validUploadSignature(signatures[0],uploadSignature(localKey,digest,expires,scoped?sites[0]:null))){json(res,403,{error:'Invalid upload signature',code:'OWA_UPLOAD_INVALID'});return true;}
      const bytes=await readBytes(req);
      authorize(req,scoped?sites[0]:'local',['upload']); // Recheck after receiving a slow body.
      if (expires<=authorizer.now()) { json(res,403,{error:'Upload grant expired or invalid',code:'OWA_UPLOAD_INVALID'}); return true; }
      if(sha256(bytes)!==digest){json(res,400,{error:'blob digest mismatch'});return true;}
      await blobs.put(digest,new Uint8Array(bytes)); auditOperation(req,'upload'); res.writeHead(204); res.end(); return true;
    }

    const commitMatch=url.pathname.match(/^\/v1\/sites\/([^/]+)\/publish\/commit$/);
    if(req.method==='POST'&&commitMatch){
      const slug=routeSite(commitMatch[1]);
      if (!slug) { json(res,400,{error:'Invalid site scope',code:'OWA_INVALID_SITE'}); return true; }
      authorize(req,slug,['commit']);
      const body=await readJson(req);
      const activate=body.activate!==false; // Preserve the existing activation default.
      authorize(req,slug,activate?['commit','activate']:['commit']);
      safeSiteRecord(await metadata.getSite(slug),slug);
      const r=await commitManifest({slug,manifest:body.manifest,expectedArtifactDigest:body.artifactDigest,blobs,metadata,activate});
      auditOperation(req,'commit');
      // Canonical public URL, derived only from validated server configuration and
      // the authorized slug. Never client input; never persisted in the manifest;
      // omitted entirely when no content origin is configured.
      const contentUrl=canonicalContentUrl(binding,r.site.slug,{scheme:contentScheme,port:contentPort});
      json(res,201,{slug:r.site.slug,releaseId:r.release.id,artifactDigest:r.release.artifactDigest,activeReleaseId:r.site.activeReleaseId,
        ...(contentUrl===null?{}:{contentUrl})});
      return true;
    }

    const a=url.pathname.match(/^\/v1\/sites\/([^/]+)\/activate\/([^/]+)$/);
    if(req.method==='POST'&&a){
      const slug=routeSite(a[1]);
      if (!slug) { json(res,400,{error:'Invalid site scope',code:'OWA_INVALID_SITE'}); return true; }
      authorize(req,slug,['activate']);
      let releaseId;
      try { releaseId=decodeURIComponent(a[2]); } catch { json(res,400,{error:'Invalid release identifier'}); return true; }
      if (!/^r_[0-9a-f]{20}(?![\s\S])/.test(releaseId)) { json(res,400,{error:'Invalid release identifier'}); return true; }
      safeSiteRecord(await metadata.getSite(slug),slug);
      const r=await activateRelease(metadata,slug,releaseId); auditOperation(req,'activate');
      json(res,200,{slug:r.site.slug,activeReleaseId:r.release.id});return true;
    }
    const l=url.pathname.match(/^\/v1\/sites\/([^/]+)\/releases$/);
    if(req.method==='GET'&&l){
      const slug=routeSite(l[1]);
      if (!slug) { json(res,400,{error:'Invalid site scope',code:'OWA_INVALID_SITE'}); return true; }
      authorize(req,slug,['read']);
      const site=safeSiteRecord(await metadata.getSite(slug),slug);
      if(!site){json(res,404,{error:'site not found'});return true;}
      const releases=await metadata.listReleases(site.id); auditOperation(req,'read');
      json(res,200,{site,releases});return true;
    }
    return false;
  }

  /**
   * Serve one already-selected site. The caller decides which site; this never
   * reads Host or query input, so selection and path resolution stay independent.
   */
  async function serveSite(req,res,slug,rawPath){
    if (!isSiteScope(slug)) { json(res,404,{error:'site or active release not found'}); return true; }
    const site=safeSiteRecord(await metadata.getSite(slug),slug);
    if(!site?.activeReleaseId){json(res,404,{error:'site or active release not found'});return true;}
    if (!/^r_[0-9a-f]{20}(?![\s\S])/.test(site.activeReleaseId)) throw new Error('Invalid active release');
    const release=await metadata.getRelease(site.id,site.activeReleaseId);
    if(!release){json(res,404,{error:'release not found'});return true;}
    if(release.manifest.lifecycle?.expiresAt&&new Date(release.manifest.lifecycle.expiresAt)<=new Date()){json(res,410,{error:'artifact expired'});return true;}
    // Preserve the raw artifact pathname for the unchanged decode-once resolver;
    // WHATWG URL parsing must not erase traversal before its checks.
    const file=resolveRequestPath(release.manifest,rawPath);
    if(!file){json(res,404,{error:'file not found'});return true;}
    const body=await blobs.get(file.digest);
    res.writeHead(200,{...artifactHeaders(file.mediaType),'content-length':String(body.byteLength),'etag':`"${file.digest}"`});
    res.end(req.method==='HEAD'?undefined:Buffer.from(body));
    return true;
  }

  /** Prototype shared-origin selection: `.localhost` host, else the `?site=` query. */
  async function legacyContentDispatch(req,res,url,rawPath){
    const host=(req.headers.host??'').split(':')[0];
    const slug=host.endsWith('.localhost')?host.slice(0,-10):url.searchParams.get('site');
    if((req.method==='GET'||req.method==='HEAD')&&slug) return serveSite(req,res,slug,rawPath);
    return false;
  }

  /**
   * Production content origin: GET/HEAD only, one Host-bound site, no query
   * selector, and no control route reachable even as an SPA fallback.
   */
  async function contentDispatch(req,res,url,rawPath){
    // Allowlist first, and answer every non-content request with the SAME fixed
    // 404. A 405 here would confirm which paths and methods the control plane
    // implements, so the content origin deliberately reveals no method surface.
    if(CONTROL_RESERVED_PATH.test(rawPath)||(req.method!=='GET'&&req.method!=='HEAD')){json(res,404,{error:'not found'});return true;}
    // Host is the ONLY site selector here; `?site=` is inert and cannot override it.
    const slug=binding.resolve(req.headers.host);
    return serveSite(req,res,slug,rawPath);
  }

  return {authorizer,binding,controlDispatch,legacyContentDispatch,contentDispatch,
    contentUrlFor:slug=>canonicalContentUrl(binding,slug,{scheme:contentScheme,port:contentPort})};
}

/** Wrap a dispatcher in the shared framing, profile and fixed-error contract. */
function createListener(dispatch){
  return createServer(async(req,res)=>{
    // Install the profile before every route and auth failure. Auth's challenge
    // and no-store fields are added normally; this never replaces all headers.
    for (const [name,value] of Object.entries(securityHeaders())) res.setHeader(name,value);
    try{
      const target=req.url??'/';
      if(!target.startsWith('/')||target.includes('#'))return json(res,400,{error:'Invalid request target'});
      const queryIndex=target.indexOf('?');
      const rawPath=queryIndex<0?target:target.slice(0,queryIndex);
      // A hostile Host (bad port, brackets, control bytes) must not make URL
      // construction throw into the generic 500 branch and hide the real reason.
      // Parsing falls back to an inert base; Host-based decisions never use it.
      let base;
      try {
        base=new URL(`http://${req.headers.host??'localhost'}`).origin;
        if(base==='null')base='http://invalid.invalid';
      } catch { base='http://invalid.invalid'; }
      const url=new URL(target,base);
      if(await dispatch(req,res,url,rawPath,base))return;
      return json(res,404,{error:'not found'});
    }catch(e){
      if (e instanceof AuthError) {
        if (e.status===401) res.setHeader('www-authenticate','Bearer realm="owa"');
        res.setHeader('cache-control','no-store');
        return json(res,e.status,{error:e.message,code:e.code});
      }
      // Fixed Host-binding failures. The body never echoes the received Host.
      if (e instanceof ContentHostError) return json(res,e.status,{error:e.message,code:e.code});
      // Fixed integrity vocabulary only. The body never carries a storage key,
      // path, provider body, signed URL or credential; OWA_BLOB_MISSING keeps
      // its historical shape.
      if (e instanceof IntegrityError) {
        const message = e.code === 'OWA_BLOB_MISSING' ? 'Missing blob'
          : e.code === 'OWA_BLOB_INTEGRITY' ? 'Blob integrity check failed' : 'Blob integrity could not be verified';
        return json(res,500,{error:message,code:e.code});
      }
      // Only a fixed, recognized core failure is surfaced; provider errors and
      // nested causes can contain presigned URLs and must never be reflected.
      if (e instanceof Error && /^Missing blob sha256:[0-9a-f]{64}(?![\s\S])/.test(e.message)) return json(res,500,{error:'Missing blob',code:'OWA_BLOB_MISSING'});
      return json(res,500,{error:'Operation failed',code:'OWA_OPERATION_FAILED'});
    }
  });
}

/**
 * Prototype/dev server: control plane AND content on ONE origin, with the
 * `?site=`/`.localhost` selector. Unchanged behavior, but it is explicitly not
 * the production topology; see createControlServer/createContentServer.
 */
export function createArtifactServer(options={}){
  const runtime=createRuntime(options);
  return createListener(async(req,res,url,rawPath,base)=>
    await runtime.controlDispatch(req,res,url,rawPath,base) || await runtime.legacyContentDispatch(req,res,url,rawPath));
}

/**
 * Control origin: authenticated publishing, activation, release listing, health.
 * Serves no artifact content, so a hostile artifact never shares this origin.
 */
export function createControlServer(options={}){
  const runtime=createRuntime(options);
  return createListener((req,res,url,rawPath,base)=>runtime.controlDispatch(req,res,url,rawPath,base));
}

/**
 * Content origin: public artifact GET/HEAD for exactly the Host-bound site.
 * Requires content host configuration and never authenticates a request.
 */
export function createContentServer({blobs,metadata,content}={}){
  if(content===null||content===undefined)throw new AuthError('OWA_AUTH_CONFIG');
  // Content serving is public by construction: no bearer, no upload key, and no
  // control routes exist on this listener, so dev auth mode is irrelevant here.
  const runtime=createRuntime({blobs,metadata,content,uploadSecret:randomBytes(32).toString('hex'),auth:{mode:'dev'}});
  return createListener((req,res,url,rawPath)=>runtime.contentDispatch(req,res,url,rawPath));
}

/**
 * Read content-origin configuration from the environment. Returns null when no
 * content origin is configured, which selects the legacy shared-origin topology.
 * Nothing here is ever derived from a request; see docs/origins.md.
 */
export function contentConfigFromEnv(env=process.env){
  const baseDomain=env.OWA_CONTENT_BASE_DOMAIN??null;
  const rawMap=env.OWA_CONTENT_HOST_MAP??null;
  if(baseDomain===null&&rawMap===null)return null;
  let hosts=null;
  if(rawMap!==null){
    // A malformed map must fail startup, never silently bind nothing.
    try { hosts=JSON.parse(rawMap); } catch { throw new AuthError('OWA_AUTH_CONFIG'); }
  }
  const rawPort=env.OWA_CONTENT_PUBLIC_PORT;
  return {
    baseDomain,
    hosts,
    scheme:env.OWA_CONTENT_SCHEME??'https',
    port:rawPort===undefined||rawPort===''?null:Number(rawPort)
  };
}

// Exactly this text, so operators and tests can match it without parsing prose.
export const SHARED_ORIGIN_WARNING='artifactd: no content origin configured; serving control and content on one origin with the prototype query selector. See docs/origins.md.';
export const STARTUP_ABORTED='artifactd: startup aborted; no listener is running.';

/** Fixed-shape startup failure. Carries labels only: never a cause, path or errno. */
export class ListenerStartupError extends Error {
  constructor(labels) {
    super('artifactd: listener startup failed');
    this.name = 'ListenerStartupError';
    this.labels = Object.freeze([...labels]);
  }
}

/** Reject anything node would silently reinterpret, e.g. NaN becoming a random port. */
function listenPort(value, fallback) {
  const raw = value === undefined || value === '' ? fallback : value;
  const port = Number(raw);
  // Canonical decimal only: no surrounding whitespace, sign, hex or leading zero.
  if (!Number.isSafeInteger(port) || port < 0 || port > 65535 || String(port) !== String(raw)) {
    throw new AuthError('OWA_AUTH_CONFIG');
  }
  return port;
}

/** Close a listener without emitting secondary teardown noise. Never rejects. */
function closeQuietly(server) {
  return new Promise(resolve => {
    if (!server.listening) return resolve();
    server.on('error', () => {}); // A cleanup-time error must not mask the real one.
    try { server.closeAllConnections?.(); } catch {}
    try { server.close(() => resolve()); } catch { resolve(); }
  });
}

/**
 * Start every listener as ONE unit.
 *
 * The separated control/content topology is a single deployment: a process with
 * only one of the two bound is not a degraded server, it is a broken security
 * boundary (a reachable control plane with no content origin, or content with no
 * way to publish). So each binding is attempted, ALL outcomes are awaited, and if
 * any listener failed every listener that did bind is closed again before this
 * throws. Readiness is announced only once every listener is bound.
 */
export async function startListenerGroup(entries, { onReady = null, log = console } = {}) {
  const results = await Promise.all(entries.map(entry => new Promise(resolve => {
    let settled = false;
    const finish = ok => { if (!settled) { settled = true; resolve({ entry, ok }); } };
    // Attach before listen so a synchronous bind failure cannot escape as an
    // unhandled 'error' event and kill the process before cleanup runs.
    entry.server.once('error', () => finish(false));
    try { entry.server.listen(entry.port, entry.host, () => finish(true)); } catch { finish(false); }
  })));

  const failed = results.filter(result => !result.ok);
  if (failed.length) {
    for (const { entry } of failed) log.error(`${entry.label} failed to bind`);
    // Nothing may stay open: process.exitCode alone would leave the event loop
    // alive on the listener that did bind, and artifactd would keep serving.
    await Promise.all(results.map(result => closeQuietly(result.entry.server)));
    log.error(STARTUP_ABORTED);
    throw new ListenerStartupError(failed.map(result => result.entry.label));
  }

  for (const { entry } of results) {
    // Post-startup: the group stays one unit. A later listener error closes the
    // whole group rather than leaving half a topology serving.
    entry.server.on('error', () => {
      log.error(`${entry.label} listener error`);
      process.exitCode = 1;
      for (const other of results) void closeQuietly(other.entry.server);
    });
    onReady?.(entry);
  }
  return results.map(result => result.entry);
}

async function main(){
  const mode=process.argv.includes('--dev')?'dev':(process.env.OWA_AUTH_MODE??'required');
  const auth={mode,secret:process.env.OWA_AUTH_SECRET};
  createAuthorizer(auth); // Fail before opening storage or a listener.
  const content=contentConfigFromEnv();
  const stores=await createDefaultStores();
  const controlPort=listenPort(process.env.OWA_CONTROL_PORT??process.env.PORT,7331);
  const controlHost=mode==='dev'?'127.0.0.1':(process.env.OWA_CONTROL_HOST??process.env.HOST??'127.0.0.1');
  const listeners=[];

  if(content===null){
    // Legacy prototype topology: control and content share ONE origin and the
    // `?site=` selector is live. Announce it; this must never be mistaken for
    // the production boundary, which requires a configured content origin.
    const server=createArtifactServer({...stores,auth,publicBaseUrl:process.env.OWA_PUBLIC_BASE_URL??null});
    listeners.push({label:'artifactd',server,port:controlPort,host:controlHost});
    // One fixed line on stderr. The readiness line on stdout is unchanged, so
    // existing supervisors keep working, but the weaker topology is never silent.
    console.warn(SHARED_ORIGIN_WARNING);
  } else {
    const contentPort=listenPort(process.env.OWA_CONTENT_LISTEN_PORT,7332);
    const contentHost=mode==='dev'?'127.0.0.1':(process.env.OWA_CONTENT_LISTEN_HOST??process.env.HOST??'127.0.0.1');
    // Reject an identical bind pair up front. Racing two listeners for one
    // address would otherwise make which one "wins" nondeterministic, and the
    // surviving half would be exactly the partial topology we refuse to run.
    if(controlHost===contentHost&&controlPort===contentPort&&controlPort!==0){
      console.error('artifactd: control and content listeners are configured on the same host and port');
      throw new ListenerStartupError(['artifactd control','artifactd content']);
    }
    listeners.push({label:'artifactd control',server:createControlServer({...stores,auth,content,publicBaseUrl:process.env.OWA_PUBLIC_BASE_URL??null}),port:controlPort,host:controlHost});
    listeners.push({label:'artifactd content',server:createContentServer({...stores,content}),port:contentPort,host:contentHost});
  }

  // Readiness is emitted only after EVERY listener has bound.
  await startListenerGroup(listeners,{
    onReady:entry=>console.log(`${entry.label} (${stores.storageKind}, auth ${mode}) listening on port ${entry.server.address().port}`)
  });
}

if(process.argv[1]&&import.meta.url===pathToFileURL(resolve(process.argv[1])).href){
  try { await main(); } catch (error) {
    // A bind failure has already reported itself in fixed terms and closed every
    // listener; do not mislabel it as an auth/storage problem. Either way only a
    // fixed string is printed: no cause, errno, path, stack or secret.
    if (!(error instanceof ListenerStartupError)) console.error('artifactd startup failed; check authentication and storage configuration');
    process.exitCode=1;
  }
}
