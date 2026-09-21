import { createHash, createHmac } from 'node:crypto';

function hashHex(data='') { return createHash('sha256').update(data).digest('hex'); }
function hmac(key, data, encoding) { return createHmac('sha256', key).update(data).digest(encoding); }
function amzDate(date) { return date.toISOString().replace(/[:-]|\.\d{3}/g,''); }
function dateStamp(date) { return amzDate(date).slice(0,8); }
function enc(value) { return encodeURIComponent(value).replace(/[!'()*]/g, c => `%${c.charCodeAt(0).toString(16).toUpperCase()}`); }
function encodePath(path) { return path.split('/').map(enc).join('/'); }
/** Base64 SHA-256 of the object bytes, as S3 checksum headers carry it, derived from the CAS digest. */
function checksumFor(digest) { return Buffer.from(digest.slice('sha256:'.length), 'hex').toString('base64'); }
/**
 * Headers a client MUST send with a direct upload grant. Both are SigV4-signed
 * into the presigned URL, so they cannot be dropped or altered; the provider
 * validates the checksum against the actual payload bytes and refuses to
 * overwrite an existing object. Together: a grant can only ever create the one
 * correct object, and a still-valid grant cannot corrupt it after commit.
 */
export function uploadHeadersFor(digest, { repair = false } = {}) {
  const headers = { 'x-amz-checksum-sha256': checksumFor(digest) };
  // A REPAIR grant replaces an object proven corrupt relative to its own key,
  // so create-once is deliberately omitted; the checksum binding stays signed,
  // so even a replayed repair grant can only ever write the one correct object.
  if (!repair) headers['if-none-match'] = '*';
  return headers;
}
function canonicalQuery(params) { return [...params.entries()].sort(([a,av],[b,bv])=>a===b?av.localeCompare(bv):a.localeCompare(b)).map(([k,v])=>`${enc(k)}=${enc(v)}`).join('&'); }

/** Fixed-shape storage failure. Never carries a provider body, URL or credential. */
export class S3OperationError extends Error {
  constructor(code, reason = null) {
    super(`storage operation failed: ${code}`);
    this.name = 'S3OperationError';
    this.code = code;
    this.reason = reason; // Internal attribution ('digest' | 'size'); see core IntegrityError.
  }
}

/** Hosts proven LIVE to validate x-amz-checksum-sha256 against payload bytes. */
const CHECKSUM_ENFORCING_HOSTS = [/\.r2\.cloudflarestorage\.com$/i];
/**
 * Hosts proven LIVE to enforce the COMPLETE direct final-CAS grant contract:
 * the signed x-amz-checksum-sha256 is validated against the payload; a signed
 * header cannot be omitted or altered; If-None-Match: * refuses overwrite on a
 * presigned PUT; and a checksum-only (repair) grant still cannot write bytes
 * that fail the checksum. MinIO was proven too, but an arbitrary MinIO endpoint
 * cannot be recognised from its hostname, so it needs an explicit operator
 * assertion (directUploadIntegrity: 'enforced') after verification.
 */
const DIRECT_UPLOAD_ENFORCING_HOSTS = [/\.r2\.cloudflarestorage\.com$/i];

const XML_NAMED = Object.freeze({ amp: '&', lt: '<', gt: '>', quot: '"', apos: "'" });

/**
 * Decode XML character data strictly. S3 escapes text content, so an opaque
 * continuation token `a&b` arrives as `a&amp;b`; using the escaped bytes as the
 * next token would silently change it. Supports the five XML named entities and
 * decimal/hex character references. Anything else that looks like a reference
 * — an unknown name, a bare `&`, an unterminated or out-of-range reference —
 * is malformed and THROWS rather than being guessed at, so a corrupt listing
 * fails closed instead of driving a wrong request or an endless page loop.
 */
export function decodeXmlText(text) {
  if (typeof text !== 'string') throw new S3OperationError('OWA_GC_LIST_FAILED');
  if (text.includes('<')) throw new S3OperationError('OWA_GC_LIST_FAILED'); // Not character data.
  let out = '';
  for (let i = 0; i < text.length; i++) {
    const ch = text[i];
    if (ch !== '&') { out += ch; continue; }
    const end = text.indexOf(';', i + 1);
    if (end < 0) throw new S3OperationError('OWA_GC_LIST_FAILED');
    const ref = text.slice(i + 1, end);
    if (Object.hasOwn(XML_NAMED, ref)) { out += XML_NAMED[ref]; i = end; continue; }
    const numeric = /^#(?:x([0-9A-Fa-f]{1,6})|([0-9]{1,7}))$/.exec(ref);
    if (!numeric) throw new S3OperationError('OWA_GC_LIST_FAILED');
    const code = numeric[1] !== undefined ? parseInt(numeric[1], 16) : parseInt(numeric[2], 10);
    // XML Char production: no NUL, no surrogates, nothing beyond U+10FFFF.
    if (code === 0 || (code >= 0xD800 && code <= 0xDFFF) || code > 0x10FFFF) throw new S3OperationError('OWA_GC_LIST_FAILED');
    out += String.fromCodePoint(code);
    i = end;
  }
  return out;
}

export class S3BlobStore {
  constructor({endpoint,bucket,region='auto',accessKeyId,secretAccessKey,sessionToken=null,prefix='owa',addressingStyle='path',now=()=>new Date(),checksumEvidence=undefined,directUploadIntegrity=undefined}) {
    if (!endpoint || !bucket || !accessKeyId || !secretAccessKey) throw new Error('S3 endpoint, bucket, accessKeyId, and secretAccessKey are required');
    this.endpoint=endpoint.replace(/\/$/,''); this.bucket=bucket; this.region=region; this.accessKeyId=accessKeyId; this.secretAccessKey=secretAccessKey; this.sessionToken=sessionToken; this.prefix=prefix.replace(/^\/+|\/+$/g,''); this.addressingStyle=addressingStyle; this.now=now;
    if(!['path','virtual'].includes(addressingStyle))throw new Error(`Unsupported S3 addressingStyle: ${addressingStyle}`);
    const hostname=new URL(this.endpoint).hostname;
    // PROVIDER CHECKSUM TRUST BOUNDARY. A returned x-amz-checksum-sha256 is
    // strong proof only if the provider validated it against the bytes it
    // stored. 'enforced' allows the zero-byte HEAD fast path; 'advisory' treats
    // the header as informational and ALWAYS rehashes. Unset selects
    // automatically: only hosts proven live to enforce are 'enforced'; every
    // other endpoint is 'advisory'. Getting this wrong in the safe direction
    // costs bandwidth, never correctness — there is no way to skip verification.
    if(checksumEvidence!==undefined&&!['enforced','advisory'].includes(checksumEvidence))throw new Error(`Unsupported S3 checksumEvidence: ${checksumEvidence}`);
    this.checksumEvidence=checksumEvidence??(CHECKSUM_ENFORCING_HOSTS.some(pattern=>pattern.test(hostname))?'enforced':'advisory');
    // DIRECT-UPLOAD INTEGRITY CAPABILITY. A separate question from the one
    // above: not "can a HEAD checksum replace a rehash?" but "may a publisher
    // hold a presigned grant on a FINAL CAS key at all?". Such a grant outlives
    // commit, so it is safe only where the provider is known to enforce the
    // signed checksum and create-once semantics; on an unknown provider a
    // replay could overwrite a verified, active release. 'enforced' issues
    // direct grants; 'mediated' never does — bytes travel through artifactd,
    // which hashes them before put(). Unset selects automatically: proven hosts
    // are 'enforced'; every other endpoint is 'mediated'. Again the safe
    // direction only costs bandwidth; there is no value that weakens integrity.
    if(directUploadIntegrity!==undefined&&!['enforced','mediated'].includes(directUploadIntegrity))throw new Error(`Unsupported S3 directUploadIntegrity: ${directUploadIntegrity}`);
    this.directUploadIntegrity=directUploadIntegrity??(DIRECT_UPLOAD_ENFORCING_HOSTS.some(pattern=>pattern.test(hostname))?'enforced':'mediated');
  }
  /**
   * Declared capability the server consults before minting ANY publisher-held
   * storage grant. Explicit on purpose: implementing createUpload() is not the
   * same as being allowed to use it.
   */
  canCreateSafeDirectUpload() { return this.directUploadIntegrity==='enforced'; }
  key(digest) { const [algorithm,hex]=digest.split(':'); return `${this.prefix}/blobs/${algorithm}/${hex}`; }
  urlForKey(key) {
    const url=new URL(this.endpoint);
    if(this.addressingStyle==='virtual'){url.hostname=`${this.bucket}.${url.hostname}`;url.pathname=`/${encodePath(key)}`;}
    else url.pathname=`/${enc(this.bucket)}/${encodePath(key)}`;
    return url;
  }
  signingKey(date) { const kDate=hmac(Buffer.from(`AWS4${this.secretAccessKey}`),date); const kRegion=hmac(kDate,this.region); const kService=hmac(kRegion,'s3'); return hmac(kService,'aws4_request'); }
  credentialScope(date) { return `${date}/${this.region}/s3/aws4_request`; }

  /**
   * Presign a request. `headers`, when given, are SIGNED into the grant: the
   * client must send exactly those values or the provider rejects the request
   * with SignatureDoesNotMatch. With no headers the output is byte-identical
   * to the historical host-only presign.
   */
  presign(method,key,{expires=900,headers={}}={}) {
    const now=this.now(), stamp=dateStamp(now), timestamp=amzDate(now), url=this.urlForKey(key);
    const host=url.host, scope=this.credentialScope(stamp);
    const signing={host,...Object.fromEntries(Object.entries(headers).map(([name,value])=>[name.toLowerCase(),String(value).trim()]))};
    const signedNames=Object.keys(signing).sort();
    url.searchParams.set('X-Amz-Algorithm','AWS4-HMAC-SHA256');
    url.searchParams.set('X-Amz-Credential',`${this.accessKeyId}/${scope}`);
    url.searchParams.set('X-Amz-Date',timestamp);
    url.searchParams.set('X-Amz-Expires',String(expires));
    url.searchParams.set('X-Amz-SignedHeaders',signedNames.join(';'));
    if(this.sessionToken) url.searchParams.set('X-Amz-Security-Token',this.sessionToken);
    const canonicalRequest=[method,url.pathname,canonicalQuery(url.searchParams),signedNames.map(name=>`${name}:${signing[name]}\n`).join(''),signedNames.join(';'),'UNSIGNED-PAYLOAD'].join('\n');
    const stringToSign=['AWS4-HMAC-SHA256',timestamp,scope,hashHex(canonicalRequest)].join('\n');
    const signature=hmac(this.signingKey(stamp),stringToSign,'hex');
    url.searchParams.set('X-Amz-Signature',signature);
    return url.toString();
  }

  /**
   * Signed request. `query` is optional and defaults to no query string, so
   * every pre-existing caller signs exactly the same canonical request as
   * before; only GC's ListObjectsV2 passes signed query parameters.
   * `url` overrides the key-derived URL for bucket-level operations.
   */
  async signedFetch(method,key,{body=null,query=null,url:overrideUrl=null,headers:extraHeaders={}}={}) {
    const now=this.now(), stamp=dateStamp(now), timestamp=amzDate(now);
    const url=overrideUrl??this.urlForKey(key);
    const host=url.host;
    // ONE serialization. The canonical query string is both what is signed and
    // what is transmitted, byte for byte. Re-serializing the same logical query
    // through URLSearchParams would use form encoding, where a space becomes
    // "+" while SigV4 signed "%20": a valid signature for a different request.
    const canonicalQueryString=query===null?'':canonicalQuery(query);
    const target=`${url.origin}${url.pathname}${canonicalQueryString?`?${canonicalQueryString}`:''}`;
    const payloadHash=hashHex(body ?? '');
    const signingHeaders={'host':host,'x-amz-content-sha256':payloadHash,'x-amz-date':timestamp};
    // Extra headers are signed AND sent, so they are part of the request contract.
    for(const [name,value] of Object.entries(extraHeaders)) signingHeaders[name.toLowerCase()]=String(value).trim();
    if(this.sessionToken) signingHeaders['x-amz-security-token']=this.sessionToken;
    const signedHeaderNames=Object.keys(signingHeaders).sort();
    const canonicalHeaders=signedHeaderNames.map(name=>`${name}:${signingHeaders[name]}\n`).join('');
    const canonicalRequest=[method,url.pathname,canonicalQueryString,canonicalHeaders,signedHeaderNames.join(';'),payloadHash].join('\n');
    const scope=this.credentialScope(stamp);
    const stringToSign=['AWS4-HMAC-SHA256',timestamp,scope,hashHex(canonicalRequest)].join('\n');
    const signature=hmac(this.signingKey(stamp),stringToSign,'hex');
    const headers={'x-amz-content-sha256':payloadHash,'x-amz-date':timestamp};
    for(const [name,value] of Object.entries(extraHeaders)) headers[name.toLowerCase()]=String(value).trim();
    if(this.sessionToken) headers['x-amz-security-token']=this.sessionToken;
    headers.authorization=`AWS4-HMAC-SHA256 Credential=${this.accessKeyId}/${scope}, SignedHeaders=${signedHeaderNames.join(';')}, Signature=${signature}`;
    return fetch(target,{method,headers,body});
  }

  async has(digest) { const res=await this.signedFetch('HEAD',this.key(digest)); if(res.status===404)return false; if(!res.ok)throw new Error(`S3 HEAD failed: ${res.status} ${await res.text()}`); return true; }
  async get(digest) { const res=await this.signedFetch('GET',this.key(digest)); if(!res.ok)throw new Error(`S3 GET failed: ${res.status} ${await res.text()}`); return new Uint8Array(await res.arrayBuffer()); }
  // Trusted writes also declare the checksum, so the provider validates the
  // bytes and leaves SHA-256 evidence that verifyBlob can later read cheaply.
  async put(digest,data) { const res=await this.signedFetch('PUT',this.key(digest),{body:Buffer.from(data),headers:{'x-amz-checksum-sha256':checksumFor(digest)}}); if(!res.ok)throw new Error(`S3 PUT failed: ${res.status} ${await res.text()}`); }
  /**
   * Direct-upload grant: a presigned PUT on the final CAS key whose SIGNED
   * headers bind it to this digest's checksum and to create-once semantics.
   * The `headers` field tells the client exactly what it must send.
   */
  async createUpload(digest,{expires=900,repair=false}={}) {
    // Fail closed at the store boundary as well as in the server: a mediated
    // store signs no publisher-held grant on a final CAS key, whoever asks.
    if(!this.canCreateSafeDirectUpload()) throw new Error('S3 direct uploads are mediated for this endpoint; bytes must pass through artifactd');
    const headers=uploadHeadersFor(digest,{repair});
    return {digest,method:'PUT',url:this.presign('PUT',this.key(digest),{expires,headers}),expiresIn:expires,headers};
  }

  /**
   * Strong integrity verification (issue #10). One HEAD with checksum mode:
   * a 404 is MISSING; a Content-Length other than the declared size is
   * INTEGRITY; a provider-validated x-amz-checksum-sha256 equal to the expected
   * value is accepted with zero payload transfer. Any other case — no evidence,
   * a composite multipart value, a mismatch — falls through to a definitive
   * streaming GET + SHA-256 of the actual bytes, bounded at the declared size.
   * Provider bodies never surface; failures are fixed codes.
   */
  async verifyBlob({digest,size}={}) {
    if(!/^sha256:[0-9a-f]{64}$/.test(String(digest??''))||!Number.isSafeInteger(size)||size<0) throw new S3OperationError('OWA_BLOB_UNVERIFIED');
    const key=this.key(digest);
    let head;
    try { head=await this.signedFetch('HEAD',key,{headers:{'x-amz-checksum-mode':'ENABLED'}}); await head.arrayBuffer().catch(()=>{}); }
    catch { throw new S3OperationError('OWA_BLOB_UNVERIFIED'); }
    if(head.status===404) throw new S3OperationError('OWA_BLOB_MISSING');
    if(!head.ok) throw new S3OperationError('OWA_BLOB_UNVERIFIED');
    const actualSize=Number(head.headers.get('content-length'));
    if(!Number.isSafeInteger(actualSize)||actualSize<0) throw new S3OperationError('OWA_BLOB_UNVERIFIED');
    // Zero-byte fast path ONLY where the provider is known to have validated
    // the checksum against the stored bytes. Then the object matches its key,
    // and any size disagreement is the submitted manifest's fault, not the
    // object's — never a reason to touch the object.
    if(this.checksumEvidence==='enforced'&&head.headers.get('x-amz-checksum-sha256')===checksumFor(digest)){
      if(actualSize!==size) throw new S3OperationError('OWA_BLOB_INTEGRITY','size');
      return {ok:true,method:'provider-checksum'};
    }
    // Otherwise the header is advisory at best: rehash the ACTUAL object,
    // streamed and bounded by its real length, so a size disagreement can be
    // attributed to the object ('digest') or to the manifest ('size').
    let res;
    try { res=await this.signedFetch('GET',key); } catch { throw new S3OperationError('OWA_BLOB_UNVERIFIED'); }
    if(res.status===404){ await res.arrayBuffer().catch(()=>{}); throw new S3OperationError('OWA_BLOB_MISSING'); }
    if(!res.ok||!res.body){ await res.arrayBuffer().catch(()=>{}); throw new S3OperationError('OWA_BLOB_UNVERIFIED'); }
    const hash=createHash('sha256'); let count=0;
    try {
      for await (const chunk of res.body) {
        count+=chunk.byteLength;
        if(count>actualSize) throw new S3OperationError('OWA_BLOB_UNVERIFIED'); // Changed underneath us.
        hash.update(chunk);
      }
    } catch(error) { throw error instanceof S3OperationError ? error : new S3OperationError('OWA_BLOB_UNVERIFIED'); }
    if(count!==actualSize) throw new S3OperationError('OWA_BLOB_UNVERIFIED');
    if(hash.digest('hex')!==digest.slice('sha256:'.length)) throw new S3OperationError('OWA_BLOB_INTEGRITY','digest');
    if(actualSize!==size) throw new S3OperationError('OWA_BLOB_INTEGRITY','size');
    return {ok:true,method:'rehash'};
  }

  /** Bucket-level URL for operations that address the bucket, not one object. */
  bucketUrl() {
    const url=new URL(this.endpoint);
    if(this.addressingStyle==='virtual'){url.hostname=`${this.bucket}.${url.hostname}`;url.pathname='/';}
    else url.pathname=`/${enc(this.bucket)}`;
    return url;
  }

  /** The exact prefix GC is allowed to see. Nothing outside it is ever a candidate. */
  blobPrefix() { return `${this.prefix}/blobs/sha256/`; }

  /**
   * Enumerate OWA blob objects via ListObjectsV2, confined to blobPrefix().
   *
   * Only keys matching the exact OWA grammar `<prefix>/blobs/sha256/<64 hex>`
   * become results: a neighbouring object, a nested "directory", or a malformed
   * key under the same prefix is ignored rather than returned, so GC can never
   * offer an unrelated bucket object as a candidate. Pagination follows
   * NextContinuationToken until the provider reports the listing complete.
   */
  async listBlobs({maxKeys=1000}={}) {
    const prefix=this.blobPrefix();
    const valid=new RegExp(`^${prefix.replace(/[.*+?^${}()|[\]\\]/g,'\\$&')}[0-9a-f]{64}$`);
    const out=[]; let token=null; let pages=0;
    do {
      const query=new URLSearchParams();
      query.set('list-type','2');
      query.set('max-keys',String(maxKeys));
      query.set('prefix',prefix);
      // The token is signed and transmitted as an ordinary parameter value; the
      // canonical encoder escapes it identically on both sides of the signature.
      if(token!==null) query.set('continuation-token',token);
      let res, text;
      try {
        res=await this.signedFetch('GET',null,{query,url:this.bucketUrl()});
        text=await res.text();
      } catch { throw new S3OperationError('OWA_GC_LIST_FAILED'); }
      // Never surface a provider body: it can echo request details.
      if(!res.ok) throw new S3OperationError('OWA_GC_LIST_FAILED');
      for(const match of text.matchAll(/<Contents>([\s\S]*?)<\/Contents>/g)){
        const part=match[1];
        const rawKey=part.match(/<Key>([^<]*)<\/Key>/)?.[1];
        if(typeof rawKey!=='string')continue;
        // Decode XML escaping BEFORE grammar validation, so a prefix containing
        // an XML-significant character still matches its real object key.
        const key=decodeXmlText(rawKey);
        if(!valid.test(key))continue; // Not an OWA blob.
        const size=Number(part.match(/<Size>([0-9]+)<\/Size>/)?.[1] ?? NaN);
        const modified=new Date(part.match(/<LastModified>([^<]*)<\/LastModified>/)?.[1] ?? NaN);
        if(!Number.isSafeInteger(size)||!Number.isFinite(modified.getTime())) throw new S3OperationError('OWA_GC_LIST_FAILED');
        out.push({digest:`sha256:${key.slice(prefix.length)}`,size,lastModified:modified});
      }
      const truncated=/<IsTruncated>\s*true\s*<\/IsTruncated>/i.test(text);
      const rawToken=truncated?(text.match(/<NextContinuationToken>([^<]*)<\/NextContinuationToken>/)?.[1] ?? null):null;
      if(truncated&&rawToken===null) throw new S3OperationError('OWA_GC_LIST_FAILED');
      // The token is opaque provider data: decode its XML escaping exactly, then
      // hand the ORIGINAL value back as a plain query parameter. A malformed
      // reference throws here, before another request or any deletion.
      token=rawToken===null?null:decodeXmlText(rawToken);
      if(token==='') throw new S3OperationError('OWA_GC_LIST_FAILED');
      if(++pages>10_000) throw new S3OperationError('OWA_GC_LIST_FAILED');
    } while(token!==null);
    return out;
  }

  /**
   * Delete exactly one validated blob key with storage credentials only.
   * An OWA bearer is never involved. Missing objects are idempotent: S3 and R2
   * both answer 204 for an absent key, and 404 is accepted for the same reason.
   */
  async delete(digest) {
    if(!/^sha256:[0-9a-f]{64}$/.test(digest)) throw new S3OperationError('OWA_GC_INVALID_DIGEST');
    let res;
    try { res=await this.signedFetch('DELETE',this.key(digest)); }
    catch { throw new S3OperationError('OWA_GC_DELETE_FAILED'); }
    try { await res.arrayBuffer(); } catch {}
    if(!res.ok&&res.status!==404) throw new S3OperationError('OWA_GC_DELETE_FAILED');
  }
}
