import { createHash, createHmac } from 'node:crypto';

function hashHex(data='') { return createHash('sha256').update(data).digest('hex'); }
function hmac(key, data, encoding) { return createHmac('sha256', key).update(data).digest(encoding); }
function amzDate(date) { return date.toISOString().replace(/[:-]|\.\d{3}/g,''); }
function dateStamp(date) { return amzDate(date).slice(0,8); }
function enc(value) { return encodeURIComponent(value).replace(/[!'()*]/g, c => `%${c.charCodeAt(0).toString(16).toUpperCase()}`); }
function encodePath(path) { return path.split('/').map(enc).join('/'); }
function canonicalQuery(params) { return [...params.entries()].sort(([a,av],[b,bv])=>a===b?av.localeCompare(bv):a.localeCompare(b)).map(([k,v])=>`${enc(k)}=${enc(v)}`).join('&'); }

/** Fixed-shape storage failure. Never carries a provider body, URL or credential. */
export class S3OperationError extends Error {
  constructor(code) {
    super(`storage operation failed: ${code}`);
    this.name = 'S3OperationError';
    this.code = code;
  }
}

export class S3BlobStore {
  constructor({endpoint,bucket,region='auto',accessKeyId,secretAccessKey,sessionToken=null,prefix='owa',addressingStyle='path',now=()=>new Date()}) {
    if (!endpoint || !bucket || !accessKeyId || !secretAccessKey) throw new Error('S3 endpoint, bucket, accessKeyId, and secretAccessKey are required');
    this.endpoint=endpoint.replace(/\/$/,''); this.bucket=bucket; this.region=region; this.accessKeyId=accessKeyId; this.secretAccessKey=secretAccessKey; this.sessionToken=sessionToken; this.prefix=prefix.replace(/^\/+|\/+$/g,''); this.addressingStyle=addressingStyle; this.now=now;
    if(!['path','virtual'].includes(addressingStyle))throw new Error(`Unsupported S3 addressingStyle: ${addressingStyle}`);
  }
  key(digest) { const [algorithm,hex]=digest.split(':'); return `${this.prefix}/blobs/${algorithm}/${hex}`; }
  urlForKey(key) {
    const url=new URL(this.endpoint);
    if(this.addressingStyle==='virtual'){url.hostname=`${this.bucket}.${url.hostname}`;url.pathname=`/${encodePath(key)}`;}
    else url.pathname=`/${enc(this.bucket)}/${encodePath(key)}`;
    return url;
  }
  signingKey(date) { const kDate=hmac(Buffer.from(`AWS4${this.secretAccessKey}`),date); const kRegion=hmac(kDate,this.region); const kService=hmac(kRegion,'s3'); return hmac(kService,'aws4_request'); }
  credentialScope(date) { return `${date}/${this.region}/s3/aws4_request`; }

  presign(method,key,{expires=900}={}) {
    const now=this.now(), stamp=dateStamp(now), timestamp=amzDate(now), url=this.urlForKey(key);
    const host=url.host, scope=this.credentialScope(stamp);
    url.searchParams.set('X-Amz-Algorithm','AWS4-HMAC-SHA256');
    url.searchParams.set('X-Amz-Credential',`${this.accessKeyId}/${scope}`);
    url.searchParams.set('X-Amz-Date',timestamp);
    url.searchParams.set('X-Amz-Expires',String(expires));
    url.searchParams.set('X-Amz-SignedHeaders','host');
    if(this.sessionToken) url.searchParams.set('X-Amz-Security-Token',this.sessionToken);
    const canonicalRequest=[method,url.pathname,canonicalQuery(url.searchParams),`host:${host}\n`,'host','UNSIGNED-PAYLOAD'].join('\n');
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
  async signedFetch(method,key,{body=null,query=null,url:overrideUrl=null}={}) {
    const now=this.now(), stamp=dateStamp(now), timestamp=amzDate(now);
    const url=overrideUrl??this.urlForKey(key);
    const host=url.host;
    // Canonical query must be sorted and RFC3986-encoded independently of the
    // URL's own serialization, which escapes a different character set.
    const canonicalQueryString=query===null?'':canonicalQuery(query);
    if(query!==null){ url.search=''; for(const [name,value] of query.entries()) url.searchParams.append(name,value); }
    const payloadHash=hashHex(body ?? '');
    const signingHeaders={'host':host,'x-amz-content-sha256':payloadHash,'x-amz-date':timestamp};
    if(this.sessionToken) signingHeaders['x-amz-security-token']=this.sessionToken;
    const signedHeaderNames=Object.keys(signingHeaders).sort();
    const canonicalHeaders=signedHeaderNames.map(name=>`${name}:${signingHeaders[name]}\n`).join('');
    const canonicalRequest=[method,url.pathname,canonicalQueryString,canonicalHeaders,signedHeaderNames.join(';'),payloadHash].join('\n');
    const scope=this.credentialScope(stamp);
    const stringToSign=['AWS4-HMAC-SHA256',timestamp,scope,hashHex(canonicalRequest)].join('\n');
    const signature=hmac(this.signingKey(stamp),stringToSign,'hex');
    const headers={'x-amz-content-sha256':payloadHash,'x-amz-date':timestamp};
    if(this.sessionToken) headers['x-amz-security-token']=this.sessionToken;
    headers.authorization=`AWS4-HMAC-SHA256 Credential=${this.accessKeyId}/${scope}, SignedHeaders=${signedHeaderNames.join(';')}, Signature=${signature}`;
    return fetch(url,{method,headers,body});
  }

  async has(digest) { const res=await this.signedFetch('HEAD',this.key(digest)); if(res.status===404)return false; if(!res.ok)throw new Error(`S3 HEAD failed: ${res.status} ${await res.text()}`); return true; }
  async get(digest) { const res=await this.signedFetch('GET',this.key(digest)); if(!res.ok)throw new Error(`S3 GET failed: ${res.status} ${await res.text()}`); return new Uint8Array(await res.arrayBuffer()); }
  async put(digest,data) { const res=await this.signedFetch('PUT',this.key(digest),{body:Buffer.from(data)}); if(!res.ok)throw new Error(`S3 PUT failed: ${res.status} ${await res.text()}`); }
  async createUpload(digest,{expires=900}={}) { return {digest,method:'PUT',url:this.presign('PUT',this.key(digest),{expires}),expiresIn:expires}; }

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
        const key=part.match(/<Key>([^<]*)<\/Key>/)?.[1];
        if(typeof key!=='string'||!valid.test(key))continue; // Not an OWA blob.
        const size=Number(part.match(/<Size>([0-9]+)<\/Size>/)?.[1] ?? NaN);
        const modified=new Date(part.match(/<LastModified>([^<]*)<\/LastModified>/)?.[1] ?? NaN);
        if(!Number.isSafeInteger(size)||!Number.isFinite(modified.getTime())) throw new S3OperationError('OWA_GC_LIST_FAILED');
        out.push({digest:`sha256:${key.slice(prefix.length)}`,size,lastModified:modified});
      }
      const truncated=/<IsTruncated>\s*true\s*<\/IsTruncated>/i.test(text);
      token=truncated?(text.match(/<NextContinuationToken>([^<]*)<\/NextContinuationToken>/)?.[1] ?? null):null;
      if(truncated&&token===null) throw new S3OperationError('OWA_GC_LIST_FAILED');
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
