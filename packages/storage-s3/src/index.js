import { createHash, createHmac } from 'node:crypto';

function hashHex(data='') { return createHash('sha256').update(data).digest('hex'); }
function hmac(key, data, encoding) { return createHmac('sha256', key).update(data).digest(encoding); }
function amzDate(date) { return date.toISOString().replace(/[:-]|\.\d{3}/g,''); }
function dateStamp(date) { return amzDate(date).slice(0,8); }
function enc(value) { return encodeURIComponent(value).replace(/[!'()*]/g, c => `%${c.charCodeAt(0).toString(16).toUpperCase()}`); }
function encodePath(path) { return path.split('/').map(enc).join('/'); }
function canonicalQuery(params) { return [...params.entries()].sort(([a,av],[b,bv])=>a===b?av.localeCompare(bv):a.localeCompare(b)).map(([k,v])=>`${enc(k)}=${enc(v)}`).join('&'); }

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

  async signedFetch(method,key,{body=null}={}) {
    const now=this.now(), stamp=dateStamp(now), timestamp=amzDate(now), url=this.urlForKey(key), host=url.host;
    const payloadHash=hashHex(body ?? '');
    const signingHeaders={'host':host,'x-amz-content-sha256':payloadHash,'x-amz-date':timestamp};
    if(this.sessionToken) signingHeaders['x-amz-security-token']=this.sessionToken;
    const signedHeaderNames=Object.keys(signingHeaders).sort();
    const canonicalHeaders=signedHeaderNames.map(name=>`${name}:${signingHeaders[name]}\n`).join('');
    const canonicalRequest=[method,url.pathname,'',canonicalHeaders,signedHeaderNames.join(';'),payloadHash].join('\n');
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
}
