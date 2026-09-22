import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { artifactDigest, canonicalJson, OWA_MEDIA_TYPE, owaError, parseJsonText, sha256, validateManifest } from '../../spec/src/index.js';

export const OCI_IMAGE_MANIFEST = 'application/vnd.oci.image.manifest.v1+json';
export const OCI_IMAGE_INDEX = 'application/vnd.oci.image.index.v1+json';
export const OCI_LAYOUT_VERSION = '1.0.0';
export const OCI_FALLBACK_MEDIA_TYPE = 'application/octet-stream';
// The OCI image-spec descriptor `mediaType` grammar (RFC 6838 type/subtype, the
// pattern the image-spec JSON schema and registries such as Zot enforce).
const OCI_DESCRIPTOR_MEDIA_TYPE = /^[A-Za-z0-9][A-Za-z0-9!#$&^_.+-]{0,126}\/[A-Za-z0-9][A-Za-z0-9!#$&^_.+-]{0,126}$/;

/**
 * Transport-local mapping from an OWA `file.mediaType` to the OCI layer
 * DESCRIPTOR media type. An OWA mediaType is an arbitrary nonempty string that
 * may carry parameters (`text/html; charset=utf-8`); an OCI descriptor mediaType
 * must be a bare RFC 6838 type/subtype. So: take the part before the first `;`,
 * trim ASCII SP/HTAB, and use it verbatim when it satisfies the descriptor
 * grammar; otherwise use application/octet-stream. This is representation only:
 * the canonical OWA manifest in the OCI config blob remains the sole source of
 * the full, exact `file.mediaType`, and import reads it from there unchanged.
 */
export function ociLayerMediaType(fileMediaType) {
  if (typeof fileMediaType !== 'string') return OCI_FALLBACK_MEDIA_TYPE;
  const semicolon = fileMediaType.indexOf(';');
  const candidate = (semicolon === -1 ? fileMediaType : fileMediaType.slice(0, semicolon)).replace(/^[ \t]+|[ \t]+$/g, '');
  return OCI_DESCRIPTOR_MEDIA_TYPE.test(candidate) ? candidate : OCI_FALLBACK_MEDIA_TYPE;
}

function bytes(value) { return Buffer.isBuffer(value) ? value : Buffer.from(value); }
function digestPath(root,digest){const [algorithm,hex]=digest.split(':');return join(root,'blobs',algorithm,hex);}
async function writeBlob(root,digest,data){const body=bytes(data);if(sha256(body)!==digest)throw owaError('OWA_CONTENT_DIGEST_MISMATCH', `Blob bytes do not match ${digest}`);const path=digestPath(root,digest);await mkdir(join(root,'blobs','sha256'),{recursive:true});await writeFile(path,body);}
async function readVerifiedBlob(root,digest,size=null){const body=await readFile(digestPath(root,digest));if(sha256(body)!==digest)throw owaError('OWA_CONTENT_DIGEST_MISMATCH', `OCI blob digest mismatch: ${digest}`);if(size!=null&&body.byteLength!==size)throw owaError('OWA_CONTENT_SIZE_MISMATCH', `OCI blob size mismatch: ${digest}`);return body;}
async function sourceGet(source,digest){if(source instanceof Map){const value=source.get(digest);if(!value)throw new Error(`Source blob missing: ${digest}`);return value;}return source.get(digest);}

export async function writeOciLayout({manifest,blobs,output,ref='latest'}){
  validateManifest(manifest);
  const root=output;
  await mkdir(join(root,'blobs','sha256'),{recursive:true});
  await writeFile(join(root,'oci-layout'),JSON.stringify({imageLayoutVersion:OCI_LAYOUT_VERSION}));

  const configBytes=Buffer.from(canonicalJson(manifest),'utf8');
  const configDigest=artifactDigest(manifest);
  await writeBlob(root,configDigest,configBytes);

  const layers=[];
  for(const file of manifest.files){
    const body=await sourceGet(blobs,file.digest);
    if(body.byteLength!==file.size)throw owaError('OWA_CONTENT_SIZE_MISMATCH', `Source blob size mismatch for ${file.path}`);
    await writeBlob(root,file.digest,body);
    layers.push({
      // Descriptor media type only; the full OWA value lives in the config blob.
      mediaType:ociLayerMediaType(file.mediaType),
      digest:file.digest,
      size:file.size,
      annotations:{
        'org.opencontainers.image.title':file.path.replace(/^\//,''),
        'dev.openwebartifact.path':file.path
      }
    });
  }

  const ociManifest={
    schemaVersion:2,
    mediaType:OCI_IMAGE_MANIFEST,
    artifactType:OWA_MEDIA_TYPE,
    config:{mediaType:OWA_MEDIA_TYPE,digest:configDigest,size:configBytes.byteLength},
    layers,
    annotations:{'dev.openwebartifact.artifact.digest':configDigest}
  };
  const ociManifestBytes=Buffer.from(canonicalJson(ociManifest),'utf8');
  const ociManifestDigest=sha256(ociManifestBytes);
  await writeBlob(root,ociManifestDigest,ociManifestBytes);

  const index={schemaVersion:2,mediaType:OCI_IMAGE_INDEX,manifests:[{
    mediaType:OCI_IMAGE_MANIFEST,
    digest:ociManifestDigest,
    size:ociManifestBytes.byteLength,
    artifactType:OWA_MEDIA_TYPE,
    annotations:{'org.opencontainers.image.ref.name':ref,'dev.openwebartifact.artifact.digest':configDigest}
  }]};
  await writeFile(join(root,'index.json'),JSON.stringify(index,null,2));
  return {artifactDigest:configDigest,ociManifestDigest,ref,output:root};
}

export const REF_NAME_ANNOTATION='org.opencontainers.image.ref.name';

/**
 * Index reference selection (issue #36; docs/oci.md "Index reference selection").
 * EXACTLY ONE EXACT MATCH OR FAIL. The requested `ref` is the only selector:
 *
 *  1. `index.manifests` must be an array; only its object entries are descriptors;
 *  2. a descriptor matches when `annotations` is an object that has the key
 *     `org.opencontainers.image.ref.name` with a STRING value exactly equal to
 *     `ref` — a missing annotations object, a missing key, null, a number, a
 *     boolean or a different string never match; an empty annotation matches
 *     only when the caller explicitly requested the empty string;
 *  3. zero matches → reference not found; more than one → ambiguous.
 *
 * Descriptor order carries no meaning and never breaks a tie. There is no
 * `latest` → `manifests[0]` fallback (the previous, undocumented reference
 * behaviour), no digest, artifact-digest or media-type guessing, and no
 * "first valid-looking descriptor". Both failures are transport-local layout
 * errors, deliberately without a portable OWA error category.
 */
export function selectIndexDescriptor(index,ref){
  if(typeof ref!=='string')throw new Error('OCI reference must be a string');
  const manifests=index?.manifests;
  if(!Array.isArray(manifests))throw new Error('OCI index has no manifests array');
  const matches=manifests.filter(descriptor=>{
    if(descriptor===null||typeof descriptor!=='object'||Array.isArray(descriptor))return false;
    const annotations=descriptor.annotations;
    if(annotations===null||typeof annotations!=='object'||Array.isArray(annotations)||!Object.hasOwn(annotations,REF_NAME_ANNOTATION))return false;
    const name=annotations[REF_NAME_ANNOTATION];
    return typeof name==='string'&&name===ref;
  });
  if(matches.length===0)throw new Error(`OCI reference not found: ${ref}`);
  if(matches.length>1)throw new Error(`Ambiguous OCI index: ${matches.length} descriptors carry ${REF_NAME_ANNOTATION} ${ref}`);
  return matches[0];
}

export async function readOciLayout({input,ref='latest'}){
  const root=input;
  const layout=parseJsonText(await readFile(join(root,'oci-layout'),'utf8'));
  if(layout.imageLayoutVersion!==OCI_LAYOUT_VERSION)throw new Error(`Unsupported OCI layout version: ${layout.imageLayoutVersion}`);
  const index=parseJsonText(await readFile(join(root,'index.json'),'utf8'));
  const descriptor=selectIndexDescriptor(index,ref);
  if(descriptor.mediaType!==OCI_IMAGE_MANIFEST)throw new Error(`Unsupported OCI manifest media type: ${descriptor.mediaType}`);
  const ociManifestBytes=await readVerifiedBlob(root,descriptor.digest,descriptor.size);
  const ociManifest=parseJsonText(ociManifestBytes.toString('utf8'));
  if(ociManifest.artifactType!==OWA_MEDIA_TYPE)throw new Error(`Not an Open Web Artifact: ${ociManifest.artifactType}`);
  if(ociManifest.config?.mediaType!==OWA_MEDIA_TYPE)throw new Error('OCI config is not an OWA manifest');
  const configBytes=await readVerifiedBlob(root,ociManifest.config.digest,ociManifest.config.size);
  const manifest=parseJsonText(configBytes.toString('utf8'));
  validateManifest(manifest);
  const owaDigest=artifactDigest(manifest);
  if(owaDigest!==ociManifest.config.digest)throw new Error('OWA artifact digest does not match OCI config digest');
  if(ociManifest.annotations?.['dev.openwebartifact.artifact.digest']&&ociManifest.annotations['dev.openwebartifact.artifact.digest']!==owaDigest)throw new Error('OCI OWA digest annotation mismatch');

  const blobMap=new Map();
  const {selectLayer}=indexLayers(ociManifest.layers,manifest);
  const verified=new Map(); // digest -> verified bytes; repeated descriptors share ONE blob
  for(const file of manifest.files){
    const layer=selectLayer(file);
    // Path-based selection no longer implies digest equality: check it explicitly.
    if(layer.digest!==file.digest)throw new Error(`OCI layer digest mismatch for ${file.path}`);
    if(layer.size!==file.size)throw owaError('OWA_CONTENT_SIZE_MISMATCH', `OCI layer size mismatch for ${file.path}`);
    // Representation integrity: the descriptor must carry exactly the mapped
    // transport media type for this file (never compared to the full OWA value).
    if(layer.mediaType!==ociLayerMediaType(file.mediaType))throw new Error(`OCI layer media type mismatch for ${file.path}`);
    if(hasPathAnnotation(layer)&&layer.annotations[PATH_ANNOTATION]!==file.path)throw new Error(`OCI layer path mismatch for ${file.path}`);
    let body=verified.get(file.digest);
    if(body===undefined){body=new Uint8Array(await readVerifiedBlob(root,file.digest,file.size));verified.set(file.digest,body);}
    // A cached blob still has to satisfy THIS entry's declared size.
    else if(body.byteLength!==file.size)throw owaError('OWA_CONTENT_SIZE_MISMATCH', `OCI blob size mismatch: ${file.digest}`);
    blobMap.set(file.digest,body);
  }
  return {manifest,artifactDigest:owaDigest,blobs:blobMap,ociManifest,ociManifestDigest:descriptor.digest,ref};
}

export const PATH_ANNOTATION='dev.openwebartifact.path';

/** The annotation KEY is present (whatever its value) — presence, not truthiness. */
function hasPathAnnotation(layer){
  const annotations=layer?.annotations;
  return annotations!==null&&typeof annotations==='object'&&Object.hasOwn(annotations,PATH_ANNOTATION);
}

/**
 * Descriptor selection (issue #9). An OCI manifest carries ONE layer descriptor per
 * OWA FILE ENTRY; several descriptors may reference the SAME content-addressed
 * blob digest when different paths hold identical bytes. So `layers` is a
 * descriptor LIST identified by `dev.openwebartifact.path`, never a digest-keyed
 * set (the previous Map(digest -> layer) silently collapsed repeated descriptors
 * and lost their path-specific annotations).
 *
 *  1. Index descriptors by their exact path annotation. Two descriptors claiming
 *     the same path make the representation ambiguous: reject, never pick one.
 *  2. For each OWA file, select the unique descriptor whose path annotation equals
 *     `file.path`.
 *  3. Legacy fallback (annotation-less layouts) ONLY when it is unambiguous: the
 *     file's digest occurs exactly once in the OWA manifest, exactly one layer
 *     carries that digest, and that layer has NO path annotation key at all. A
 *     present-but-different path annotation is authoritative: never fall back
 *     through it. Duplicate-digest files therefore always need their own
 *     path-annotated descriptor.
 *  4. A descriptor satisfies at most one file entry.
 * Layer ORDER carries no OWA meaning; the config manifest owns file order.
 */
function indexLayers(layers,manifest){
  const list=Array.isArray(layers)?layers:[];
  const byPath=new Map();
  const byDigest=new Map();
  for(const layer of list){
    if(layer===null||typeof layer!=='object')continue;
    if(hasPathAnnotation(layer)){
      const path=layer.annotations[PATH_ANNOTATION];
      if(typeof path==='string'){
        if(byPath.has(path))throw new Error(`Ambiguous OCI layout: multiple layers claim ${PATH_ANNOTATION} ${path}`);
        byPath.set(path,layer);
      }
    }
    if(!byDigest.has(layer.digest))byDigest.set(layer.digest,[]);
    byDigest.get(layer.digest).push(layer);
  }
  const digestUses=new Map();
  for(const file of manifest.files)digestUses.set(file.digest,(digestUses.get(file.digest)??0)+1);
  const used=new Set();
  return {
    selectLayer(file){
      let layer=byPath.get(file.path);
      if(layer===undefined){
        const candidates=byDigest.get(file.digest)??[];
        if(candidates.length===0)throw new Error(`OCI layer missing for ${file.path}`);
        const unambiguous=digestUses.get(file.digest)===1&&candidates.length===1&&!hasPathAnnotation(candidates[0]);
        if(!unambiguous)throw new Error(`OCI layer for ${file.path} cannot be selected: no descriptor carries ${PATH_ANNOTATION} ${file.path}, and digest-only matching is only allowed for a unique digest with a single annotation-less layer`);
        layer=candidates[0];
      }
      if(used.has(layer))throw new Error(`OCI layer reused: one descriptor cannot satisfy two file entries (${file.path})`);
      used.add(layer);
      return layer;
    }
  };
}
