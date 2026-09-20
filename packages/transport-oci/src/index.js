import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { artifactDigest, canonicalJson, OWA_MEDIA_TYPE, owaError, sha256, validateManifest } from '../../spec/src/index.js';

export const OCI_IMAGE_MANIFEST = 'application/vnd.oci.image.manifest.v1+json';
export const OCI_IMAGE_INDEX = 'application/vnd.oci.image.index.v1+json';
export const OCI_LAYOUT_VERSION = '1.0.0';

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
      mediaType:file.mediaType,
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

export async function readOciLayout({input,ref='latest'}){
  const root=input;
  const layout=JSON.parse(await readFile(join(root,'oci-layout'),'utf8'));
  if(layout.imageLayoutVersion!==OCI_LAYOUT_VERSION)throw new Error(`Unsupported OCI layout version: ${layout.imageLayoutVersion}`);
  const index=JSON.parse(await readFile(join(root,'index.json'),'utf8'));
  const descriptor=index.manifests?.find(item=>item.annotations?.['org.opencontainers.image.ref.name']===ref) ?? (ref==='latest'?index.manifests?.[0]:null);
  if(!descriptor)throw new Error(`OCI reference not found: ${ref}`);
  if(descriptor.mediaType!==OCI_IMAGE_MANIFEST)throw new Error(`Unsupported OCI manifest media type: ${descriptor.mediaType}`);
  const ociManifestBytes=await readVerifiedBlob(root,descriptor.digest,descriptor.size);
  const ociManifest=JSON.parse(ociManifestBytes.toString('utf8'));
  if(ociManifest.artifactType!==OWA_MEDIA_TYPE)throw new Error(`Not an Open Web Artifact: ${ociManifest.artifactType}`);
  if(ociManifest.config?.mediaType!==OWA_MEDIA_TYPE)throw new Error('OCI config is not an OWA manifest');
  const configBytes=await readVerifiedBlob(root,ociManifest.config.digest,ociManifest.config.size);
  const manifest=JSON.parse(configBytes.toString('utf8'));
  validateManifest(manifest);
  const owaDigest=artifactDigest(manifest);
  if(owaDigest!==ociManifest.config.digest)throw new Error('OWA artifact digest does not match OCI config digest');
  if(ociManifest.annotations?.['dev.openwebartifact.artifact.digest']&&ociManifest.annotations['dev.openwebartifact.artifact.digest']!==owaDigest)throw new Error('OCI OWA digest annotation mismatch');

  const layerByDigest=new Map((ociManifest.layers??[]).map(layer=>[layer.digest,layer]));
  const blobMap=new Map();
  for(const file of manifest.files){
    const layer=layerByDigest.get(file.digest);if(!layer)throw new Error(`OCI layer missing for ${file.path}`);
    if(layer.size!==file.size)throw owaError('OWA_CONTENT_SIZE_MISMATCH', `OCI layer size mismatch for ${file.path}`);
    if(layer.annotations?.['dev.openwebartifact.path']&&layer.annotations['dev.openwebartifact.path']!==file.path)throw new Error(`OCI layer path mismatch for ${file.path}`);
    blobMap.set(file.digest,new Uint8Array(await readVerifiedBlob(root,file.digest,file.size)));
  }
  return {manifest,artifactDigest:owaDigest,blobs:blobMap,ociManifest,ociManifestDigest:descriptor.digest,ref};
}
