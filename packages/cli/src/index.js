#!/usr/bin/env node
import { resolve } from 'node:path';
import { mkdir } from 'node:fs/promises';
import { packDirectory, publishDirectory, activateRelease, commitManifest } from '../../core/src/index.js';
import { FilesystemBlobStore, FilesystemMetadataStore } from '../../storage-filesystem/src/index.js';
import { readOciLayout, writeOciLayout } from '../../transport-oci/src/index.js';

const args=process.argv.slice(2);const command=args.shift();
function flag(name,fallback){const i=args.indexOf(name);return i>=0?args[i+1]:fallback;}
function usage(){console.log(`Open Web Artifact CLI

  artifact publish <dir> --site <slug> [--server http://localhost:7331]
  artifact releases --site <slug> [--server http://localhost:7331]
  artifact activate <release-id> --site <slug> [--server http://localhost:7331]
  artifact export-oci <dir> --out <layout-dir> [--ref latest]
  artifact import-oci <layout-dir> --site <slug> [--ref latest] [--data .owa-data]

Local development mode (no --server):
  artifact publish <dir> --site <slug> [--data .owa-data]`);}
async function requestJson(url,options={}){const res=await fetch(url,options);const body=await res.json().catch(()=>({}));if(!res.ok)throw new Error(body.error??`${res.status} ${res.statusText}`);return body;}
async function remotePublish(directory,slug,server){
  const packed=await packDirectory(directory); const base=server.replace(/\/$/,'');
  const plan=await requestJson(`${base}/v1/sites/${encodeURIComponent(slug)}/publish/plan`,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({manifest:packed.manifest,artifactDigest:packed.artifactDigest})});
  let uploaded=0;
  for(const upload of plan.uploads){const data=packed.blobs.get(upload.digest);if(!data)throw new Error(`Server requested unknown blob ${upload.digest}`);const res=await fetch(upload.url,{method:upload.method??'PUT',body:Buffer.from(data)});if(!res.ok)throw new Error(`Blob upload failed for ${upload.digest}: ${res.status} ${await res.text()}`);uploaded++;}
  const commit=await requestJson(`${base}/v1/sites/${encodeURIComponent(slug)}/publish/commit`,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({manifest:packed.manifest,artifactDigest:packed.artifactDigest})});
  console.log(`Published ${commit.releaseId}\nArtifact ${commit.artifactDigest}\nUploaded ${uploaded} blob(s), reused ${plan.reused}\nServer: ${base}`);
}
async function localStores(){const dataDir=resolve(flag('--data','.owa-data'));await mkdir(dataDir,{recursive:true});return {blobs:new FilesystemBlobStore(dataDir),metadata:new FilesystemMetadataStore(dataDir)};}

if(command==='publish'){
  const directory=args[0],slug=flag('--site'),server=flag('--server');if(!directory||!slug){usage();process.exit(1);} if(server)await remotePublish(directory,slug,server);else{
    const {blobs,metadata}=await localStores();const r=await publishDirectory({directory,slug,blobs,metadata});console.log(`Published ${r.release.id}\nArtifact ${r.release.artifactDigest}\nUploaded ${r.uploaded} blob(s), reused ${r.reused}\nLocal URL: http://${slug}.localhost:7331/`);
  }
}else if(command==='releases'){
  const slug=flag('--site'),server=flag('--server');if(!slug){usage();process.exit(1);}if(server){const body=await requestJson(`${server.replace(/\/$/,'')}/v1/sites/${encodeURIComponent(slug)}/releases`);for(const r of body.releases)console.log(`${r.id}${body.site.activeReleaseId===r.id?' *':''}\t${r.artifactDigest}\t${r.createdAt}`);}else{const {metadata}=await localStores();const site=await metadata.getSite(slug);if(!site)throw new Error('Site not found');for(const r of await metadata.listReleases(site.id))console.log(`${r.id}${site.activeReleaseId===r.id?' *':''}\t${r.artifactDigest}\t${r.createdAt}`);}
}else if(command==='activate'){
  const releaseId=args[0],slug=flag('--site'),server=flag('--server');if(!releaseId||!slug){usage();process.exit(1);}if(server){const body=await requestJson(`${server.replace(/\/$/,'')}/v1/sites/${encodeURIComponent(slug)}/activate/${encodeURIComponent(releaseId)}`,{method:'POST'});console.log(`Activated ${body.activeReleaseId} for ${slug}`);}else{const {metadata}=await localStores();const r=await activateRelease(metadata,slug,releaseId);console.log(`Activated ${r.release.id} for ${slug}`);}
}else if(command==='export-oci'){
  const directory=args[0],out=flag('--out'),ref=flag('--ref','latest');if(!directory||!out){usage();process.exit(1);}const packed=await packDirectory(directory);const result=await writeOciLayout({manifest:packed.manifest,blobs:packed.blobs,output:resolve(out),ref});console.log(`Exported ${result.artifactDigest}\nOCI manifest ${result.ociManifestDigest}\nLayout: ${result.output}:${result.ref}`);
}else if(command==='import-oci'){
  const input=args[0],slug=flag('--site'),ref=flag('--ref','latest');if(!input||!slug){usage();process.exit(1);}const imported=await readOciLayout({input:resolve(input),ref});const {blobs,metadata}=await localStores();let uploaded=0,reused=0;for(const [digest,data] of imported.blobs){if(await blobs.has(digest))reused++;else{await blobs.put(digest,data);uploaded++;}}const r=await commitManifest({slug,manifest:imported.manifest,expectedArtifactDigest:imported.artifactDigest,blobs,metadata});console.log(`Imported ${r.release.id}\nArtifact ${r.release.artifactDigest}\nStored ${uploaded} blob(s), reused ${reused}`);
}else usage();
