#!/usr/bin/env node
import { resolve } from 'node:path';
import { mkdir } from 'node:fs/promises';
import { packDirectory, publishDirectory, activateRelease, commitManifest } from '../../core/src/index.js';
import { FilesystemBlobStore, FilesystemMetadataStore } from '../../storage-filesystem/src/index.js';
import { readOciLayout, writeOciLayout } from '../../transport-oci/src/index.js';
import { CliError, cliErrorMessage, remotePublish, remoteReleases, remoteActivate } from './remote.js';

const args=process.argv.slice(2);const command=args.shift();
function flag(name,fallback){const i=args.indexOf(name);if(i<0)return fallback;const value=args[i+1];if(!value||value.startsWith('--'))throw new CliError('OWA_CLI_CONFIG');return value;}
function usage(){console.log(`Open Web Artifact CLI

  artifact publish <dir> --site <slug> [--server http://localhost:7331] [--no-activate]
  artifact releases --site <slug> [--server http://localhost:7331]
  artifact activate <release-id> --site <slug> [--server http://localhost:7331]
  artifact export-oci <dir> --out <layout-dir> [--ref latest]
  artifact import-oci <layout-dir> --site <slug> [--ref latest] [--data .owa-data]

Remote authentication: OWA_TOKEN environment variable only (Bearer header).
Operators mint tokens with the server createToken library; there is no CLI mint command.
Use an HTTPS server origin, or loopback HTTP for development. No redirects.
Remote publish activates by default; --no-activate needs commit but not activate.
Missing blobs require plan + upload; releases requires read; activate requires activate.

Local operator mode (no --server, host filesystem permissions):
  artifact publish <dir> --site <slug> [--data .owa-data]`);}
async function localStores(){const dataDir=resolve(flag('--data','.owa-data'));await mkdir(dataDir,{recursive:true});return {blobs:new FilesystemBlobStore(dataDir),metadata:new FilesystemMetadataStore(dataDir)};}

async function main(){
if(command==='publish'){
  const directory=args[0],slug=flag('--site'),server=flag('--server');if(!directory||!slug){usage();process.exit(1);} if(server)console.log(await remotePublish(directory,slug,server,{activate:!args.includes('--no-activate')}));else{
    const {blobs,metadata}=await localStores();const r=await publishDirectory({directory,slug,blobs,metadata});console.log(`Published ${r.release.id}\nArtifact ${r.release.artifactDigest}\nUploaded ${r.uploaded} blob(s), reused ${r.reused}\nLocal URL: http://${slug}.localhost:7331/`);
  }
}else if(command==='releases'){
  const slug=flag('--site'),server=flag('--server');if(!slug){usage();process.exit(1);}if(server){const output=await remoteReleases(slug,server);if(output)console.log(output);}else{const {metadata}=await localStores();const site=await metadata.getSite(slug);if(!site)throw new Error('Site not found');for(const r of await metadata.listReleases(site.id))console.log(`${r.id}${site.activeReleaseId===r.id?' *':''}\t${r.artifactDigest}\t${r.createdAt}`);}
}else if(command==='activate'){
  const releaseId=args[0],slug=flag('--site'),server=flag('--server');if(!releaseId||!slug){usage();process.exit(1);}if(server){console.log(await remoteActivate(releaseId,slug,server));}else{const {metadata}=await localStores();const r=await activateRelease(metadata,slug,releaseId);console.log(`Activated ${r.release.id} for ${slug}`);}
}else if(command==='export-oci'){
  const directory=args[0],out=flag('--out'),ref=flag('--ref','latest');if(!directory||!out){usage();process.exit(1);}const packed=await packDirectory(directory);const result=await writeOciLayout({manifest:packed.manifest,blobs:packed.blobs,output:resolve(out),ref});console.log(`Exported ${result.artifactDigest}\nOCI manifest ${result.ociManifestDigest}\nLayout: ${result.output}:${result.ref}`);
}else if(command==='import-oci'){
  const input=args[0],slug=flag('--site'),ref=flag('--ref','latest');if(!input||!slug){usage();process.exit(1);}const imported=await readOciLayout({input:resolve(input),ref});const {blobs,metadata}=await localStores();let uploaded=0,reused=0;for(const [digest,data] of imported.blobs){if(await blobs.has(digest))reused++;else{await blobs.put(digest,data);uploaded++;}}const r=await commitManifest({slug,manifest:imported.manifest,expectedArtifactDigest:imported.artifactDigest,blobs,metadata});console.log(`Imported ${r.release.id}\nArtifact ${r.release.artifactDigest}\nStored ${uploaded} blob(s), reused ${reused}`);
}else usage();
}

try { await main(); }
catch(error) { console.error(cliErrorMessage(error)); process.exitCode=1; }
