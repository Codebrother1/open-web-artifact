import { mkdir, readFile, readdir, writeFile } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { randomUUID } from 'node:crypto';

async function writeJson(path,value){await mkdir(dirname(path),{recursive:true});await writeFile(path,JSON.stringify(value,null,2));}
async function readJson(path){if(!existsSync(path))return null;return JSON.parse(await readFile(path,'utf8'));}

export class FilesystemBlobStore{
  constructor(root){this.root=root;}
  path(digest){return join(this.root,'blobs',digest.replace(':','/'));}
  async has(digest){return existsSync(this.path(digest));}
  async put(digest,data){const p=this.path(digest);await mkdir(dirname(p),{recursive:true});await writeFile(p,data);}
  async get(digest){return new Uint8Array(await readFile(this.path(digest)));}
}

export class FilesystemMetadataStore{
  constructor(root){this.root=root;}
  siteIndex(slug){return join(this.root,'sites-by-slug',`${slug}.json`);}
  sitePath(id){return join(this.root,'sites',id,'site.json');}
  releasePath(siteId,id){return join(this.root,'sites',siteId,'releases',`${id}.json`);}
  async createSite(slug){const existing=await this.getSite(slug);if(existing)return existing;const site={id:`s_${randomUUID().replaceAll('-','').slice(0,20)}`,slug,activeReleaseId:null,createdAt:new Date().toISOString()};await writeJson(this.sitePath(site.id),site);await writeJson(this.siteIndex(slug),{id:site.id});return site;}
  async getSite(slug){const idx=await readJson(this.siteIndex(slug));return idx?readJson(this.sitePath(idx.id)):null;}
  async saveSite(site){await writeJson(this.sitePath(site.id),site);await writeJson(this.siteIndex(site.slug),{id:site.id});}
  async saveRelease(siteId,release){await writeJson(this.releasePath(siteId,release.id),release);}
  async getRelease(siteId,releaseId){return readJson(this.releasePath(siteId,releaseId));}
  async listReleases(siteId){const dir=join(this.root,'sites',siteId,'releases');if(!existsSync(dir))return[];const out=[];for(const n of await readdir(dir)){const r=await readJson(join(dir,n));if(r)out.push(r);}return out.sort((a,b)=>b.createdAt.localeCompare(a.createdAt));}
}
