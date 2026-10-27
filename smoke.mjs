// Run only against your local Wrangler dev instance, after db:local.
import assert from 'node:assert/strict';import {readFileSync} from 'node:fs';import {randomUUID} from 'node:crypto';
const origin='http://localhost:8787';
const token=readFileSync('.dev.vars','utf8').match(/BOOTSTRAP_TOKEN="([^"]+)"/)[1];
const suffix=randomUUID().slice(0,8),password=randomUUID()+randomUUID();
async function q(path,method='GET',data,cookie){const r=await fetch(origin+path,{method,headers:{Origin:origin,'X-AH13-Request':'1',...(cookie?{Cookie:cookie}:{})},body:data?JSON.stringify(data):undefined});const b=await r.json();return {r,b,cookie:r.headers.get('set-cookie')?.split(';')[0]};}
const health=await q('/api/health');assert.equal(health.r.status,200);assert.equal(health.b.ok,true);
for(const file of ['/','/app.js','/style.css','/sw.js','/manifest.webmanifest','/icon-192.png','/icon-512.png'])assert.equal((await fetch(origin+file)).status,200,file);
const account=email=>({name:'Smoke '+suffix,email:email+'-'+suffix+'@example.com',password});
const a=await q('/api/bootstrap','POST',{...account('admin'),token});assert.equal(a.r.status,200,'Use a fresh local database for bootstrap smoke test');
const dev=await q('/api/register','POST',{...account('developer'),role:'developer'});assert.equal(dev.r.status,200);
const reader=await q('/api/register','POST',account('reader'));assert.equal(reader.r.status,200);
assert.equal((await q('/api/admin','GET',null,reader.cookie)).r.status,403);
const app=await q('/api/apps','POST',{name:'Cloudflare Docs',url:'https://developers.cloudflare.com/',icon_url:'https://developers.cloudflare.com/favicon.ico'},dev.cookie);assert.equal(app.r.status,201);
assert.equal((await q('/api/apps')).b.apps.length,0);
assert.equal((await q('/api/admin/app','POST',{id:app.b.id,status:'approved'},a.cookie)).r.status,200);
assert.equal((await q('/api/apps')).b.apps.length,1);
assert.equal((await q('/api/apps/'+app.b.id+'/library','POST',{},reader.cookie)).r.status,200);
assert.equal((await q('/api/library','GET',null,reader.cookie)).b.apps.length,1);
assert.equal((await q('/api/apps/'+app.b.id+'/ratings','POST',{score:5,comment:'Real Worker smoke test'},reader.cookie)).r.status,200);
assert.equal((await q('/api/apps')).b.apps[0].rating,5);
console.log('PASS: real Wrangler/workerd + local D1 + assets + account setup + roles + moderation + library + ratings. No production resources accessed.');
