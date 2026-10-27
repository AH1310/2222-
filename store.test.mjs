import {test} from 'node:test';
import assert from 'node:assert/strict';
import {DatabaseSync} from 'node:sqlite';
import {readFileSync} from 'node:fs';
import worker from '../src/worker.js';
import {safeURL,decode,sign} from '../src/security.js';
import {planSchema,tables} from '../scripts/db.mjs';
class D1 {
 constructor(){this.db=new DatabaseSync(':memory:');this.db.exec('PRAGMA foreign_keys=ON;'+readFileSync('schema.sql','utf8'));}
 prepare(sql){const db=this.db;return {bind(...args){return {async first(){return db.prepare(sql).get(...args)||null;},async all(){return {results:db.prepare(sql).all(...args)};},async run(){return {meta:{changes:Number(db.prepare(sql).run(...args).changes)}};}};}};}
 async batch(queries){this.db.exec('BEGIN');try{const out=[];for(const q of queries)out.push(await q.run());this.db.exec('COMMIT');return out;}catch(e){this.db.exec('ROLLBACK');throw e;}}
}
const origin='https://store.example.com';
function setup(){const env={DB:new D1(),SESSION_SECRET:'x'.repeat(64),BOOTSTRAP_TOKEN:'t'.repeat(64),AUTH_LIMITER:{async limit(){return {success:true};}},ASSETS:{async fetch(){return new Response('shell');}}};return {env,async request(path,method='GET',data,cookie='',headers={}){const r=await worker.fetch(new Request(origin+path,{method,headers:{Origin:origin,'X-AH13-Request':'1',Cookie:cookie,...headers},body:data?JSON.stringify(data):undefined}),env);const b=r.headers.get('Content-Type')?.includes('json')?await r.json():await r.text();return {r,b,cookie:r.headers.get('Set-Cookie')?.split(';')[0]};}};}
const account=(email,role='user')=>({email,name:'Member '+email.split('@')[0],password:'a-secure-passphrase-13',role});
test('Full lifecycle: admin, moderation, ownership, updates, library, ratings, reports, bans and revocation',async()=>{
 const {env,request:q}=setup();
 const bootstrap=await q('/api/bootstrap','POST',{...account('admin@example.com'),token:env.BOOTSTRAP_TOKEN});assert.equal(bootstrap.r.status,200);const admin=bootstrap.cookie;
 assert.equal((await q('/api/bootstrap','POST',{...account('admin2@example.com'),token:env.BOOTSTRAP_TOKEN})).r.status,409);
 const devRes=await q('/api/register','POST',account('dev@example.com','developer'));assert.equal(devRes.r.status,200);const dev=devRes.cookie,devId=devRes.b.user.id;
 const userRes=await q('/api/register','POST',account('reader@example.com','admin'));assert.equal(userRes.b.user.role,'user');const user=userRes.cookie;
 assert.equal((await q('/api/admin','GET',null,user)).r.status,403);
 assert.equal((await q('/api/admin','GET')).r.status,401);
 assert.equal((await q('/api/apps','POST',{name:'Bad'},user)).r.status,403);
 const sub=await q('/api/apps','POST',{name:'Useful app',url:'https://example.com',icon_url:'https://example.com/icon.png'},dev);assert.equal(sub.r.status,201);const id=sub.b.id;
 assert.equal((await q('/api/apps')).b.apps.length,0);
 await q('/api/admin/app','POST',{id,status:'approved'},admin);
 assert.equal((await q('/api/apps')).b.apps.length,1);
 assert.equal((await q('/api/apps/'+id+'/library','POST',{},user)).r.status,200);
 await q('/api/apps/'+id+'/library','POST',{},user);assert.equal((await q('/api/library','GET',null,user)).b.apps.length,1);
 assert.equal((await q('/api/apps/'+id+'/ratings','POST',{score:6},user)).r.status,400);
 await q('/api/apps/'+id+'/ratings','POST',{score:4,comment:'Great <script>'},user);
 await q('/api/apps/'+id+'/ratings','POST',{score:5,comment:'Updated'},user);
 assert.equal((await q('/api/apps/'+id+'/ratings')).b.ratings.length,1);
 assert.equal((await q('/api/apps')).b.apps[0].rating,5);
 const other=(await q('/api/register','POST',account('other@example.com','developer'))).cookie;
 assert.equal((await q('/api/apps/'+id+'/updates','POST',{url:'https://new.example.com'},other)).r.status,403);
 await q('/api/apps/'+id+'/updates','POST',{url:'https://new.example.com'},dev);
 assert.equal((await q('/api/apps')).b.apps[0].url,'https://example.com/');
 const update=(await q('/api/admin','GET',null,admin)).b.updates[0];
 await q('/api/admin/update','POST',{id:update.id,status:'approved'},admin);
 assert.equal((await q('/api/apps')).b.apps[0].url,'https://new.example.com/');
 assert.equal((await q('/api/admin/update','POST',{id:update.id,status:'approved'},admin)).r.status,409);
 await q('/api/apps/'+id+'/report','POST',{reason:'Broken login page'},user);
 const report=(await q('/api/admin','GET',null,admin)).b.reports[0];
 await q('/api/admin/report','POST',{id:report.id},admin);
 assert.equal((await q('/api/admin','GET',null,admin)).b.reports[0].status,'resolved');
 await q('/api/admin/user','POST',{id:devId,banned:true,role:'developer'},admin);
 assert.equal((await q('/api/developer','GET',null,dev)).r.status,401);
 assert.equal((await q('/api/apps')).b.apps.length,0);
 await q('/api/admin/user','POST',{id:devId,banned:false,role:'developer'},admin);
 assert.equal((await q('/api/developer','GET',null,dev)).r.status,401);
 assert.equal((await q('/api/apps')).b.apps.length,1);
 await q('/api/admin/app','POST',{id,status:'blocked'},admin);
 assert.equal((await q('/api/library','GET',null,user)).b.apps.length,0);
 assert.ok((await q('/api/admin','GET',null,admin)).b.audit.length>=8);
 const oldCookie=user;await q('/api/password','POST',{current:'a-secure-passphrase-13',password:'changed-secure-password'},user);
 assert.equal((await q('/api/library','GET',null,oldCookie)).r.status,401);
 assert.equal((await q('/api/login','POST',{email:'reader@example.com',password:'a-secure-passphrase-13'})).r.status,401);
 const login=await q('/api/login','POST',{email:'reader@example.com',password:'changed-secure-password'});assert.equal(login.r.status,200);
 await q('/api/logout','POST',{},login.cookie);assert.equal((await q('/api/library','GET',null,login.cookie)).r.status,401);
 const raw=env.DB.db.prepare('SELECT password_hash FROM users LIMIT 1').get().password_hash;assert.ok(raw.startsWith('pbkdf2$'));assert.ok(!raw.includes('a-secure'));
});
test('Security boundaries, setup secret, rate limits, headers and icon upload',async()=>{
 const {env,request:q}=setup();
 assert.equal((await q('/api/register','POST',account('a@example.com'),'',{Origin:'https://attacker.example'})).r.status,403);
 assert.equal((await q('/api/register','POST',account('a@example.com'),'',{'X-AH13-Request':''})).r.status,403);
 assert.equal((await q('/api/bootstrap','POST',{...account('a@example.com'),token:'wrong'})).r.status,403);
 for(const url of ['javascript:alert(1)','http://example.com','https://user:pass@example.com','https://127.0.0.1','https://localhost','https://10.0.0.1'])assert.throws(()=>safeURL(url));
 const r=await q('/api/me');assert.match(r.r.headers.get('Content-Security-Policy'),/frame-ancestors 'none'/);assert.equal(r.r.headers.get('Cache-Control'),'no-store');
 const s=await sign({sub:'a',exp:Date.now()+10000},env.SESSION_SECRET);assert.equal(await decode(s+'x',env.SESSION_SECRET),null);assert.equal(await decode(await sign({exp:0},env.SESSION_SECRET),env.SESSION_SECRET),null);
 const dev=(await q('/api/register','POST',account('dev@example.com','developer'))).cookie;
 assert.equal((await q('/api/icons','POST',{},dev)).r.status,503);
 const objects=new Map();env.ICONS={async put(k,v,meta){objects.set(k,{body:v,httpMetadata:meta.httpMetadata});},async get(k){return objects.get(k);}};
 const upload=await worker.fetch(new Request(origin+'/api/icons',{method:'POST',headers:{Origin:origin,'X-AH13-Request':'1',Cookie:dev},body:readFileSync('public/icon-192.png')}),env);assert.equal(upload.status,201);const icon=(await upload.json()).url;
 assert.equal((await worker.fetch(new Request(icon),env)).headers.get('Content-Type'),'image/png');
 assert.equal((await q('/api/icons','POST',{},dev)).r.status,400);
 env.AUTH_LIMITER={async limit(){return {success:false};}};
 assert.equal((await q('/api/login','POST',account('a@example.com'))).r.status,429);
 delete env.AUTH_LIMITER;assert.equal((await q('/api/login','POST',account('a@example.com'))).r.status,503);
});
test('Schema migration guard preserves rows and refuses unknown legacy schema',()=>{
 const d=new DatabaseSync(':memory:');d.exec(readFileSync('schema.sql','utf8'));d.prepare('INSERT INTO users(id,email,name,password_hash) VALUES(?,?,?,?)').run('old','old@example.com','Legacy','legacy');
 const expected=tables.map(t=>d.prepare(`PRAGMA table_info(${t})`).all());
 assert.deepEqual(planSchema(expected,expected),[]);
 const older=structuredClone(expected);older[0]=older[0].filter(c=>c.name!=='session_version');const sql=planSchema(older,expected);assert.match(sql[0],/ADD COLUMN session_version/);
 const wrong=structuredClone(expected);wrong[1]=wrong[1].filter(c=>c.name!=='url');assert.throws(()=>planSchema(wrong,expected),/No changes made/);
 assert.equal(d.prepare('SELECT name FROM users WHERE id=?').get('old').name,'Legacy');
});
