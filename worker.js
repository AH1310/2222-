import {digest,passwordHash,verifyPassword,sign,decode,equal,safeURL,text} from './security.js';
const uid=()=>crypto.randomUUID();
const error=(status,message)=>{throw Object.assign(new Error(message),{status});};
const json=(data,status=200,headers={})=>new Response(JSON.stringify(data),{status,headers:{'Content-Type':'application/json; charset=utf-8','Cache-Control':'no-store',...headers}});
const stmt=(db,sql,...args)=>db.prepare(sql).bind(...args);
const all=async(db,sql,...args)=>(await stmt(db,sql,...args).all()).results;
const one=(db,sql,...args)=>stmt(db,sql,...args).first();
const publicUser=u=>u&&({id:u.id,name:u.name,email:u.email,role:u.role});
function audit(db,u,action,id,detail=''){return stmt(db,'INSERT INTO audit_log(id,actor_id,action,target_id,detail) VALUES(?,?,?,?,?)',uid(),u.id,action,id,detail);}
async function body(req){if(Number(req.headers.get('content-length')||0)>16384)error(413,'Request too large');const reader=req.body?.getReader();if(!reader)error(400,'JSON body required');let size=0;const chunks=[];while(true){const {done,value}=await reader.read();if(done)break;size+=value.length;if(size>16384){await reader.cancel();error(413,'Request too large');}chunks.push(value);}const bytes=new Uint8Array(size);let i=0;for(const c of chunks){bytes.set(c,i);i+=c.length;}try{return JSON.parse(new TextDecoder().decode(bytes));}catch{error(400,'Invalid JSON');}}
async function auth(req,env,required=true){
 const token=req.headers.get('Cookie')?.match(/(?:^|; )ah13_session=([^;]+)/)?.[1];
 const p=token&&await decode(token,env.SESSION_SECRET);
 const u=p&&await one(env.DB,'SELECT * FROM users WHERE id=?',p.sub);
 if(!u||u.banned||u.session_version!==p.ver){if(required)error(401,'Please sign in');return null;}return u;
}
function role(u,r){if(!r.includes(u.role))error(403,'Permission denied');}
async function session(u,env,req){const token=await sign({sub:u.id,ver:u.session_version,exp:Date.now()+7*86400000},env.SESSION_SECRET);return json({user:publicUser(u)},200,{'Set-Cookie':`ah13_session=${token}; HttpOnly; SameSite=Strict; Path=/; Max-Age=604800${new URL(req.url).protocol==='https:'?'; Secure':''}`});}
async function rate(req,env){if(env.AUTH_LIMITER){const r=await env.AUTH_LIMITER.limit({key:req.headers.get('CF-Connecting-IP')||'local'});if(!r.success)error(429,'Too many attempts. Try later.');}else if(!['localhost','127.0.0.1'].includes(new URL(req.url).hostname))error(503,'AUTH_LIMITER binding required');}
async function api(req,env){
 const url=new URL(req.url),p=url.pathname,m=req.method,db=env.DB;
 if(!db)error(503,'DB binding missing');
 if(!env.SESSION_SECRET||env.SESSION_SECRET.length<32)error(503,'SESSION_SECRET must contain at least 32 characters');
 if(m!=='GET'&&m!=='HEAD'){
  if(req.headers.get('Origin')!==url.origin||req.headers.get('X-AH13-Request')!=='1')error(403,'Invalid request origin');
 }
 if(p==='/api/health')return json({ok:true,database:!!await one(db,'SELECT 1 AS ok')});
 if(p==='/api/me')return json({user:publicUser(await auth(req,env,false))});
 if(['/api/register','/api/login','/api/bootstrap'].includes(p)&&m==='POST'){
  await rate(req,env); const b=await body(req);
  const email=text(b.email,3,254).toLowerCase();if(!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email))error(400,'Invalid email');
  const password=text(b.password,12,128);
  if(p==='/api/login'){
   const u=await one(db,'SELECT * FROM users WHERE email=?',email);
   // Perform a hash for unknown accounts too.
   const valid=await verifyPassword(password,u?.password_hash||await passwordHash('invalid-password'));
   if(!u||!valid||u.banned)error(401,'Invalid credentials');return session(u,env,req);
  }
  const name=text(b.name,2,70); const isAdmin=p==='/api/bootstrap';
  if(isAdmin&&(!env.BOOTSTRAP_TOKEN||env.BOOTSTRAP_TOKEN.length<32||!equal(await digest(String(b.token||'')),await digest(env.BOOTSTRAP_TOKEN))))error(403,'Invalid setup token');
  const id=uid(),hash=await passwordHash(password);
  try{
   const sql=isAdmin?"INSERT INTO users(id,email,name,password_hash,role) SELECT ?,?,?,?,'admin' WHERE NOT EXISTS(SELECT 1 FROM users WHERE role='admin')":"INSERT INTO users(id,email,name,password_hash,role) VALUES(?,?,?,?,?)";
   const q=isAdmin?stmt(db,sql,id,email,name,hash):stmt(db,sql,id,email,name,hash,b.role==='developer'?'developer':'user');
   const r=await q.run();if(!r.meta.changes)error(409,'An administrator already exists');
  }catch(e){if(e.status)throw e;if(String(e).includes('UNIQUE'))error(409,'Email already registered');throw e;}
  return session(await one(db,'SELECT * FROM users WHERE id=?',id),env,req);
 }
 if(p==='/api/logout'&&m==='POST'){const u=await auth(req,env);await stmt(db,'UPDATE users SET session_version=session_version+1 WHERE id=?',u.id).run();return json({ok:true},200,{'Set-Cookie':'ah13_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0'});}
 if(p==='/api/password'&&m==='POST'){const u=await auth(req,env),b=await body(req);if(!await verifyPassword(String(b.current||''),u.password_hash))error(403,'Incorrect password');await stmt(db,'UPDATE users SET password_hash=?,session_version=session_version+1 WHERE id=?',await passwordHash(text(b.password,12,128)),u.id).run();return session(await one(db,'SELECT * FROM users WHERE id=?',u.id),env,req);}
 if(p==='/api/apps'&&m==='GET')return json({apps:await all(db,"SELECT a.*,u.name developer_name,COALESCE((SELECT AVG(score) FROM ratings WHERE app_id=a.id),0) rating,(SELECT COUNT(*) FROM ratings WHERE app_id=a.id) rating_count FROM apps a JOIN users u ON u.id=a.developer_id WHERE a.status='approved' AND u.banned=0 ORDER BY a.created_at DESC LIMIT 500")});
 const match=p.match(/^\/api\/apps\/([^/]+)(?:\/(ratings|library|updates|report))?$/);
 if(match){const id=match[1],action=match[2],a=await one(db,'SELECT a.*,u.banned developer_banned FROM apps a JOIN users u ON u.id=a.developer_id WHERE a.id=?',id);if(!a)error(404,'App not found');
  if(action==='ratings'&&m==='GET'){if(a.status!=='approved'||a.developer_banned)error(404,'App unavailable');return json({ratings:await all(db,'SELECT r.score,r.comment,r.created_at,u.name FROM ratings r JOIN users u ON u.id=r.user_id WHERE app_id=? AND u.banned=0 ORDER BY r.created_at DESC LIMIT 100',id)});}
  const u=await auth(req,env);
  if(action==='updates'&&m==='POST'){role(u,['developer','admin']);if(a.developer_id!==u.id)error(403,'Not your app');if(a.status!=='approved')error(409,'App must be approved first');const b=await body(req);const update=uid();await db.batch([stmt(db,'INSERT INTO app_updates(id,app_id,developer_id,url) VALUES(?,?,?,?)',update,id,u.id,safeURL(b.url)),audit(db,u,'request_update',id)]);return json({ok:true},201);}
  if(a.status!=='approved'||a.developer_banned)error(404,'App unavailable');
  if(action==='library'&&['POST','DELETE'].includes(m)){await stmt(db,m==='POST'?'INSERT INTO library(user_id,app_id) VALUES(?,?) ON CONFLICT(user_id,app_id) DO NOTHING':'DELETE FROM library WHERE user_id=? AND app_id=?',u.id,id).run();return json({ok:true});}
  if(action==='ratings'&&m==='POST'){const b=await body(req);if(!Number.isInteger(b.score)||b.score<1||b.score>5)error(400,'Score must be 1–5');await stmt(db,'INSERT INTO ratings(user_id,app_id,score,comment) VALUES(?,?,?,?) ON CONFLICT(user_id,app_id) DO UPDATE SET score=excluded.score,comment=excluded.comment,created_at=CURRENT_TIMESTAMP',u.id,id,b.score,text(b.comment||'',0,1000)).run();return json({ok:true});}
  if(action==='report'&&m==='POST'){const b=await body(req);await stmt(db,'INSERT INTO reports(id,user_id,app_id,reason) VALUES(?,?,?,?)',uid(),u.id,id,text(b.reason,5,1000)).run();return json({ok:true},201);}
 }
 if(p==='/api/library'&&m==='GET'){const u=await auth(req,env);return json({apps:await all(db,"SELECT a.* FROM library l JOIN apps a ON a.id=l.app_id JOIN users u ON u.id=a.developer_id WHERE l.user_id=? AND a.status='approved' AND u.banned=0 ORDER BY l.created_at DESC LIMIT 500",u.id)});}
 if(p==='/api/developer'&&m==='GET'){const u=await auth(req,env);role(u,['developer','admin']);return json({apps:await all(db,'SELECT * FROM apps WHERE developer_id=? ORDER BY created_at DESC LIMIT 500',u.id),updates:await all(db,'SELECT * FROM app_updates WHERE developer_id=? ORDER BY created_at DESC LIMIT 500',u.id)});}
 if(p==='/api/apps'&&m==='POST'){const u=await auth(req,env);role(u,['developer','admin']);const b=await body(req),id=uid();await db.batch([stmt(db,'INSERT INTO apps(id,developer_id,name,url,icon_url) VALUES(?,?,?,?,?)',id,u.id,text(b.name,2,80),safeURL(b.url),safeURL(b.icon_url)),audit(db,u,'submit_app',id)]);return json({id},201);}
 if(p==='/api/icons'&&m==='POST'){
  const u=await auth(req,env);role(u,['developer','admin']);if(!env.ICONS)error(503,'R2 is not configured. Use an HTTPS icon URL.');
  const declared=Number(req.headers.get('content-length')||0);if(declared>524288)error(413,'Icon max 512 KB');
  const reader=req.body?.getReader();if(!reader)error(400,'Image required');let size=0;const chunks=[];while(true){const {done,value}=await reader.read();if(done)break;size+=value.length;if(size>524288){await reader.cancel();error(413,'Icon max 512 KB');}chunks.push(value);}
  const data=new Uint8Array(size);let offset=0;for(const c of chunks){data.set(c,offset);offset+=c.length;}
  const png=data[0]===137&&data[1]===80&&data[2]===78&&data[3]===71;const jpg=data[0]===255&&data[1]===216&&data[2]===255;const webp=String.fromCharCode(...data.slice(0,4))==='RIFF'&&String.fromCharCode(...data.slice(8,12))==='WEBP';if(!png&&!jpg&&!webp)error(400,'PNG, JPEG or WebP required');
  const key=`${u.id}/${uid()}.${png?'png':jpg?'jpg':'webp'}`;await env.ICONS.put(key,data,{httpMetadata:{contentType:png?'image/png':jpg?'image/jpeg':'image/webp'}});return json({url:url.origin+'/icons/'+key},201);
 }
 if(p.startsWith('/api/admin')){
  const u=await auth(req,env);role(u,['admin']);
  if(p==='/api/admin'&&m==='GET')return json({apps:await all(db,'SELECT a.*,u.name developer_name FROM apps a JOIN users u ON u.id=a.developer_id ORDER BY a.created_at DESC LIMIT 500'),users:await all(db,'SELECT id,email,name,role,banned,created_at FROM users ORDER BY created_at DESC LIMIT 500'),updates:await all(db,'SELECT t.*,a.name app_name FROM app_updates t JOIN apps a ON a.id=t.app_id ORDER BY t.created_at DESC LIMIT 500'),reports:await all(db,'SELECT * FROM reports ORDER BY created_at DESC LIMIT 500'),audit:await all(db,'SELECT * FROM audit_log ORDER BY created_at DESC,rowid DESC LIMIT 200')});
  if(m==='POST'){
   const b=await body(req),id=text(b.id,1,100);
   if(p==='/api/admin/app'){if(!['approved','rejected','blocked','pending'].includes(b.status))error(400,'Invalid status');if(!await one(db,'SELECT id FROM apps WHERE id=?',id))error(404,'Missing app');await db.batch([stmt(db,'UPDATE apps SET status=? WHERE id=?',b.status,id),audit(db,u,'app_'+b.status,id)]);return json({ok:true});}
   if(p==='/api/admin/user'){const target=await one(db,'SELECT * FROM users WHERE id=?',id);if(!target)error(404,'User not found');if(target.role==='admin')error(403,'Administrator accounts cannot be changed here');if(typeof b.banned!=='boolean'||!['user','developer'].includes(b.role))error(400,'Invalid user settings');await db.batch([stmt(db,'UPDATE users SET banned=?,role=?,session_version=session_version+1 WHERE id=?',b.banned?1:0,b.role,id),audit(db,u,'manage_user',id,JSON.stringify({banned:b.banned,role:b.role}))]);return json({ok:true});}
   if(p==='/api/admin/update'){
    if(!['approved','rejected'].includes(b.status))error(400,'Invalid status');const t=await one(db,"SELECT * FROM app_updates WHERE id=? AND status='pending'",id);if(!t)error(409,'Update already reviewed');
    if(b.status==='approved'){const app=await one(db,'SELECT a.status,u.banned FROM apps a JOIN users u ON u.id=a.developer_id WHERE a.id=?',t.app_id);if(!app||app.status!=='approved'||app.banned)error(409,'App must be published and developer active before approval');}
    const qs=[];if(b.status==='approved')qs.push(stmt(db,"UPDATE apps SET url=? WHERE id=? AND status='approved' AND EXISTS(SELECT 1 FROM app_updates WHERE id=? AND status='pending')",t.url,t.app_id,id));
    qs.push(stmt(db,"UPDATE app_updates SET status=? WHERE id=? AND status='pending'",b.status,id),audit(db,u,'update_'+b.status,id));await db.batch(qs);return json({ok:true});
   }
   if(p==='/api/admin/report'){await db.batch([stmt(db,"UPDATE reports SET status='resolved' WHERE id=?",id),audit(db,u,'resolve_report',id)]);return json({ok:true});}
  }
 }
 error(404,'Endpoint not found');
}
export default {async fetch(req,env){
 let response;const p=new URL(req.url).pathname;
 try{
  if(p.startsWith('/api/'))response=await api(req,env);
  else if(p.startsWith('/icons/')){const key=decodeURIComponent(p.slice(7));if(!/^[a-f0-9-]+\/[a-f0-9-]+\.(png|jpg|webp)$/.test(key))error(404,'Icon not found');const o=await env.ICONS?.get(key);response=o?new Response(o.body,{headers:{'Content-Type':o.httpMetadata.contentType,'Cache-Control':'public,max-age=86400'}}):new Response('Not found',{status:404});}
  else response=await env.ASSETS.fetch(req);
 }catch(e){if(!e.status)console.error('Request failed',e);response=json({error:e.status?e.message:'Server error. Check database setup and Worker logs.'},e.status||500);}
 const headers=new Headers(response.headers);headers.set('X-Content-Type-Options','nosniff');headers.set('Referrer-Policy','no-referrer');headers.set('X-Frame-Options','DENY');headers.set('Permissions-Policy','camera=(), microphone=(), geolocation=()');
 headers.set('Content-Security-Policy',"default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' https:; connect-src 'self'; frame-src https:; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'");
 if(new URL(req.url).protocol==='https:')headers.set('Strict-Transport-Security','max-age=31536000');
 return new Response(response.body,{status:response.status,headers});
}};
