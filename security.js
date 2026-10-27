const enc = new TextEncoder();
export const hex = b => Array.from(new Uint8Array(b), x => x.toString(16).padStart(2,'0')).join('');
export async function digest(s) { return hex(await crypto.subtle.digest('SHA-256',enc.encode(s))); }
export async function passwordHash(password, salt=hex(crypto.getRandomValues(new Uint8Array(16)))) {
 const key=await crypto.subtle.importKey('raw',enc.encode(password),'PBKDF2',false,['deriveBits']);
 const bits=await crypto.subtle.deriveBits({name:'PBKDF2',hash:'SHA-256',salt:enc.encode(salt),iterations:100000},key,256);
 return `pbkdf2$100000$${salt}$${hex(bits)}`;
}
export function equal(a,b) { if(typeof a!=='string'||typeof b!=='string')return false; let d=a.length^b.length; for(let i=0;i<Math.max(a.length,b.length);i++)d|=(a.charCodeAt(i)||0)^(b.charCodeAt(i)||0); return d===0; }
export async function verifyPassword(p,h) { const x=h?.split('$'); return x?.[0]==='pbkdf2'&&x[1]==='100000'&&equal(await passwordHash(p,x[2]),h); }
const b64 = s => btoa(s).replaceAll('+','-').replaceAll('/','_').replaceAll('=','');
async function key(s) { return crypto.subtle.importKey('raw',enc.encode(s),{name:'HMAC',hash:'SHA-256'},false,['sign','verify']); }
export async function sign(payload,secret) { const body=b64(JSON.stringify(payload)); return body+'.'+hex(await crypto.subtle.sign('HMAC',await key(secret),enc.encode(body))); }
export async function decode(token,secret) { try {const [body,sig]=token.split('.'); if(!equal(hex(await crypto.subtle.sign('HMAC',await key(secret),enc.encode(body))),sig))return null; const p=JSON.parse(atob(body.replaceAll('-','+').replaceAll('_','/')));return p.exp>Date.now()?p:null;} catch{return null;} }
export function safeURL(value) { try {const u=new URL(value); if(u.protocol!=='https:'||u.username||u.password||u.hostname==='localhost'||!u.hostname.includes('.')||/^\d+[.:]/.test(u.hostname)||u.hostname.endsWith('.local'))throw 0; return u.href;}catch{throw Object.assign(new Error('HTTPS URL required'),{status:400});} }
export function text(value,min,max) {if(typeof value!=='string'||value.trim().length<min||value.trim().length>max)throw Object.assign(new Error('Invalid text length'),{status:400});return value.trim();}
