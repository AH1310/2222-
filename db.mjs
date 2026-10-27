// Never applies schema.sql blindly to an existing database.
import {readFileSync,writeFileSync,mkdirSync} from 'node:fs';
import {execFileSync} from 'node:child_process';
import {DatabaseSync} from 'node:sqlite';
export const tables=['users','apps','app_updates','library','ratings','reports','audit_log'];
export function planSchema(actual,expected){
 const additions=[],problems=[];
 for(let i=0;i<tables.length;i++){
  const name=tables[i],have=actual[i]||[],want=expected[i];
  if(!have.length)continue;
  for(const col of want){
   const old=have.find(x=>x.name===col.name);
   if(!old){
    if(name==='users'&&['banned','session_version'].includes(col.name))additions.push(`ALTER TABLE users ADD COLUMN ${col.name} INTEGER NOT NULL DEFAULT 0;`);
    else problems.push(`${name}.${col.name}: required column missing; map legacy schema first`);
   }else if(old.type.toUpperCase()!==col.type.toUpperCase()||Number(old.pk)!==Number(col.pk))problems.push(`${name}.${col.name}: type or primary key differs`);
  }
  for(const col of have)if(!want.some(x=>x.name===col.name)&&col.notnull&&col.dflt_value===null&&!col.pk)problems.push(`${name}.${col.name}: extra mandatory legacy column`);
 }
 if(problems.length)throw Error('Schema mismatch. No changes made.\n'+problems.join('\n'));
 return additions;
}
if(process.argv[1]?.endsWith('db.mjs')){
 const remote=process.argv.includes('--remote'),local=process.argv.includes('--local');if(!remote&&!local)throw Error('Pass --local or --remote');
 const target=remote?'--remote':'--local';
 const config=JSON.parse(readFileSync('wrangler.json','utf8'));
 if(remote&&config.d1_databases[0].database_id.startsWith('00000000'))throw Error('Set your existing D1 database_id in wrangler.json first.');
 const wrangler=(args)=>execFileSync(process.execPath,['node_modules/wrangler/bin/wrangler.js',...args],{encoding:'utf8',maxBuffer:20*1024*1024});
 if(remote){mkdirSync('backups',{recursive:true});const dest='backups/d1-'+new Date().toISOString().replaceAll(':','-')+'.sql';console.log(wrangler(['d1','export','ah13-store-db','--remote','--output',dest]));console.log('Backup created:',dest);}
 const command=tables.map(t=>`PRAGMA table_info(${t});`).join('\n');
 const output=wrangler(['d1','execute','ah13-store-db',target,'--command',command,'--json']);
 const actual=JSON.parse(output).map(x=>x.results);
 const mem=new DatabaseSync(':memory:');const schema=readFileSync('schema.sql','utf8');mem.exec(schema);
 const expected=tables.map(t=>mem.prepare(`PRAGMA table_info(${t})`).all());
 writeFileSync('schema-inspection.json',JSON.stringify({tables,actual},null,2));
 const additions=planSchema(actual,expected);
 // IF NOT EXISTS never replaces existing tables. Extra unique indexes support UPSERT.
 const indexes='\nCREATE UNIQUE INDEX IF NOT EXISTS ah13_users_email ON users(email);\nCREATE UNIQUE INDEX IF NOT EXISTS ah13_library_pair ON library(user_id,app_id);\nCREATE UNIQUE INDEX IF NOT EXISTS ah13_rating_pair ON ratings(user_id,app_id);\n';
 writeFileSync('schema-plan.sql',additions.join('\n')+'\n'+schema+indexes);
 console.log(wrangler(['d1','execute','ah13-store-db',target,'--file','schema-plan.sql']));
 console.log('Schema ready. Existing rows were not deleted. Inspect legacy CHECK constraints / password format before production.');
}
