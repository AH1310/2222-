import {readFileSync,existsSync} from 'node:fs';
import {execFileSync} from 'node:child_process';
for(const p of ['src/worker.js','src/security.js','public/app.js','public/sw.js'])execFileSync(process.execPath,['--check',p],{stdio:'inherit'});
for(const p of ['wrangler.json','public/manifest.webmanifest'])JSON.parse(readFileSync(p,'utf8'));
for(const p of ['public/index.html','public/style.css','public/icon-192.png','public/icon-512.png'])if(!existsSync(p))throw Error('Missing '+p);
console.log('Build checks passed. No frontend compilation required.');
