import {mkdirSync,copyFileSync,readFileSync} from 'node:fs';
import {execFileSync} from 'node:child_process';
const files=['index.html','style.css','app.js','sw.js','logo.svg','manifest.webmanifest','icon-192.png','icon-512.png'];
for(const file of ['worker.js','security.js','app.js','sw.js'])execFileSync(process.execPath,['--check',file],{stdio:'inherit'});
JSON.parse(readFileSync('manifest.webmanifest','utf8'));
mkdirSync('.assets',{recursive:true});
for(const file of files)copyFileSync(file,'.assets/'+file);
console.log('PASS: static assets prepared safely in .assets; worker.js remains server-only.');
