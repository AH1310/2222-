import {existsSync,writeFileSync} from 'node:fs';import {randomBytes} from 'node:crypto';
if(existsSync('.dev.vars'))throw Error('.dev.vars already exists; leaving it unchanged.');
writeFileSync('.dev.vars',`SESSION_SECRET="${randomBytes(48).toString('hex')}"\nBOOTSTRAP_TOKEN="${randomBytes(48).toString('hex')}"\n`);console.log('Created local-only secrets in .dev.vars. Never commit this file.');
