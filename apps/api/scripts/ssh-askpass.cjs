#!/usr/bin/env node
// Password is read from a private file, never from argv or a plaintext environment value.
const fs=require('node:fs');try{const file=process.env.SELFGUARD_SSH_PASSWORD_FILE,st=fs.lstatSync(file);if(!st.isFile()||(st.mode&0o077)!==0||st.uid!==process.getuid())process.exit(1);const password=fs.readFileSync(file,'utf8');if(/[\r\n\x00]/.test(password))process.exit(1);process.stdout.write(password+'\n')}catch{process.exit(1)}
