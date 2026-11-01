const fs=require('node:fs'),crypto=require('node:crypto');

function atomicWrite(file,contents,mode){
 const temporary=file+'.tmp-'+process.pid+'-'+crypto.randomBytes(6).toString('hex');
 try{fs.writeFileSync(temporary,contents,{flag:'wx',mode});fs.renameSync(temporary,file);}finally{fs.rmSync(temporary,{force:true});}
}
function provision(){
 if(!fs.existsSync('.env'))throw Error('Run init-env first');
 const text=fs.readFileSync('.env','utf8');
 if(!text)throw Error('Run init-env first');
 const lines=text.split(/\r?\n/),names=['DATA_ENCRYPTION_KEY','TASK_SIGNING_PRIVATE_KEY'];
 const assignments=lines.map(line=>line.match(/^\s*(?:export\s+)?(DATA_ENCRYPTION_KEY|TASK_SIGNING_PRIVATE_KEY)\s*=\s*(.*)$/));
 const values={};
 for(const name of names){
  const existing=[...new Set(assignments.filter(match=>match&&match[1]===name).map(match=>match[2]).filter(value=>value!==''))];
  if(existing.length>1)throw Error('Conflicting duplicate assignments for '+name+'; resolve them before provisioning');
  values[name]=existing[0]||'';
 }
 if(values.DATA_ENCRYPTION_KEY&&!/^[a-f0-9]{64}$/i.test(values.DATA_ENCRYPTION_KEY))throw Error('DATA_ENCRYPTION_KEY must be 32 bytes encoded as hexadecimal');
 if(!values.DATA_ENCRYPTION_KEY)values.DATA_ENCRYPTION_KEY=crypto.randomBytes(32).toString('hex');
 if(!values.TASK_SIGNING_PRIVATE_KEY){const {privateKey}=crypto.generateKeyPairSync('ed25519');values.TASK_SIGNING_PRIVATE_KEY=privateKey.export({format:'der',type:'pkcs8'}).toString('base64');}
 let key;
 try{
  const der=Buffer.from(values.TASK_SIGNING_PRIVATE_KEY,'base64');
  if(der.toString('base64')!==values.TASK_SIGNING_PRIVATE_KEY)throw Error('invalid base64');
  key=crypto.createPrivateKey({key:der,format:'der',type:'pkcs8'});
  if(key.asymmetricKeyType!=='ed25519')throw Error('invalid algorithm');
 }catch{throw Error('TASK_SIGNING_PRIVATE_KEY must be an Ed25519 PKCS8 DER key encoded as canonical Base64');}
 const publicKey=crypto.createPublicKey(key).export({format:'der',type:'spki'}).subarray(-32).toString('base64');
 const seen=new Set(),normalized=[];
 for(let i=0;i<lines.length;i++){
  const assignment=assignments[i];
  if(!assignment){normalized.push(lines[i]);continue;}
  const name=assignment[1];if(seen.has(name))continue;seen.add(name);normalized.push(name+'='+values[name]);
 }
 while(normalized.at(-1)==='')normalized.pop();
 for(const name of names)if(!seen.has(name))normalized.push(name+'='+values[name]);
 atomicWrite('.env',normalized.join('\n')+'\n',0o600);
 fs.mkdirSync('.artifacts',{recursive:true});
 atomicWrite('.artifacts/executor-public-key.txt',publicKey+'\n',0o644);
 console.log('Required private keys are configured; public executor key saved in .artifacts/executor-public-key.txt. Existing nonempty keys preserved.');
}
try{provision();}catch(error){console.error(error.message);process.exitCode=1;}
