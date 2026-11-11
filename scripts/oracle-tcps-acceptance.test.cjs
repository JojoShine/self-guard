const {test}=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),os=require('node:os'),path=require('node:path'),{spawnSync}=require('node:child_process');
const root=path.resolve(__dirname,'..'),pki=process.env.SG_VENDOR_ACCEPT_PKI_JAR;
function simulate(mode){const tmp=fs.mkdtempSync(path.join(os.tmpdir(),'sg-tcps-safety-')),trace=path.join(tmp,'trace.jsonl');let ownedTemp;
 try{fs.writeFileSync(path.join(tmp,'openssl'),'#!/bin/sh\nexit 0\n',{mode:0o700});fs.writeFileSync(path.join(tmp,'docker'),`#!/usr/bin/env node
const fs=require('node:fs'),path=require('node:path'),args=process.argv.slice(2),file=process.env.SG_STUB_TRACE;
fs.appendFileSync(file,JSON.stringify(args)+'\\n');
if(process.env.SG_STUB_MODE==='collision'){if(args[0]==='run'||args[0]==='create'){console.error('Conflict: name belongs to another existing container');process.exit(125)}process.exit(0)}
if(args[0]==='run'||args[0]==='create'){
 const volume=args.find(v=>v.endsWith(':/fixture'));if(volume)fs.writeFileSync(file+'.fixture',volume.slice(0,-':/fixture'.length));
 if(args[0]==='run'&&args.includes('--rm'))fs.writeFileSync(path.join(fs.readFileSync(file+'.fixture','utf8'),'wallet/cwallet.sso'),'fixture');
 console.log(args.includes('-p')?'b'.repeat(64):'a'.repeat(64));
}else if(args[0]==='start'&&args.includes('-a')){fs.writeFileSync(path.join(fs.readFileSync(file+'.fixture','utf8'),'wallet/cwallet.sso'),'fixture');}
else if(args[0]==='inspect')console.log('running');
else if(args[0]==='logs')console.log('DATABASE IS READY TO USE!');
else if(args[0]==='rm'){console.error('simulated removal failure');process.exit(1)}
`,{mode:0o700});
 const run=spawnSync(process.execPath,[path.join(root,'scripts/oracle-tcps-acceptance.cjs')],{cwd:root,encoding:'utf8',timeout:20000,env:{...process.env,PATH:tmp+path.delimiter+process.env.PATH,SG_VENDOR_ACCEPT_PKI_JAR:pki,SG_STUB_TRACE:trace,SG_STUB_MODE:mode}});
 const calls=fs.existsSync(trace)?fs.readFileSync(trace,'utf8').trim().split('\n').filter(Boolean).map(JSON.parse):[];
 const volume=calls.flat().find(v=>v.endsWith(':/fixture'));if(volume)ownedTemp=volume.slice(0,-':/fixture'.length);
 assert.equal(run.status,1,'negative safety fixture must fail');return{calls,ownedTemp,remaining:ownedTemp&&fs.existsSync(ownedTemp)};
 }finally{if(ownedTemp)fs.rmSync(ownedTemp,{recursive:true,force:true});fs.rmSync(tmp,{recursive:true,force:true});}
}
test('failed creation never removes a pre-existing container',{skip:!pki},()=>{const result=simulate('collision');assert.equal(result.calls.filter(a=>a[0]==='rm').length,0);});
test('temporary credentials are removed even when Docker cleanup fails',{skip:!pki},()=>{const result=simulate('cleanup');assert.ok(result.ownedTemp);assert.equal(result.remaining,false);assert.equal(result.calls.filter(a=>a[0]==='rm').length,2,'attempt cleanup of every owned container');});
