import {test} from 'node:test';import assert from 'node:assert/strict';
import {mkdtempSync,writeFileSync,readFileSync,existsSync,rmSync} from 'node:fs';
import {join,dirname,delimiter} from 'node:path';import {tmpdir} from 'node:os';
import {createHash} from 'node:crypto';import {spawnSync} from 'node:child_process';
import {remoteInstallCommand} from '../src/ssh-installations';import {installationDiagnostic} from '../src/ssh-install-progress';
function fixture(){
 const dir=mkdtempSync(join(tmpdir(),'selfguard bootstrap ')),ticket='a'.repeat(43);
 const program='#!/bin/bash\nread -r ticket\n[ "$ticket" = "$SG_FIXTURE_TICKET" ] || exit 1\nif [ -n "${AGENT_CA_FILE:-}" ]; then [ -s "$AGENT_CA_FILE" ] || exit 1; fi\nprintf ok > "$SG_FIXTURE_DIRECTORY/ran"\n';
 writeFileSync(join(dir,'program'),program);
 // Use this test's Node runtime; target hosts do not need Node for the bootstrap.
 writeFileSync(join(dir,'curl'),`#!/usr/bin/env node
const fs=require('node:fs'),path=require('node:path'),args=process.argv.slice(2),directory=process.env.SG_FIXTURE_DIRECTORY;
if(args.some(value=>value.includes(process.env.SG_FIXTURE_TICKET)))throw Error('ticket leaked into curl arguments');
const url=args.find(value=>value.startsWith('https:')),out=args[args.indexOf('-o')+1];
if(!url||!out)throw Error('unexpected curl invocation');
fs.appendFileSync(path.join(directory,'requests'),JSON.stringify(args)+'\\n');
if(url.endsWith('/api/health/ready')){
 if(process.env.TEST_PLATFORM==='404'){console.error('curl: (22) The requested URL returned error: 404');process.exit(22)}
 fs.writeFileSync(out,process.env.TEST_PLATFORM==='HTML'?'<html>site</html>':JSON.stringify({ready:true}));
}else{
 fs.appendFileSync(path.join(directory,'downloads'),'attempt\\n');
 if(process.env.TEST_PLATFORM==='DOWNLOAD404'){console.error('curl: (22) The requested URL returned error: 404');process.exit(22)}
 const input=fs.readFileSync(0,'utf8');if(!input.includes('Bearer '+process.env.SG_FIXTURE_TICKET))throw Error('missing installation authorization');
 fs.writeFileSync(out,process.env.TEST_PLATFORM==='CORRUPT'?'untrusted replacement':fs.readFileSync(path.join(directory,'program')));
}
`,{mode:0o700});
 // Exercise the non-root path without using the machine's real privilege elevation.
 writeFileSync(join(dir,'sudo'),'#!/bin/sh\n[ "$1" = "-n" ] || exit 2\nshift\nexec "$@"\n',{mode:0o700});
 const digest=createHash('sha256').update(program).digest('hex');
 function run(mode:string,proxyMode='DIRECT',caCertificate=''){
  const command=remoteInstallCommand('https://owned.invalid','12345678-1234-4234-9234-123456789abc',digest,'A'.repeat(44),caCertificate,{proxyMode,...(proxyMode==='EXPLICIT'?{proxyUrl:'http://proxy.invalid:3128'}:{})});
  return spawnSync('/bin/bash',['-c',command],{input:ticket+'\n',encoding:'utf8',env:{...process.env,PATH:[dir,dirname(process.execPath),process.env.PATH].join(delimiter),TMPDIR:dir,TEST_PLATFORM:mode,SG_FIXTURE_DIRECTORY:dir,SG_FIXTURE_TICKET:ticket}});
 }
 return {dir,run,ticket,close:()=>rmSync(dir,{recursive:true,force:true})};
}
test('bootstrap validates public platform API before using the installation ticket and reports stage failures',()=>{
 const f=fixture();try{
  for(const mode of ['404','HTML']){const result=f.run(mode);assert.notEqual(result.status,0,result.stderr);assert.equal(existsSync(join(f.dir,'downloads')),false);assert.equal(existsSync(join(f.dir,'ran')),false);assert.equal(installationDiagnostic(result.stderr)?.uncertain,false);assert.ok(!result.stderr.includes(f.ticket));}
  const download=f.run('DOWNLOAD404');assert.notEqual(download.status,0);assert.match(installationDiagnostic(download.stderr)!.detail,/404/);assert.equal(existsSync(join(f.dir,'ran')),false);
  const corrupt=f.run('CORRUPT');assert.notEqual(corrupt.status,0);assert.match(corrupt.stderr,/SELFGUARD_INSTALL_FAILED:VERIFY:/);assert.equal(existsSync(join(f.dir,'ran')),false);
 }finally{f.close()}
});
test('bootstrap supports empty CA and proxy arrays and preserves argument boundaries on the host Bash',()=>{
 for(const proxyMode of ['DIRECT','ENVIRONMENT','EXPLICIT']){const f=fixture();try{
  const result=f.run('OK',proxyMode);assert.equal(result.status,0,result.stderr);assert.equal(readFileSync(join(f.dir,'ran'),'utf8'),'ok');
  const requests=readFileSync(join(f.dir,'requests'),'utf8').trim().split('\n').map(line=>JSON.parse(line) as string[]);assert.equal(requests.length,2);
  for(const args of requests){assert.equal(args.includes('--cacert'),false);assert.equal(args.includes('-k'),false);assert.ok(args.includes('--fail'));if(proxyMode==='DIRECT'){assert.equal(args[args.indexOf('--noproxy')+1],'*');assert.equal(args[args.indexOf('--proxy')+1],'');}if(proxyMode==='ENVIRONMENT')assert.equal(args.includes('--proxy'),false);}
 }finally{f.close()}}
});
test('bootstrap passes the approved CA to verification and install without relaxing TLS',()=>{
 const f=fixture();try{
  const result=f.run('OK','ENVIRONMENT','owned test CA\n');assert.equal(result.status,0,result.stderr);
  const requests=readFileSync(join(f.dir,'requests'),'utf8').trim().split('\n').map(line=>JSON.parse(line) as string[]);assert.ok(requests.every(args=>args.includes('--cacert')&&!args.includes('-k')));
  for(const args of requests)assert.equal(existsSync(args[args.indexOf('--cacert')+1]),false,'temporary CA must be removed');
 }finally{f.close()}
});
