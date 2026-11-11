import {test} from 'node:test';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {probeTransfer,accessProbeCommand} from '../src/probe-artifacts';
const id='6bc04a33-c4cf-48e3-8282-9833e52d0b97';
test('private transfer verifies binary digest and keeps credentials out of command',()=>{
 const bytes=Buffer.from('probe'),sha256=createHash('sha256').update(bytes).digest('hex');
 const transfer=probeTransfer('ACCESS',id,{bytes,sha256},{token:'private-secret'});
 assert.ok(transfer.command.includes('sha256sum -c'));assert.ok(!transfer.command.includes('private-secret'));
 assert.deepEqual(JSON.parse(Buffer.from(transfer.input.trim().split('\n')[1],'base64').toString()),{token:'private-secret'});
 assert.throws(()=>probeTransfer('ACCESS',id,{bytes,sha256:'0'.repeat(64)},{}));
});
test('remote operations reject shell injection and stop both source services only',()=>{
 assert.throws(()=>accessProbeCommand(';reboot','STOP'));
 const command=accessProbeCommand(id,'STOP');assert.ok(!command.includes('selfguard-agent'));assert.ok(!command.includes('expire'));
});

import {mkdtempSync,mkdirSync,writeFileSync,readFileSync,symlinkSync,rmSync,existsSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {spawnSync} from 'node:child_process';
function fixture(){
 const root=mkdtempSync(join(tmpdir(),'probe-script-')),bin=join(root,'bin');mkdirSync(bin);mkdirSync(join(root,'systemd'));mkdirSync(join(root,'run'));
 for(const [name,body] of Object.entries({id:'echo 0',stat:'echo 0',systemctl:'printf "%s\\n" "$*" >> "$TEST_CALLS"'}))writeFileSync(join(bin,name),'#!/bin/sh\n'+body+'\n',{mode:0o755});
 const execute=(command:string,input='')=>spawnSync('/bin/sh',['-c',command.replaceAll('/etc/systemd/system',join(root,'systemd')).replaceAll('/run/systemd/system',join(root,'run')).replaceAll('/opt',join(root,'opt'))],{input,encoding:'utf8',env:{...process.env,PATH:bin+':'+process.env.PATH,TEST_CALLS:join(root,'calls')}});
 return {root,execute,clean:()=>rmSync(root,{recursive:true,force:true})};
}
test('actual stop script disables both owned services and tolerates absent services',()=>{
 const f=fixture();try{
  assert.equal(f.execute(accessProbeCommand(id,'STOP')).status,0);assert.equal(existsSync(join(f.root,'calls')),false);
  for(const suffix of ['','-capture'])writeFileSync(join(f.root,'systemd','selfguard-access-'+id+suffix+'.service'),'ExecStart=/usr/local/libexec/selfguard-access-probe-0.1.6 --config /etc/selfguard-probe/'+id+'/config.json\n');
  const result=f.execute(accessProbeCommand(id,'STOP'));assert.equal(result.status,0,result.stderr);
  assert.deepEqual(readFileSync(join(f.root,'calls'),'utf8').trim().split('\n'),['disable --now selfguard-access-'+id+'.service','disable --now selfguard-access-'+id+'-capture.service']);
 }finally{f.clean();}
});
test('actual transfer script rejects symlinks at either ancestor before writing payload',()=>{
 const bytes=Buffer.from('probe'),transfer=probeTransfer('ACCESS',id,{bytes,sha256:createHash('sha256').update(bytes).digest('hex')},{});
 for(const ancestor of ['opt','opt/selfguard-probes']){const f=fixture();try{
  const target=join(f.root,'outside');mkdirSync(target);if(ancestor.includes('/'))mkdirSync(join(f.root,'opt'));
  symlinkSync(target,join(f.root,ancestor));const result=f.execute(transfer.command,transfer.input);assert.notEqual(result.status,0);assert.equal(existsSync(join(target,id)),false);assert.equal(existsSync(join(target,'selfguard-probes')),false);
 }finally{f.clean();}}
});

test('actual CHECK reports uninstalled and inactive services without command failure',()=>{
 const f=fixture();try{
  writeFileSync(join(f.root,'bin','systemctl'),'#!/bin/sh\nexit 3\n',{mode:0o755});
  let result=f.execute(accessProbeCommand(id,'CHECK'));assert.equal(result.status,0,result.stderr);assert.match(result.stdout,/PROBE_CHECK_NOT_INSTALLED/);
  for(const suffix of ['','-capture'])writeFileSync(join(f.root,'systemd','selfguard-access-'+id+suffix+'.service'),'ExecStart=/usr/local/libexec/selfguard-access-probe-0.1.6 --config /etc/selfguard-probe/'+id+'/config.json\n');
  result=f.execute(accessProbeCommand(id,'CHECK'));assert.equal(result.status,0,result.stderr);assert.match(result.stdout,/PROBE_CHECK_NOT_RUNNING/);
  writeFileSync(join(f.root,'bin','systemctl'),'#!/bin/sh\nexit 0\n',{mode:0o755});
  result=f.execute(accessProbeCommand(id,'CHECK'));assert.equal(result.status,0,result.stderr);assert.match(result.stdout,/PROBE_CHECK_RUNNING/);
  rmSync(join(f.root,'run'),{recursive:true});result=f.execute(accessProbeCommand(id,'CHECK'));assert.equal(result.status,0);assert.match(result.stdout,/PROBE_CHECK_SYSTEMD_REQUIRED/);
  writeFileSync(join(f.root,'bin','id'),'#!/bin/sh\necho 1000\n',{mode:0o755});result=f.execute(accessProbeCommand(id,'CHECK'));assert.equal(result.status,0);assert.match(result.stdout,/PROBE_CHECK_ROOT_REQUIRED/);
 }finally{f.clean();}
});

test('actual INSTALL restarts only both source services after successful installer',()=>{
 for(const exitCode of [0,1]){const f=fixture();try{
  const directory=join(f.root,'opt','selfguard-probes',id);mkdirSync(directory,{recursive:true});
  writeFileSync(join(directory,'selfguard-access-probe'),'#!/bin/sh\nprintf "INSTALLER\\n" >> "$TEST_CALLS"\nexit '+exitCode+'\n',{mode:0o755});
  const result=f.execute(accessProbeCommand(id,'INSTALL'));
  const calls=readFileSync(join(f.root,'calls'),'utf8').trim().split('\n');
  if(exitCode===0){assert.equal(result.status,0,result.stderr);assert.deepEqual(calls,['INSTALLER','restart selfguard-access-'+id+'.service selfguard-access-'+id+'-capture.service']);assert.equal(result.stdout.trim(),'PROBE_COMMAND_OK');}
  else{assert.notEqual(result.status,0);assert.deepEqual(calls,['INSTALLER']);assert.equal(result.stdout.includes('PROBE_COMMAND_OK'),false);}
 }finally{f.clean();}}
});
