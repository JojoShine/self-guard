import {test} from 'node:test';import assert from 'node:assert/strict';
import {sshDeploymentInput,sshArguments,remoteInstallCommand} from '../src/ssh-installations';

test('SSH deployment requires pinned host keys, explicit targets and bounded concurrency',()=>{
 const valid={name:'Production installation',releaseId:'12345678-1234-4234-9234-123456789abc',server:'https://guard.example',username:'root',privateKey:'-----BEGIN OPENSSH PRIVATE KEY-----\n'+'a'.repeat(100)+'\n-----END OPENSSH PRIVATE KEY-----',targets:[{assetId:'12345678-1234-4234-9234-123456789abc',hostKey:'ssh-ed25519 '+Buffer.alloc(32).toString('base64')}]};
 assert.equal(sshDeploymentInput.parse(valid).concurrency,5);
 for(const input of [{...valid,targets:[]},{...valid,concurrency:101},{...valid,username:'root -o ProxyCommand=evil'},{...valid,targets:[{...valid.targets[0],hostKey:'* ssh-ed25519 key'}]}])assert.equal(sshDeploymentInput.safeParse(input).success,false);
});
test('SSH arguments always isolate configuration and force host key checks, with no secret arguments',()=>{
 const args=sshArguments('192.0.2.12',22,'root','/tmp/key','/tmp/known-hosts','fixed command');
 assert.ok(args.includes('StrictHostKeyChecking=yes'));assert.ok(args.includes('BatchMode=yes'));assert.ok(args.includes('IdentitiesOnly=yes'));assert.ok(args.includes('/dev/null'));assert.ok(!args.join(' ').includes('PRIVATE KEY'));
 assert.throws(()=>sshArguments('-oProxyCommand=evil',22,'root','/tmp/key','/tmp/known-hosts','fixed command'));
 const command=remoteInstallCommand('https://guard.example','12345678-1234-4234-9234-123456789abc','a'.repeat(64),'A'.repeat(44));assert.ok(command.includes('sha256sum -c -'));assert.ok(!command.includes('StrictHostKeyChecking=no'));assert.ok(!command.includes('curl -k'));assert.ok(command.includes('sudo -n'));assert.ok(command.includes('read -r ticket'));
});
test('SSH bootstrap carries the explicitly configured CA through download and sudo installation',()=>{
 const ca='-----BEGIN CERTIFICATE-----\nfixture\n-----END CERTIFICATE-----';
 const command=remoteInstallCommand('https://guard.example','12345678-1234-4234-9234-123456789abc','a'.repeat(64),'A'.repeat(44),ca);
 assert.ok(command.includes('--cacert'));assert.ok(command.includes('AGENT_CA_FILE='));assert.ok(command.includes(Buffer.from(ca).toString('base64')));assert.ok(!command.includes('curl -k'));
});

test('pinned SSH trust never falls back to global host files or DNS trust',()=>{
 const args=sshArguments('2001:db8::1',2222,'operator','/tmp/key','/tmp/hosts','command');
 assert.ok(args.includes('GlobalKnownHostsFile=/dev/null'));assert.ok(args.includes('VerifyHostKeyDNS=no'));assert.ok(args.includes('UpdateHostKeys=no'));
});

import 'reflect-metadata';
import {Db} from '../src/db';import {SshInstallationService} from '../src/ssh-installations';import {InstallationService} from '../src/installations';
import {generateKeyPairSync,sign,randomBytes} from 'node:crypto';import {spawnSync} from 'node:child_process';
test('SSH batch persists encrypted credentials, requires exact approval and keeps cancellation separate from uninstall',{skip:!process.env.DATABASE_URL},async()=>{
 const admin=new Db(),schema='ssh_install_test_'+randomBytes(8).toString('hex');let db:Db|undefined;const saved={root:process.env.AGENT_UPGRADE_PUBLIC_KEY,encryption:process.env.DATA_ENCRYPTION_KEY};
 try{await admin.$executeRawUnsafe('CREATE SCHEMA "'+schema+'"');const url=new URL(process.env.DATABASE_URL!);url.searchParams.set('schema',schema);const setup=spawnSync(process.execPath,['node_modules/prisma/build/index.js','db','push','--skip-generate'],{env:{...process.env,DATABASE_URL:url.toString()},encoding:'utf8'});assert.equal(setup.status,0,setup.stderr);
  db=new Db({datasourceUrl:url.toString()});const user=await db.user.create({data:{email:'operator@ssh.local',name:'Operator',role:'OPERATOR',passwordHash:'unused',dataScope:{restricted:true,businesses:['A']}}});
  const good=await db.asset.create({data:{hostname:'authorized',os:'linux',ip:'192.0.2.10',business:'A'}}),bad=await db.asset.create({data:{hostname:'other',os:'linux',ip:'192.0.2.11',business:'B'}});
  const keys=generateKeyPairSync('ed25519');process.env.AGENT_UPGRADE_PUBLIC_KEY=keys.publicKey.export({format:'der',type:'spki'}).subarray(-32).toString('base64');process.env.DATA_ENCRYPTION_KEY='34'.repeat(32);
  const manifest={version:'1.0.0',sequence:1,sha256:'a'.repeat(64),size:1,os:'linux',architecture:'arm64',expiresAt:new Date(Date.now()+86400000).toISOString()},raw=Buffer.from(JSON.stringify(manifest));
  const release=await db.agentRelease.create({data:{version:'1.0.0',sequence:1,architecture:'arm64',sha256:manifest.sha256,size:1,expiresAt:new Date(manifest.expiresAt),manifestBytes:raw.toString('base64'),signature:sign(null,raw,keys.privateKey).toString('base64'),sourceDigest:'b'.repeat(64),license:'Internal',sbom:{},author:user.email,status:'PUBLISHED'}});
  const service=new SshInstallationService(db,new InstallationService(db));const key='-----BEGIN OPENSSH PRIVATE KEY-----\n'+'a'.repeat(100)+'\n-----END OPENSSH PRIVATE KEY-----';const body={name:'Scoped installation',releaseId:release.id,server:'https://guard.example',username:'root',privateKey:key,targets:[{assetId:good.id,hostKey:'ssh-ed25519 '+Buffer.alloc(32).toString('base64')}]};
  await assert.rejects(()=>service.create(user,{...body,targets:[{...body.targets[0],assetId:bad.id}]}));const batch=await service.create(user,body);assert.ok(!JSON.stringify(batch).includes(key));assert.ok(!JSON.stringify(await service.list(user,{})).includes('credential'));const stored=await db.agentInstallBatch.findUniqueOrThrow({where:{id:batch.id}});assert.ok(!stored.credential.includes(key));
  await assert.rejects(()=>service.state(user,batch.id,'start',{assetIds:[bad.id]}));await service.state(user,batch.id,'start',{assetIds:[good.id]});await service.state(user,batch.id,'cancel');
  const cancelled=await db.agentInstallBatch.findUniqueOrThrow({where:{id:batch.id},include:{targets:true}});assert.equal(cancelled.status,'CANCELLED');assert.equal(cancelled.targets[0].status,'CANCELLED');assert.equal(await db.asset.count(),2);
  assert.equal((await service.list({...user,dataScope:{restricted:true,businesses:['B']}},{})).total,0);
  const second=await service.create(user,body);await db.agentInstallTarget.updateMany({where:{batchId:second.id},data:{status:'RUNNING',leaseUntil:new Date(0)}});await db.agentInstallBatch.update({where:{id:second.id},data:{status:'RUNNING'}});await service.tick();const stopped=await db.agentInstallBatch.findUniqueOrThrow({where:{id:second.id},include:{targets:true}});assert.equal(stopped.status,'PAUSED');assert.equal(stopped.targets[0].status,'UNKNOWN');
  const accepted=await db.agentInstallation.create({data:{releaseId:release.id,ownerId:user.id,profile:{},ticketHash:randomBytes(32).toString('hex'),challenge:'test',expiresAt:new Date(),status:'SUCCEEDED'}});await db.agentInstallTarget.update({where:{id:stopped.targets[0].id},data:{installationId:accepted.id}});await service.tick();assert.equal((await db.agentInstallTarget.findUniqueOrThrow({where:{id:stopped.targets[0].id}})).status,'SUCCEEDED');
 }finally{process.env.AGENT_UPGRADE_PUBLIC_KEY=saved.root||'';process.env.DATA_ENCRYPTION_KEY=saved.encryption||'';await db?.$disconnect();await admin.$executeRawUnsafe('DROP SCHEMA "'+schema+'" CASCADE');await admin.$disconnect();}
});

import {sshFailureReason} from '../src/ssh-installations';
test('SSH diagnostics explain known failures without persisting arbitrary remote secrets',()=>{
 assert.match(sshFailureReason('Host key verification failed. PRIVATE KEY secret'),/主机密钥/);
 assert.match(sshFailureReason('Permission denied (publickey).'),/凭据/);
 assert.match(sshFailureReason('sudo: a password is required'),/免交互/);
 assert.ok(!sshFailureReason('PRIVATE KEY secret-token-value').includes('secret-token-value'));
});

test('SSH bootstrap carries the same explicit proxy and persistent state profile',()=>{
 const command=remoteInstallCommand('https://guard.example','12345678-1234-4234-9234-123456789abc','a'.repeat(64),'A'.repeat(44),'',{proxyUrl:'http://proxy.example:3128',stateDir:'/var/lib/selfguard-agent-production'});
 assert.ok(command.includes('--proxy'));assert.ok(command.includes('AGENT_PROXY_URL='));assert.ok(command.includes('AGENT_INSTALL_STATE_DIR='));assert.ok(command.includes('install_env=(/usr/bin/env'));assert.ok(command.includes('AGENT_PROXY_MODE='));
});
