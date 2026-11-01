import { test } from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, sign } from 'node:crypto';
import { validateRelease } from '../src/rollouts';

test('signed rollout registration binds exact manifest bytes and configured artifact origin',()=>{
 const {publicKey,privateKey}=generateKeyPairSync('ed25519');
 const key=publicKey.export({format:'der',type:'spki'}).subarray(-32).toString('base64');
 const raw=JSON.stringify({version:'0.2.0',sequence:1,sha256:'ab'.repeat(32),size:10,os:'linux',architecture:'amd64',expiresAt:new Date(Date.now()+3600000).toISOString()});
 const input={manifestBytes:Buffer.from(raw).toString('base64'),signature:sign(null,Buffer.from(raw),privateKey).toString('base64'),artifactUrl:'https://releases.example.test/agent'};
 assert.equal(validateRelease(input,key,['https://releases.example.test']).version,'0.2.0');
 assert.throws(()=>validateRelease({...input,artifactUrl:'http://releases.example.test/agent'},key,['https://releases.example.test']));
 assert.throws(()=>validateRelease({...input,artifactUrl:'https://releases.example.test.evil/agent'},key,['https://releases.example.test']));
 assert.throws(()=>validateRelease({...input,manifestBytes:Buffer.from(raw+' ').toString('base64')},key,['https://releases.example.test']));
 assert.throws(()=>validateRelease(input,'',[]));
});

import { randomBytes } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { Db } from '../src/db';
import { hashToken } from '../src/security';
import { RolloutsController, AgentRolloutController, RepairController } from '../src/rollouts';
import { Platform } from '../src/platform';

test('isolated PostgreSQL rollout canary, heartbeat gates, batches, failure pause and explicit approval', {skip:!process.env.DATABASE_URL},async()=>{
 const admin=new Db(), schema='rollout_test_'+randomBytes(8).toString('hex');
 const url=new URL(process.env.DATABASE_URL!);url.searchParams.set('schema',schema);
 let db:Db|undefined; const oldKey=process.env.AGENT_UPGRADE_PUBLIC_KEY,oldOrigins=process.env.AGENT_UPGRADE_ORIGINS,oldTaskKey=process.env.TASK_SIGNING_PRIVATE_KEY;
 try {
  await admin.$executeRawUnsafe('CREATE SCHEMA "'+schema+'"');
  const pushed=spawnSync(process.execPath,['node_modules/prisma/build/index.js','db','push','--skip-generate'],{env:{...process.env,DATABASE_URL:url.toString()},encoding:'utf8'});assert.equal(pushed.status,0,pushed.stderr);
  db=new Db({datasourceUrl:url.toString()});
  const platform=new Platform(db);const c=new RolloutsController(db,platform),agent=new AgentRolloutController(db);
  const user={user:{role:'ADMIN',email:'test-admin@example.test'}};
  const signing=generateKeyPairSync('ed25519');process.env.TASK_SIGNING_PRIVATE_KEY=signing.privateKey.export({format:'der',type:'pkcs8'}).toString('base64');
  const {publicKey,privateKey}=generateKeyPairSync('ed25519');process.env.AGENT_UPGRADE_PUBLIC_KEY=publicKey.export({format:'der',type:'spki'}).subarray(-32).toString('base64');process.env.AGENT_UPGRADE_ORIGINS='https://releases.example.test';
  const raw=JSON.stringify({version:'0.2.0',sequence:1,sha256:'cd'.repeat(32),size:10,os:'linux',architecture:'amd64',expiresAt:new Date(Date.now()+3600000).toISOString()});
  const assets=[];for(let i=0;i<4;i++)assets.push(await db.asset.create({data:{hostname:'fixture-'+i,identity:'fixture-'+i,os:'linux',tokenHash:hashToken('agent-'+i),inventory:{architecture:'amd64',agentDiagnostics:{version:'0.1.0'}},lastSeen:new Date()}}));
  const auth=(i:number)=>({headers:{authorization:'Bearer agent-'+i}});
  const rollout=await c.create(user,{manifestBytes:Buffer.from(raw).toString('base64'),signature:sign(null,Buffer.from(raw),privateKey).toString('base64'),artifactUrl:'https://releases.example.test/agent',targetIds:assets.map(a=>a.id),batchSize:2});
  await assert.rejects(()=>c.approve(user,rollout.id,{targetIds:[assets[1].id]}));
  await assert.rejects(()=>c.list({user:{role:'VIEWER'}}));
  await c.approve(user,rollout.id,{targetIds:assets.map(a=>a.id)});
  assert.equal((await agent.poll(auth(1))).item,null);
  const first=(await agent.poll(auth(0))).item;assert.ok(first);
  assert.equal((await agent.poll(auth(1))).item,null);
  await agent.result(auth(0),first.id,{status:'STAGED',version:'0.1.0'});
  await assert.rejects(()=>agent.result(auth(0),first.id,{status:'RUNNING',version:'0.2.0'}));
  await db.asset.update({where:{id:assets[0].id},data:{inventory:{architecture:'amd64',agentDiagnostics:{version:'0.2.0'}},lastSeen:new Date()}});
  await agent.result(auth(0),first.id,{status:'RUNNING',version:'0.2.0'});
  const second=(await agent.poll(auth(1))).item,third=(await agent.poll(auth(2))).item;assert.ok(second);assert.ok(third);assert.equal((await agent.poll(auth(3))).item,null);
  await agent.result(auth(1),second.id,{status:'FAILED',version:'0.1.0'});
  assert.equal((await db.agentRollout.findUniqueOrThrow({where:{id:rollout.id}})).status,'PAUSED');assert.equal((await agent.poll(auth(3))).item,null);
  await assert.rejects(()=>agent.result(auth(3),third.id,{status:'FAILED',version:'0.1.0'}));
  const repair=new RepairController(db,platform);
  const original=await db.task.create({data:{title:'fixture repair',assetId:assets[0].id,template:'FILE_PERMISSION',parameters:{path:'/fixture/file',mode:'0600'},status:'VERIFYING',requestedBy:'fixture',result:{success:true,evidence:'fixture'},expiresAt:new Date(Date.now()+3600000)}});
  const verification=await repair.verify(user,original.id);assert.equal(verification.template,'VERIFY_READ');assert.equal(verification.status,'APPROVED');assert.deepEqual(verification.parameters,{originalTaskId:original.id});
  const rollback=await repair.rollback(user,original.id);assert.equal(rollback.template,'ROLLBACK');assert.equal(rollback.status,'PENDING');assert.equal(rollback.rollbackOf,original.id);
  await assert.rejects(()=>repair.rollback({user:{role:'VIEWER'}},original.id));
  const failed=await db.task.create({data:{title:'never applied',assetId:assets[0].id,template:'FILE_PERMISSION',parameters:{path:'/fixture/file',mode:'0600'},status:'FAILED',requestedBy:'fixture',result:{success:false,evidence:'fixture'},expiresAt:new Date(Date.now()+3600000)}});
  await assert.rejects(()=>repair.rollback(user,failed.id));
  await c.cancel(user,rollout.id);
  const timeout=await c.create(user,{manifestBytes:Buffer.from(raw).toString('base64'),signature:sign(null,Buffer.from(raw),privateKey).toString('base64'),artifactUrl:'https://releases.example.test/agent',targetIds:[assets[3].id],batchSize:1});
  await c.approve(user,timeout.id,{targetIds:[assets[3].id]});const expired=(await agent.poll(auth(3))).item;assert.ok(expired);
  await db.agentRolloutTarget.update({where:{id:expired.id},data:{claimedAt:new Date(Date.now()-11*60000)}});
  assert.equal((await agent.poll(auth(2))).item,null);assert.equal((await db.agentRollout.findUniqueOrThrow({where:{id:timeout.id}})).status,'PAUSED');
  await c.cancel(user,timeout.id);
  const executor=generateKeyPairSync('ed25519');await db.asset.update({where:{id:assets[3].id},data:{executorPublicKey:executor.publicKey.export({format:'der',type:'spki'}).subarray(-32).toString('base64')}});
  const rootRollout=await c.create(user,{manifestBytes:Buffer.from(raw).toString('base64'),signature:sign(null,Buffer.from(raw),privateKey).toString('base64'),artifactUrl:'https://releases.example.test/agent',targetIds:[assets[3].id],batchSize:1});await c.approve(user,rootRollout.id,{targetIds:[assets[3].id]});const rootOffer=(await agent.poll(auth(3))).item;assert.ok(rootOffer?.authorization);const command=JSON.parse(Buffer.from(rootOffer.authorization.payload,'base64').toString('utf8'));assert.equal(command.template,'UPGRADE');assert.equal(command.id,rootOffer.id);assert.equal(command.assetId,assets[3].id);assert.equal(command.parameters.artifactUrl,'https://releases.example.test/agent');
  const rootResult=(version:string,processId:string,targetId=rootOffer.id)=>{const details={upgradeStaged:'true',upgradeVersion:'0.2.0',executorVersion:version,stageProcess:'old-process',executorProcess:processId};const result={success:true,evidence:'root verified staging',details};const bytes=Buffer.from(JSON.stringify({taskId:targetId,assetId:assets[3].id,result}));return {...result,details:{...details,executorProof:JSON.stringify({payload:bytes.toString('base64'),signature:sign(null,bytes,executor.privateKey).toString('base64')})}}};
  await agent.result(auth(3),rootOffer.id,{status:'STAGED',version:'0.1.0',executorResult:rootResult('0.1.0','old-process')});await db.asset.update({where:{id:assets[3].id},data:{lastSeen:new Date(),inventory:{architecture:'amd64',agentDiagnostics:{version:'0.2.0'}}}});
  // A fresh collector heartbeat cannot advance while the privileged process is still the one that staged.
  const rejected=await agent.result(auth(3),rootOffer.id,{status:'RUNNING',version:'0.2.0',executorResult:rootResult('0.2.0','old-process')});assert.equal(rejected.ok,false);assert.equal((await db.agentRolloutTarget.findUniqueOrThrow({where:{id:rootOffer.id}})).status,'UNKNOWN');assert.equal((await db.agentRollout.findUniqueOrThrow({where:{id:rootRollout.id}})).status,'PAUSED');
  await c.cancel(user,rootRollout.id);const completed=await c.create(user,{manifestBytes:Buffer.from(raw).toString('base64'),signature:sign(null,Buffer.from(raw),privateKey).toString('base64'),artifactUrl:'https://releases.example.test/agent',targetIds:[assets[3].id],batchSize:1});await c.approve(user,completed.id,{targetIds:[assets[3].id]});const completedOffer=(await agent.poll(auth(3))).item;assert.ok(completedOffer);await agent.result(auth(3),completedOffer.id,{status:'STAGED',version:'0.1.0',executorResult:rootResult('0.1.0','old-process',completedOffer.id)});await db.asset.update({where:{id:assets[3].id},data:{lastSeen:new Date()}});await agent.result(auth(3),completedOffer.id,{status:'RUNNING',version:'0.2.0',executorResult:rootResult('0.2.0','new-process',completedOffer.id)});assert.equal((await db.agentRollout.findUniqueOrThrow({where:{id:completed.id}})).status,'COMPLETED');




 } finally {
  if(oldTaskKey===undefined)delete process.env.TASK_SIGNING_PRIVATE_KEY;else process.env.TASK_SIGNING_PRIVATE_KEY=oldTaskKey;
  if(oldKey===undefined)delete process.env.AGENT_UPGRADE_PUBLIC_KEY;else process.env.AGENT_UPGRADE_PUBLIC_KEY=oldKey;
  if(oldOrigins===undefined)delete process.env.AGENT_UPGRADE_ORIGINS;else process.env.AGENT_UPGRADE_ORIGINS=oldOrigins;
  if(db)await db.$disconnect();await admin.$executeRawUnsafe('DROP SCHEMA "'+schema+'" CASCADE');await admin.$disconnect();
 }
});
