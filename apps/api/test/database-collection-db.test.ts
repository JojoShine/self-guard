import 'reflect-metadata';
import {test} from 'node:test';
import assert from 'node:assert/strict';
import {randomBytes} from 'node:crypto';
import {spawnSync} from 'node:child_process';
import {Db} from '../src/db';
import {DatabaseInstancesController} from '../src/database-instances';

test('collection evidence distinguishes configuration, heartbeat and actual collector records within scope',{skip:!process.env.DATABASE_URL},async()=>{
 const admin=new Db(),schema='connections_'+randomBytes(8).toString('hex');let db:Db|undefined;
 try{
  await admin.$executeRawUnsafe('CREATE SCHEMA "'+schema+'"');
  const url=new URL(process.env.DATABASE_URL!);url.searchParams.set('schema',schema);
  const migrated=spawnSync(process.execPath,['node_modules/prisma/build/index.js','migrate','deploy'],{env:{...process.env,DATABASE_URL:url.href},encoding:'utf8'});assert.equal(migrated.status,0,migrated.stderr);
  db=new Db({datasourceUrl:url.href});
  const now=new Date(),host=await db.asset.create({data:{hostname:'visible',os:'linux',lastSeen:now}}),hidden=await db.asset.create({data:{hostname:'private',os:'linux',lastSeen:now}});
  const instance=await db.databaseInstance.create({data:{name:'PG',engine:'postgresql',stableKey:'pilot',owner:'dba',hostIds:[host.id,hidden.id],auditSources:[{assetId:host.id,path:'/log/visible',format:'postgresql-stderr'},{assetId:hidden.id,path:'/log/private',format:'postgresql-stderr'}]}});
  for(const [i,id] of [host.id,hidden.id,null].entries())await db.databaseAudit.create({data:{dedupKey:'event-'+i,eventId:'event-'+i,instanceId:instance.id,collectorAssetId:id,engine:'postgresql',operation:'LOGIN',user:'pilot',timestamp:now,details:{},classification:{}}});
  const controller=new DatabaseInstancesController(db),user={email:'pilot@example.invalid',role:'ANALYST',dataScope:{restricted:true,assetIds:[host.id],databaseInstanceIds:[instance.id]}};
  assert.equal((await controller.collection({user},instance.id)).hosts.reporting,0,'registration timestamps alone are not a collector report');
  await db.asset.update({where:{id:host.id},data:{inventory:{observedAt:now.toISOString()}}});
  const snapshot=await controller.collection({user},instance.id);
  assert.equal(snapshot.sources,1);assert.equal(snapshot.hosts.authorized,1);assert.equal(snapshot.hosts.reporting,1);assert.equal(snapshot.recentEvents,1);assert.ok(snapshot.latestEventAt);
  assert.ok(!JSON.stringify(snapshot).includes('/log/private'));assert.ok(!JSON.stringify(snapshot).includes(hidden.id));
  const statement=await db.databaseAudit.create({data:{dedupKey:'sql-visible',eventId:'sql-visible',instanceId:instance.id,collectorAssetId:host.id,engine:'postgresql',operation:'SELECT',user:'pilot',timestamp:now,details:{execution:{protocol:'SIMPLE',sqlState:'00000'}},classification:{}}});
  const hiddenStatement=await db.databaseAudit.create({data:{dedupKey:'sql-private',eventId:'sql-private',instanceId:instance.id,collectorAssetId:hidden.id,engine:'postgresql',operation:'SELECT',user:'private',timestamp:now,details:{execution:{protocol:'SIMPLE',sqlState:'00000'}},classification:{}}});
  for(const auditId of [statement.id,hiddenStatement.id])await db.databaseSqlEvidence.create({data:{auditId,ciphertext:'fixture-protected-evidence',bytes:26,expiresAt:new Date(now.getTime()+3600000)}});
  const withSql=await controller.collection({user},instance.id);
  assert.equal(withSql.connections.recentEvents,1);assert.equal(withSql.statements.recentEvents,1);assert.equal(withSql.statements.retainedTextRecords,1);assert.equal(withSql.operations.recentEvents,0);assert.equal(withSql.capabilities.engine,'postgresql');
  assert.ok(!JSON.stringify(withSql).includes('fixture-protected-evidence'));
  await db.databaseInstance.update({where:{id:instance.id},data:{auditSources:[{assetId:host.id,path:'/log/raw',format:'audit-sql-json'}]}});
  assert.deepEqual((await controller.collection({user},instance.id)).statements.collectors,{required:1,ready:0},'host reporting alone does not prove raw source support');
  await db.asset.update({where:{id:host.id},data:{inventory:{observedAt:now.toISOString(),agentDiagnostics:{capabilities:['database-statements-v1']}}}});
  assert.deepEqual((await controller.collection({user},instance.id)).statements.collectors,{required:1,ready:1});
  await db.databaseSqlEvidence.update({where:{auditId:statement.id},data:{expiresAt:new Date(now.getTime()-1)}});
  assert.equal((await controller.collection({user},instance.id)).statements.retainedTextRecords,0,'expired raw evidence is not available even before cleanup');
  await assert.rejects(()=>controller.collection({user:{...user,dataScope:{...user.dataScope,databaseInstanceIds:[]}}},instance.id));
  await assert.rejects(()=>controller.collection({user:{...user,dataScope:{...user.dataScope,canReadEvidence:false}}},instance.id));
  await db.databaseAudit.deleteMany();await db.asset.update({where:{id:host.id},data:{lastSeen:null}});
  const empty=await controller.collection({user},instance.id);assert.equal(empty.hosts.reporting,0);assert.equal(empty.recentEvents,0);assert.equal(empty.latestEventAt,null);
 }finally{await db?.$disconnect();await admin.$executeRawUnsafe('DROP SCHEMA "'+schema+'" CASCADE');await admin.$disconnect();}
});
