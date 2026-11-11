import 'reflect-metadata';
import {test} from 'node:test';import assert from 'node:assert/strict';import {randomBytes} from 'node:crypto';import {spawnSync} from 'node:child_process';
import {Db} from '../src/db';import {GovernanceController} from '../src/governance';import {Platform} from '../src/platform';import {DeliveryService,seal} from '../src/maintenance';
test('assigned, overdue and escalation notices are opt-in, scoped, idempotent and in-app only',{skip:!process.env.DATABASE_URL},async()=>{
 const admin=new Db(),schema='finding_notes_'+randomBytes(8).toString('hex');let db:Db|undefined;
 try{
  await admin.$executeRawUnsafe('CREATE SCHEMA "'+schema+'"');const url=new URL(process.env.DATABASE_URL!);url.searchParams.set('schema',schema);const m=spawnSync(process.execPath,['node_modules/prisma/build/index.js','migrate','deploy'],{env:{...process.env,DATABASE_URL:url.href},encoding:'utf8'});assert.equal(m.status,0,m.stderr);db=new Db({datasourceUrl:url.href});
  const g=new GovernanceController(db,new Platform(db)),asset=await db.asset.create({data:{hostname:'visible',os:'linux'}}),hidden=await db.asset.create({data:{hostname:'hidden',os:'linux'}});
  const analyst=await db.user.create({data:{email:'owner@test.invalid',name:'owner',role:'ANALYST',passwordHash:'unused',dataScope:{restricted:true,assetIds:[asset.id]}}}),manager=await db.user.create({data:{email:'admin@test.invalid',name:'admin',role:'ADMIN',passwordHash:'unused'}});
  const due=new Date(Date.now()-25*3600000);async function finding(key:string,assetId=asset.id,status='OPEN'){return db!.finding.create({data:{dedupKey:key,externalId:key,title:key,kind:'ALERT',severity:'LOW',source:'test',evidence:'fixture',owner:analyst.email,assetId,status,dueAt:due}})}
  const f=await finding('overdue');await finding('hidden',hidden.id);await finding('resolved',asset.id,'RESOLVED');
  const req={user:analyst};assert.equal((await g.syncNotifications(req)).created,0);
  await g.setNotificationSettings(req,{assignedFindings:true,overdueFindings:true,criticalFindings:false,approvals:false,taskFailures:false});
  await Promise.all([g.syncNotifications(req),g.syncNotifications(req)]);let notes=await db.notification.findMany({where:{userId:analyst.id}});assert.equal(notes.length,2);assert.ok(notes.every(n=>n.resourceId===f.id&&n.inAppOnly));
  await db.finding.update({where:{id:f.id},data:{dueAt:new Date(Date.now()-1000)}});await g.syncNotifications(req);assert.equal(await db.notification.count({where:{userId:analyst.id}}),3);
  await g.setNotificationSettings({user:manager},{overdueFindings:true,criticalFindings:false,approvals:false,taskFailures:false});await g.syncNotifications({user:manager});const escalations=await db.notification.findMany({where:{userId:manager.id}});assert.equal(escalations.length,1);assert.match(escalations[0].title,/24小时/);assert.equal(escalations[0].resourceId,(await db.finding.findUniqueOrThrow({where:{dedupKey:'hidden'}})).id);
  await db.finding.update({where:{id:f.id},data:{assetId:hidden.id}});assert.equal((await g.notifications(req,{})).total,0);
  await db.finding.update({where:{id:f.id},data:{assetId:asset.id}});assert.ok(process.env.DATA_ENCRYPTION_KEY);await db.setting.create({data:{key:'webhook:'+analyst.id,value:{enabled:true,endpoint:seal('https://example.invalid/hook'),secret:seal('fixture-secret')}}});await db.delivery.create({data:{id:'forced-inapp-job',userId:analyst.id,notificationId:notes[0].id}});let sends=0;await new DeliveryService(db).tick(async()=>{sends++});assert.equal(sends,0);assert.equal((await db.delivery.findUniqueOrThrow({where:{id:'forced-inapp-job'}})).status,'CANCELLED');
 }finally{await db?.$disconnect();await admin.$executeRawUnsafe('DROP SCHEMA IF EXISTS "'+schema+'" CASCADE');await admin.$disconnect();}
});
