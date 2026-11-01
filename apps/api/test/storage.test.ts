import 'reflect-metadata';import {test} from 'node:test';import assert from 'node:assert/strict';import {Db} from '../src/db';
import {CorrelationService} from '../src/correlation';import {Platform} from '../src/platform';
import {StorageController,assertEventCapacity,sweepStorage} from '../src/storage';
test('isolated storage limits reject new overflow and automatic cleanup obeys age and opt-in',{skip:!process.env.GOVERNANCE_TEST_ISOLATED},async()=>{
 assert.match(process.env.DATABASE_URL||'',/[?&]schema=governance_test_/);const db=new Db(),controller=new StorageController(db),req={user:{role:'ADMIN',email:'storage-test'}};
 try{await assert.rejects(()=>controller.configure({user:{role:'VIEWER'}},{automaticCleanup:true}));await controller.configure(req,{automaticCleanup:false,telemetryLimit:100,accessLimit:100,wafEventLimit:100,telemetryDays:1,accessDays:1,assetChangeDays:30});
 const old=new Date(Date.now()-3*86400000);await db.telemetryEvent.createMany({data:Array.from({length:100},(_,i)=>({source:'test',sourceKey:'test',externalId:String(i),type:'LOG',occurredAt:old,expiresAt:old,data:{}}))});
 await assert.rejects(()=>db.$transaction(async tx=>{await tx.telemetryEvent.create({data:{source:'test',sourceKey:'test',externalId:'overflow',type:'LOG',occurredAt:new Date(),expiresAt:new Date(Date.now()+86400000),data:{}}});await assertEventCapacity(tx,'telemetry',1)}),/存储上限/);await db.$transaction(tx=>assertEventCapacity(tx,'telemetry',0));
 await sweepStorage(db);assert.equal(await db.telemetryEvent.count(),100);
 await controller.configure(req,{automaticCleanup:true});const result=await sweepStorage(db);assert.equal(result?.telemetry,100);assert.equal(await db.telemetryEvent.count(),0);await db.$transaction(tx=>assertEventCapacity(tx,'telemetry',1));
 const recent=await db.telemetryEvent.create({data:{source:'test',sourceKey:'test',externalId:'recent',type:'LOG',occurredAt:new Date(),expiresAt:new Date(Date.now()+86400000),data:{}}});await sweepStorage(db);assert.ok(await db.telemetryEvent.findUnique({where:{id:recent.id}}));
 await controller.configure(req,{telemetryDays:90});const now=Date.now();await new CorrelationService(db,new Platform(db)).ingest('test','test-retention',[{id:'retention90',type:'LOG',timestamp:new Date(now).toISOString(),data:{}}]);const stored=await db.telemetryEvent.findFirstOrThrow({where:{externalId:'retention90'}});assert.ok(stored.expiresAt.getTime()-now>=90*86400000);assert.ok(stored.expiresAt.getTime()-now<90*86400000+10000);
 const stats=await controller.status(req);assert.equal(stats.counts.telemetry,2);assert.equal(stats.policy.telemetryLimit,100);
 }finally{await db.$disconnect();}
});
