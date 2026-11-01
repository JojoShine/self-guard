import 'reflect-metadata';
import {test} from 'node:test';
import assert from 'node:assert/strict';
import {randomBytes} from 'node:crypto';
import {spawnSync} from 'node:child_process';
import {Db} from '../src/db';
import {ReportsController} from '../src/reports';

test('isolated detailed reports apply the same UTC creation-date and business scope to every dimension',{skip:!process.env.DATABASE_URL},async()=>{
 const admin=new Db(),schema='reports_test_'+randomBytes(8).toString('hex');const url=new URL(process.env.DATABASE_URL!);url.searchParams.set('schema',schema);let db:Db|undefined;
 try{
  await admin.$executeRawUnsafe('CREATE SCHEMA "'+schema+'"');const setup=spawnSync(process.execPath,['node_modules/prisma/build/index.js','db','push','--skip-generate'],{env:{...process.env,DATABASE_URL:url.toString()},encoding:'utf8'});assert.equal(setup.status,0,setup.stderr);
  db=new Db({datasourceUrl:url.toString()});const c=new ReportsController(db);
  const user={email:'mine@test.local',name:'Mine',role:'ANALYST',dataScope:{restricted:true,businesses:['A'],canReadEvidence:false}};
  const a=await db.asset.create({data:{hostname:'A',os:'Linux',business:'A',createdAt:new Date('2026-10-02T00:00:00Z')}});
  const b=await db.asset.create({data:{hostname:'B',os:'Linux',business:'B',createdAt:new Date('2026-10-02T00:00:00Z')}});
  const archived=await db.asset.create({data:{hostname:'archived A',os:'Linux',business:'A',archivedAt:new Date(),createdAt:new Date('2026-10-03T00:00:00Z')}});
  const f=async(title:string,assetId:string,createdAt:string,status='OPEN',kind='RISK',owner=user.email)=>db!.finding.create({data:{title,assetId,createdAt:new Date(createdAt),kind,status,owner,dueAt:new Date('2026-10-01T00:00:00Z'),dedupKey:title,externalId:title,severity:'HIGH',source:'test',evidence:'PRIVATE-EVIDENCE'}});
  await f('included',a.id,'2026-10-02T00:00:00Z');await f('endday',archived.id,'2026-10-03T23:59:59.999Z','CLOSED');await f('before',a.id,'2026-10-01T23:59:59.999Z');await f('after',a.id,'2026-10-04T00:00:00Z');await f('hidden',b.id,'2026-10-02T00:00:00Z');await f('alert',a.id,'2026-10-03T00:00:00Z','IN_PROGRESS','ALERT','Mine');
  const t=async(title:string,assetId:string,status:string,template='FILE_PERMISSION',createdAt='2026-10-02T00:00:00Z')=>db!.task.create({data:{title,assetId,status,template,createdAt:new Date(createdAt),requestedBy:user.email,parameters:{secret:'PRIVATE-PARAMETERS'},expiresAt:new Date(Date.now()+3600000)}});
  await t('success',a.id,'SUCCEEDED');await t('failure',a.id,'FAILED');await t('rollback',archived.id,'ROLLED_BACK');await t('pending',a.id,'PENDING');await t('child',a.id,'SUCCEEDED','VERIFY_READ');await t('hidden-success',b.id,'SUCCEEDED');await t('outside',a.id,'SUCCEEDED','FILE_PERMISSION','2026-10-04T00:00:00Z');
  const report=await c.detailed({user},{from:'2026-10-02',to:'2026-10-03'});
  assert.deepEqual(report.filters,{from:'2026-10-02',to:'2026-10-03',business:null});assert.equal(report.timezone,'UTC');assert.match(report.basis,/创建/);
  assert.deepEqual(report.totals,{assetsCreated:2,risksCreated:2,alertsCreated:1,openFindings:2,closedFindings:1,tasksCreated:5});
  assert.deepEqual(report.personal,{assignedOpenFindings:2,overdueFindings:2,myActiveTasks:1});assert.deepEqual(report.repairOutcomes,{succeeded:1,failed:1,rolledBack:1});
  assert.deepEqual(report.businesses,[{business:'A',assetsCreated:2,risksCreated:2,alertsCreated:1,tasksCreated:5}]);
  assert.equal(report.trends.length,2);assert.deepEqual(report.trends[0],{day:'2026-10-02',assetsCreated:1,risksCreated:1,alertsCreated:0,tasksCreated:5,closedFindings:0});assert.equal(report.trends[1].closedFindings,1);
  const encoded=JSON.stringify(report);assert.ok(!encoded.includes('PRIVATE-'));assert.ok(!encoded.includes(b.id));
  const denied=await c.detailed({user},{from:'2026-10-02',to:'2026-10-03',business:'B'});assert.equal(denied.totals.risksCreated,0);assert.deepEqual(denied.businesses,[]);assert.equal(denied.trends[0].tasksCreated,0);
  const selected=await c.detailed({user:{...user,role:'ADMIN'}},{from:'2026-10-02',to:'2026-10-03',business:'B'});assert.equal(selected.totals.risksCreated,1);assert.equal(selected.totals.assetsCreated,1);assert.equal(selected.repairOutcomes.succeeded,1);assert.equal(selected.personal.myActiveTasks,0);assert.equal(selected.filters.business,'B');
  await assert.rejects(()=>c.detailed({user},{from:'2026-02-30',to:'2026-03-01'}));await assert.rejects(()=>c.detailed({user},{from:'2026-10-03',to:'2026-10-02'}));await assert.rejects(()=>c.detailed({user},{from:'2024-01-01',to:'2026-10-03'}));
 }finally{await db?.$disconnect();await admin.$executeRawUnsafe('DROP SCHEMA "'+schema+'" CASCADE');await admin.$disconnect();}
});
