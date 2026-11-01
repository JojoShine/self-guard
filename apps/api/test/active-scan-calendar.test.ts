import 'reflect-metadata';
import {test} from 'node:test';
import assert from 'node:assert/strict';
import {randomBytes} from 'node:crypto';
import {spawnSync} from 'node:child_process';
import {setTimeout as delay} from 'node:timers/promises';
import {Db} from '../src/db';
import {Platform} from '../src/platform';
import {ActiveScansController,processActiveScans,queueDueActiveScans} from '../src/active-scans';
import {approvedProbeFixture} from './approved-probe-fixture';

async function ownedCalendar(run:(db:Db,req:any,plans:ActiveScansController,choice:any)=>Promise<void>){
 const admin=new Db(),schema='active_calendar_'+randomBytes(8).toString('hex');let db:Db|undefined,created=false;
 try{
  await admin.$executeRawUnsafe('CREATE SCHEMA "'+schema+'"');created=true;
  const url=new URL(process.env.DATABASE_URL!);url.searchParams.set('schema',schema);
  const migrated=spawnSync(process.execPath,['node_modules/prisma/build/index.js','migrate','deploy'],{env:{...process.env,DATABASE_URL:url.href},encoding:'utf8'});assert.equal(migrated.status,0,migrated.stderr);
  db=new Db({datasourceUrl:url.href});const user=await db.user.create({data:{email:'calendar@fixture.test',name:'Owned calendar administrator',role:'ADMIN',passwordHash:'fixture'}}),req={user},asset=await db.asset.create({data:{hostname:'Owned actual calendar target',os:'linux'}});
  const fixture=await approvedProbeFixture(db,user,asset,{hostname:process.env.SCAN_TEST_HOST!,port:8089,protocol:'http',allowedPaths:['/public'],excludedPaths:[]},[{method:'GET',path:'/public/known',rule:{description:'Only the actual owned marker',operator:'ALL',conditions:[{kind:'STATUS',status:200},{kind:'BODY_CONTAINS',value:'owned-probe-fixture'}]}}]);
  await run(db,req,new ActiveScansController(db),{endpointIds:[fixture.endpoint.id],templateIds:fixture.templates.map(row=>row.id),scope:{include:[{assetIds:[asset.id]}]}});
 }finally{await db?.$disconnect();if(created)await admin.$executeRawUnsafe('DROP SCHEMA "'+schema+'" CASCADE');await admin.$disconnect()}
}

test('active metadata edits preserve an interval due time and permit renaming an elapsed once plan',{skip:!process.env.DATABASE_URL||!process.env.SCAN_TEST_HOST},async()=>{
 await ownedCalendar(async(db,req,plans,choice)=>{
  const preview=await plans.preview(req,choice),interval=await plans.create(req,{...choice,name:'Owned preserved interval',timing:{kind:'INTERVAL',timezone:'UTC',seconds:3600},previewHash:preview.previewHash});
  await delay(30);const renamed=await plans.patch(req,interval.id,{name:'Owned renamed interval',expectedVersion:interval.version});
  assert.equal(renamed.nextRunAt?.toISOString(),interval.nextRunAt?.toISOString(),'A name edit must not postpone an existing scheduled check');
  const tomorrow=new Date(Date.now()+86400000).toISOString().slice(0,10),once=await plans.create(req,{...choice,name:'Owned elapsed once fixture',timing:{kind:'ONCE',timezone:'UTC',date:tomorrow,time:'09:00'},previewHash:preview.previewHash});
  // Explicit persistence fixture for an already elapsed schedule; the natural
  // clock scheduling test below separately verifies actual execution cadence.
  const elapsed={kind:'ONCE',timezone:'UTC',date:'2000-01-01',time:'09:00',windows:[]};await db.scanPlan.update({where:{id:once.id},data:{timing:elapsed,nextRunAt:null}});
  const historyEdit=await plans.patch(req,once.id,{name:'Owned elapsed plan renamed',expectedVersion:once.version});assert.equal(historyEdit.nextRunAt,null);assert.deepEqual(historyEdit.timing,elapsed);
  await plans.patch(req,once.id,{enabled:false,expectedVersion:historyEdit.version});await assert.rejects(()=>plans.patch(req,once.id,{enabled:true,expectedVersion:historyEdit.version+1}),/未来时间/);
 });
});

test('actual minute calendar and once schedules queue exactly once with shared budgets and frozen evidence',{skip:process.env.SCAN_CALENDAR_ACCEPTANCE!=='true'||!process.env.SCAN_TEST_HOST||!process.env.DATABASE_URL,timeout:150000},async()=>{
 await ownedCalendar(async(db,req,plans,choice)=>{
  const due=new Date(Math.ceil((Date.now()+15000)/60000)*60000),date=due.toISOString().slice(0,10),time=due.toISOString().slice(11,16),preview=await plans.preview(req,choice),rows=[];
  for(const kind of ['CALENDAR','ONCE'])rows.push(await plans.create(req,{...choice,name:'Owned actual '+kind,timing:{kind,timezone:'UTC',time,...(kind==='ONCE'?{date}:{weekdays:[1,2,3,4,5,6,7]})},previewHash:preview.previewHash}));
  for(const row of rows)assert.equal(row.nextRunAt?.toISOString(),due.toISOString());assert.ok(Date.now()<+due);assert.equal((await queueDueActiveScans(db)).length,0);assert.equal(await db.scanRun.count(),0);
  const stats=async()=>{const r=await fetch('http://'+process.env.SCAN_TEST_HOST+':8089/stats',{signal:AbortSignal.timeout(3000)});assert.ok(r.ok);return (await r.json() as any).requests as number},before=await stats();
  await delay(Math.max(0,+due-Date.now()+100));const queued=(await Promise.all([queueDueActiveScans(db),queueDueActiveScans(db)])).flat();assert.equal(queued.length,2);assert.equal(new Set(queued.map(row=>row.planId)).size,2);assert.equal((await queueDueActiveScans(db)).length,0);
  const calendar=await db.scanPlan.findUniqueOrThrow({where:{id:rows[0].id}}),once=await db.scanPlan.findUniqueOrThrow({where:{id:rows[1].id}});assert.equal(calendar.nextRunAt?.getTime(),+due+86400000);assert.equal(once.nextRunAt,null);
  await processActiveScans(db,new Platform(db));assert.equal((await stats())-before,2);assert.equal(await db.scanRun.count({where:{status:'SUCCEEDED'}}),2);const targets=await db.scanTarget.findMany();assert.equal(targets.length,2);assert.ok(targets.every(row=>row.httpRequests===1));
  const finding=await db.finding.findFirstOrThrow();assert.equal(await db.finding.count(),1);assert.equal(finding.occurrences,2);assert.equal((await queueDueActiveScans(db)).length,0);
  for(const run of await db.scanRun.findMany()){assert.equal((run.timing as any).policy.time,time);assert.equal((run.timing as any).policy.timezone,'UTC');assert.ok(run.trigger.startsWith('scheduled:'));assert.equal(run.planVersion,1)}
  const edited=await plans.patch(req,once.id,{name:'Owned completed once renamed',expectedVersion:once.version});assert.equal(edited.nextRunAt,null);assert.equal((await stats())-before,2,'Renaming history cannot produce another request');
 });
});
