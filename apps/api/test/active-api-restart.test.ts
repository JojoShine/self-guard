import 'reflect-metadata';
import {test} from 'node:test';
import assert from 'node:assert/strict';
import {randomBytes} from 'node:crypto';
import {spawn,spawnSync} from 'node:child_process';
import {setTimeout as delay} from 'node:timers/promises';
import {Db} from '../src/db';
import {hashPassword} from '../src/security';
import {approvedProbeFixture} from './approved-probe-fixture';

test('actual API hard restart preserves live scan lease, consumed allowance and result identity',{
 skip:!process.env.DATABASE_URL||!process.env.SCAN_TEST_HOST||process.env.SCAN_API_RESTART_ACCEPTANCE!=='true',timeout:480000,
},async()=>{
 const schema='active_api_'+randomBytes(8).toString('hex'),admin=new Db(),url=new URL(process.env.DATABASE_URL!),children=new Set<ReturnType<typeof spawn>>();url.searchParams.set('schema',schema);assert.match(schema,/^active_api_[a-f0-9]{16}$/);
 let db:Db|undefined;const base='http://127.0.0.1:4465/api',password=randomBytes(32).toString('hex');let token='';
 async function waitFor<T>(read:()=>Promise<T|false>,timeout:number){const until=Date.now()+timeout;for(;;){const value=await read();if(value)return value;assert.ok(Date.now()<until,'Owned API recovery did not complete in time');await delay(250)}}
 async function call(path:string,body?:unknown){const response=await fetch(base+path,{method:body?'POST':'GET',headers:{'content-type':'application/json',...(token?{authorization:'Bearer '+token}:{})},...(body?{body:JSON.stringify(body)}:{})});assert.ok(response.ok,'Owned API request failed: '+path+' '+response.status);return response.json() as Promise<any>}
 function server(){const child=spawn(process.execPath,['dist/main.js'],{env:{...process.env,DATABASE_URL:url.href,PORT:'4465',API_TLS_CERT:'',API_TLS_KEY:'',ENROLLMENT_TOKEN:randomBytes(32).toString('hex'),WAF_TOKEN:randomBytes(32).toString('hex')},stdio:['ignore','ignore','pipe']});children.add(child);let diagnostic='';child.stderr.on('data',bytes=>{if(diagnostic.length<4000)diagnostic+=bytes});const done=new Promise<{code:number|null;signal:NodeJS.Signals|null}>((resolve,reject)=>{child.once('error',reject);child.once('exit',(code,signal)=>{children.delete(child);resolve({code,signal})})});return {child,done,diagnostic:()=>diagnostic}}
 async function ready(process:ReturnType<typeof server>){await waitFor(async()=>{assert.equal(process.child.exitCode,null,process.diagnostic());try{return (await fetch(base+'/health')).status===401}catch{return false}},20000)}
 try{
  await admin.$executeRawUnsafe('CREATE SCHEMA "'+schema+'"');const migrated=spawnSync(process.execPath,['node_modules/prisma/build/index.js','migrate','deploy'],{env:{...process.env,DATABASE_URL:url.href},encoding:'utf8'});assert.equal(migrated.status,0,migrated.stderr);db=new Db({datasourceUrl:url.href});
  const owner=await db.user.create({data:{email:'api-restart@fixture.test',name:'Owned restart operator',role:'ADMIN',passwordHash:hashPassword(password)}}),asset=await db.asset.create({data:{hostname:'Owned API restart asset',os:'linux'}}),fixture=await approvedProbeFixture(db,owner,asset,{hostname:process.env.SCAN_TEST_HOST,port:8089,protocol:'http',allowedPaths:['/public'],excludedPaths:[]},[{method:'GET',path:'/public/delayed',rule:{description:'Owned delayed response for API interruption',operator:'ALL',conditions:[{kind:'STATUS',status:200},{kind:'BODY_CONTAINS',value:'owned-probe-fixture'}]}}]);
  const stats=async()=>{const response=await fetch('http://'+process.env.SCAN_TEST_HOST+':8089/stats');assert.ok(response.ok);return (await response.json() as any).requests as number},baseline=await stats();
  const first=server();await ready(first);token=(await call('/auth/login',{email:owner.email,password})).token;
  const selection={endpointIds:[fixture.endpoint.id],templateIds:fixture.templates.map(row=>row.id),scope:{include:[{assetIds:[asset.id]}]}},preview=await call('/active-scan-plans/preview',selection),plan=await call('/active-scan-plans',{...selection,name:'Owned real API restart',timing:{kind:'MANUAL',timezone:'UTC',windows:[]},previewHash:preview.previewHash}),run=await call('/active-scan-plans/'+plan.id+'/run',{});
  await waitFor(async()=>await stats()>baseline,75000);first.child.kill('SIGKILL');assert.equal((await first.done).signal,'SIGKILL');const crashedAt=Date.now();
  const held=await db.scanRun.findUniqueOrThrow({where:{id:run.id}}),target=await db.scanTarget.findFirstOrThrow({where:{runId:run.id}});assert.equal(held.status,'RUNNING');assert.equal(target.httpRequests,1);assert.equal(await db.finding.count(),0,'Killed API must not commit the in-flight match');
  const second=server();await ready(second);assert.equal((await call('/auth/me')).id,owner.id,'Persisted login must survive API restart');
  // Observe at least one real lifecycle tick while the old lease remains held.
  await delay(65000);assert.equal((await db.scanRun.findUniqueOrThrow({where:{id:run.id}})).status,'RUNNING');assert.equal((await db.scanTarget.findUniqueOrThrow({where:{id:target.id}})).httpRequests,1);assert.equal(await stats(),baseline+1,'Restart must not issue another request under an unexpired lease');
  await waitFor(async()=>{const[{expired}]=await db!.$queryRaw<Array<{expired:boolean}>>`SELECT "leaseUntil"<=clock_timestamp() AS expired FROM "ScanRun" WHERE id=${run.id}`;return expired},320000);assert.ok(Date.now()-crashedAt>280000,'Natural lease expiry must be observed without changing database clocks or lease timestamps');
  await waitFor(async()=>{const row=await db!.scanRun.findUniqueOrThrow({where:{id:run.id}});return row.status==='SUCCEEDED'&&row},90000);
  const recovered=await db.scanTarget.findUniqueOrThrow({where:{id:target.id}}),probe=await db.scanProbe.findFirstOrThrow({where:{targetId:target.id}}),finding=await db.finding.findFirstOrThrow();assert.equal(recovered.httpRequests,2);assert.equal(probe.attempts,2);assert.equal(probe.status,'CONFIRMED');assert.equal(probe.findingId,finding.id);assert.equal(await db.finding.count(),1);assert.equal(finding.occurrences,1);assert.equal(await stats(),baseline+2);assert.equal((await call('/active-scan-plans/checks/'+probe.id)).result.outcome,'CONFIRMED');
  console.log(JSON.stringify({actualApiRestart:true,naturalLeaseWaitMs:Date.now()-crashedAt,retainedAllowance:recovered.httpRequests,attempts:probe.attempts,actualFixtureRequests:(await stats())-baseline,findings:1,occurrences:1}));
 }finally{
  for(const child of children)child.kill('SIGTERM');await waitFor(async()=>[...children].every(child=>child.exitCode!==null||child.signalCode!==null),6000).catch(()=>{for(const child of children)child.kill('SIGKILL')});
  await db?.$disconnect();await admin.$executeRawUnsafe('DROP SCHEMA "'+schema+'" CASCADE');await admin.$disconnect();
 }
});
