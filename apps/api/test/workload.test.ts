import 'reflect-metadata';
import {test} from 'node:test';
import assert from 'node:assert/strict';
import {randomBytes} from 'node:crypto';
import {spawnSync} from 'node:child_process';
import {Db} from '../src/db';
import {WorkloadController} from '../src/workload';

test('isolated workload scopes freshness, ownership, overdue work, approval policy and repair outcomes',{skip:!process.env.DATABASE_URL},async()=>{
 const admin=new Db(),schema='workload_test_'+randomBytes(8).toString('hex');const url=new URL(process.env.DATABASE_URL!);url.searchParams.set('schema',schema);let db:Db|undefined;
 try{
  await admin.$executeRawUnsafe('CREATE SCHEMA "'+schema+'"');
  const setup=spawnSync(process.execPath,['node_modules/prisma/build/index.js','db','push','--skip-generate'],{env:{...process.env,DATABASE_URL:url.toString()},encoding:'utf8'});assert.equal(setup.status,0,setup.stderr);
  db=new Db({datasourceUrl:url.toString()});const controller=new WorkloadController(db);
  const user=await db.user.create({data:{email:'mine@test.local',name:'My Name',role:'ANALYST',passwordHash:'unused',dataScope:{restricted:true,businesses:['A'],canReadEvidence:false}}});
  const now=Date.now();const assets=[];
  for(const [hostname,business,lastSeen,archivedAt] of [['online','A',new Date(now),null],['stale','A',new Date(now-120000),null],['never','A',null,null],['archived','A',new Date(now),new Date(now)],['hidden','B',new Date(now),null]] as const)assets.push(await db.asset.create({data:{hostname,business,os:'Linux',lastSeen,archivedAt}}));
  const finding=async(name:string,assetId:string,owner:string,status='OPEN',dueAt:Date|null=null)=>db!.finding.create({data:{dedupKey:name,externalId:name,title:name,assetId,owner,kind:'RISK',severity:'HIGH',source:'test',evidence:'PRIVATE-EVIDENCE',status,dueAt}});
  await finding('owned-overdue',assets[0].id,user.email,'OPEN',new Date(now-60000));
  await finding('owned-by-name',assets[1].id,user.name,'IN_PROGRESS',new Date(now+60000));
  await finding('closed',assets[0].id,user.email,'CLOSED',new Date(now-60000));
  await finding('other-owner',assets[0].id,'other@test.local');
  await finding('hidden-owner',assets[4].id,user.email,'OPEN',new Date(now-60000));
  await finding('verification',assets[0].id,'other@test.local','VERIFYING');
  await finding('archived-risk',assets[3].id,'other@test.local');
  const task=async(title:string,assetId:string,status:string,requestedBy:string,template='FILE_PERMISSION',expiresAt=new Date(now+3600000))=>db!.task.create({data:{title,assetId,status,requestedBy,template,parameters:{secret:'PRIVATE-PARAMETER'},expiresAt}});
  await task('my-pending',assets[0].id,'PENDING',user.email);
  await task('other-pending',assets[0].id,'PENDING','other@test.local');
  await task('hidden-pending',assets[4].id,'PENDING',user.email);
  await task('expired-pending',assets[0].id,'PENDING','other@test.local','FILE_PERMISSION',new Date(now-60000));
  await task('my-verifying',assets[1].id,'VERIFYING',user.email);
  await task('hidden-verifying',assets[4].id,'VERIFYING',user.email);
  await task('my-unknown',assets[0].id,'UNKNOWN',user.email);
  await task('success',assets[0].id,'SUCCEEDED',user.email);
  await task('failure',assets[0].id,'FAILED',user.email);
  await task('rollback',assets[0].id,'ROLLED_BACK',user.email);
  await task('verification-child',assets[0].id,'SUCCEEDED',user.email,'VERIFY_READ');
  await task('rollback-child',assets[0].id,'SUCCEEDED',user.email,'ROLLBACK');
  await task('hidden-success',assets[4].id,'SUCCEEDED',user.email);
  await db.setting.create({data:{key:'approval-policy',value:{approverRoles:['ANALYST'],allowSelfApproval:false}}});
  let response=await controller.workload({user});
  assert.equal(response.freshnessSeconds,90);assert.equal(response.timezone,'UTC');assert.ok(Number.isFinite(Date.parse(response.generatedAt)));
  assert.deepEqual(response.assets,{online:1,stale:1,neverSeen:1,archived:1});
  assert.equal(response.personal.assignedFindings.count,2);assert.equal(response.personal.overdueFindings.count,1);
  assert.equal(response.personal.myTasks.count,3);assert.equal(response.personal.approvals.count,1);assert.equal(response.personal.approvals.eligible,true);
  assert.deepEqual(response.pendingVerification,{findings:1,tasks:1});
  assert.deepEqual(response.repairOutcomes,{succeeded:1,failed:1,rolledBack:1});
  assert.deepEqual(response.businesses,[{business:'A',assets:3,openRisks:4}]);
  const serialized=JSON.stringify(response);assert.ok(!serialized.includes('PRIVATE-'));assert.ok(!serialized.includes('hidden-'));assert.ok(!serialized.includes(assets[4].id));
  await db.setting.update({where:{key:'approval-policy'},data:{value:{approverRoles:['ANALYST'],allowSelfApproval:true}}});
  response=await controller.workload({user});assert.equal(response.personal.approvals.count,2);
  for(let i=0;i<6;i++)await finding('extra-assigned-'+i,assets[0].id,user.email);
  response=await controller.workload({user});assert.equal(response.personal.assignedFindings.count,8);assert.equal(response.personal.assignedFindings.items.length,5);
  await db.setting.update({where:{key:'approval-policy'},data:{value:{approverRoles:['VIEWER'],allowSelfApproval:true}}});
  response=await controller.workload({user});assert.equal(response.personal.approvals.count,0);assert.equal(response.personal.approvals.eligible,false);
  const denied={...user,dataScope:{restricted:true,businesses:[],assetIds:[]}};
  const empty=await controller.workload({user:denied});assert.deepEqual(empty.assets,{online:0,stale:0,neverSeen:0,archived:0});assert.equal(empty.personal.assignedFindings.count,0);assert.equal(empty.personal.myTasks.count,0);assert.deepEqual(empty.repairOutcomes,{succeeded:0,failed:0,rolledBack:0});assert.deepEqual(empty.businesses,[]);
 }finally{await db?.$disconnect();await admin.$executeRawUnsafe('DROP SCHEMA "'+schema+'" CASCADE');await admin.$disconnect();}
});

test('isolated workload drilldowns match every metric with fewer than ten fixtures',{skip:!process.env.DATABASE_URL},async()=>{
 const admin=new Db(),schema='workload_details_test_'+randomBytes(8).toString('hex'),url=new URL(process.env.DATABASE_URL!);url.searchParams.set('schema',schema);let db:Db|undefined;
 try{
  await admin.$executeRawUnsafe('CREATE SCHEMA "'+schema+'"');const setup=spawnSync(process.execPath,['node_modules/prisma/build/index.js','db','push','--skip-generate'],{env:{...process.env,DATABASE_URL:url.toString()},encoding:'utf8'});assert.equal(setup.status,0,setup.stderr);db=new Db({datasourceUrl:url.toString()});const c=new WorkloadController(db),now=Date.now();
  const user={email:'mine@test.local',name:'Mine',role:'ANALYST',dataScope:{restricted:true,businesses:['A'],canReadEvidence:false}};
  const visible=await db.asset.create({data:{hostname:'Visible',os:'Linux',business:'A',lastSeen:new Date(now),inventory:{private:'NO-LEAK'}}});
  const hidden=await db.asset.create({data:{hostname:'Hidden',os:'Linux',business:'B',lastSeen:new Date(now)}});
  await db.asset.create({data:{hostname:'Archived',os:'Linux',business:'A',archivedAt:new Date(now)}});
  for(const [title,assetId]of [['Visible',visible.id],['Hidden',hidden.id]])await db.finding.create({data:{title,assetId,owner:user.email,dedupKey:title,externalId:title,kind:'RISK',status:'VERIFYING',severity:'LOW',source:'test',evidence:'NO-LEAK',dueAt:new Date(now-60000)}});
  for(const [title,assetId,status,requestedBy]of [['Pending',visible.id,'PENDING','other@test.local'],['Success',visible.id,'SUCCEEDED',user.email],['Hidden',hidden.id,'SUCCEEDED',user.email]])await db.task.create({data:{title,assetId,status,requestedBy,template:'FILE_PERMISSION',parameters:{private:'NO-LEAK'},expiresAt:new Date(now+3600000)}});
  await db.setting.create({data:{key:'approval-policy',value:{approverRoles:['ANALYST'],allowSelfApproval:false}}});
  const summary=await c.workload({user});
  const expected:Record<string,number>={online:summary.assets.online,stale:summary.assets.stale,neverSeen:summary.assets.neverSeen,archived:summary.assets.archived,assigned:summary.personal.assignedFindings.count,overdue:summary.personal.overdueFindings.count,myTasks:summary.personal.myTasks.count,approvals:summary.personal.approvals.count,verifyFindings:summary.pendingVerification.findings,verifyTasks:summary.pendingVerification.tasks,...summary.repairOutcomes,businessAssets:summary.businesses[0].assets,businessRisks:summary.businesses[0].openRisks};
  for(const [group,total]of Object.entries(expected)){
    const detail=await c.details({user},{group,...(group.startsWith('business')?{business:'A'}:{}),page:1,pageSize:1});
    assert.equal(detail.total,total,group+' count mismatch');assert.equal(detail.items.length,Math.min(total,1),group+' list mismatch');assert.equal(detail.timezone,'UTC');
    assert.ok(!JSON.stringify(detail).includes('NO-LEAK'));assert.ok(!JSON.stringify(detail).includes(hidden.id));
  }
  const second=await c.details({user},{group:'assigned',page:2,pageSize:1});assert.equal(second.total,1);assert.deepEqual(second.items,[]);
  const denied=await c.details({user},{group:'businessAssets',business:'B'});assert.equal(denied.total,0);
  const viewer={...user,role:'VIEWER'};assert.equal((await c.details({user:viewer},{group:'approvals'})).total,0);
  await db.asset.update({where:{id:visible.id},data:{lastSeen:new Date(now-120000)}});assert.equal((await c.details({user},{group:'stale'})).total,(await c.workload({user})).assets.stale);
  await db.asset.update({where:{id:visible.id},data:{lastSeen:null}});assert.equal((await c.details({user},{group:'neverSeen'})).total,(await c.workload({user})).assets.neverSeen);
  await assert.rejects(()=>c.details({user},{group:'businessRisks'}));await assert.rejects(()=>c.details({user},{group:'unknown'}));
 }finally{await db?.$disconnect();await admin.$executeRawUnsafe('DROP SCHEMA "'+schema+'" CASCADE');await admin.$disconnect();}
});

test('isolated overview drilldowns match Platform overview including accepted risks and WAF scope',{skip:!process.env.DATABASE_URL},async()=>{
 const {Platform}=await import('../src/platform');const admin=new Db(),schema='overview_details_test_'+randomBytes(8).toString('hex'),url=new URL(process.env.DATABASE_URL!);url.searchParams.set('schema',schema);let db:Db|undefined;
 try{
  await admin.$executeRawUnsafe('CREATE SCHEMA "'+schema+'"');const setup=spawnSync(process.execPath,['node_modules/prisma/build/index.js','db','push','--skip-generate'],{env:{...process.env,DATABASE_URL:url.toString()},encoding:'utf8'});assert.equal(setup.status,0,setup.stderr);db=new Db({datasourceUrl:url.toString()});const c=new WorkloadController(db),p=new Platform(db),now=Date.now();
  const user={email:'viewer@test.local',name:'Viewer',role:'VIEWER',dataScope:{restricted:true,businesses:['A'],canReadEvidence:false}};
  const a=await db.asset.create({data:{hostname:'Archived A',business:'A',os:'Linux',archivedAt:new Date()}}),b=await db.asset.create({data:{hostname:'Hidden B',business:'B',os:'Linux'}});
  let acceptedId='';for(const [title,assetId,kind,status,severity]of [['accepted',a.id,'RISK','ACCEPTED','CRITICAL'],['closed',a.id,'RISK','CLOSED','HIGH'],['alert',a.id,'ALERT','OPEN','HIGH'],['resolved',a.id,'ALERT','RESOLVED','HIGH'],['hidden',b.id,'RISK','OPEN','CRITICAL']]){const row=await db.finding.create({data:{title,assetId,kind,status,severity,dedupKey:title,externalId:title,source:'test',evidence:'PRIVATE-FINDING'}});if(title==='accepted')acceptedId=row.id;}
  for(const status of ['OPEN','CLOSED'])await db.incident.create({data:{title:status,severity:'HIGH',status,description:'PRIVATE-INCIDENT',links:{create:{findingId:acceptedId}}}});
  for(const status of ['PENDING','SUCCEEDED'])await db.task.create({data:{title:status,assetId:a.id,template:'FILE_PERMISSION',parameters:{private:'PRIVATE-PARAMETER'},requestedBy:user.email,status,expiresAt:new Date(now+3600000)}});
  for(const action of ['BLOCK','OBSERVE'])await db.wafEvent.create({data:{id:action,siteId:'fixture-site',ruleId:'fixture-rule',path:'/PRIVATE-PATH',remoteIp:'PRIVATE-IP',method:'GET',action,timestamp:new Date(now)}});
  await db.wafNode.create({data:{id:'fresh',version:'1',sites:[],startedAt:new Date(now-60000),lastSeen:new Date(now),stats:{totalRequests:12,blockedRequests:2,observedRequests:3,upstreamErrors:1,password:'PRIVATE-NODE'}}});
  await db.wafNode.create({data:{id:'stale',version:'1',sites:[],startedAt:new Date(now-600000),lastSeen:new Date(now-120000),stats:{totalRequests:99}}});
  for(const actor of [user,{...user,role:'ADMIN'}]){
    const overview=await p.overview(actor);const metrics:Record<string,number>={overviewAssets:overview.assets,overviewRisks:overview.risks,overviewAlerts:overview.alerts,overviewIncidents:overview.incidents,overviewTasks:overview.pendingTasks,overviewCritical:overview.criticalRisks,wafEvents:overview.wafEvents,wafBlocked:overview.wafBlocked};
    for(const [group,count]of Object.entries(metrics)){const detail=await c.details({user:actor},{group,pageSize:100});assert.equal(detail.total,count,group);assert.equal(detail.items.length,count,group);assert.ok(!JSON.stringify(detail).includes('PRIVATE-'));}
    const nodes=await c.details({user:actor},{group:'wafNodes'});assert.equal(nodes.total,actor.role==='ADMIN'?1:0);assert.ok(!JSON.stringify(nodes).includes('PRIVATE-'));if(actor.role==='ADMIN'){assert.equal(nodes.items[0].stats.totalRequests,12);assert.equal(nodes.items[0].id,'fresh');}
  }
  assert.equal((await c.details({user},{group:'overviewRisks'})).items[0].status,'ACCEPTED');
 }finally{await db?.$disconnect();await admin.$executeRawUnsafe('DROP SCHEMA "'+schema+'" CASCADE');await admin.$disconnect();}
});
