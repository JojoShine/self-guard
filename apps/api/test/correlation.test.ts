import {test} from 'node:test';
import assert from 'node:assert/strict';
import {correlationInput, matchesConditions, redactTelemetry} from '../src/correlation';

test('correlation ALL/ANY condition thresholds operate across events, not within one event',()=>{
 const rows=[{source:'agent',type:'LOGIN_FAILED',data:{status:401}},{source:'agent',type:'LOGIN_FAILED',data:{status:401}},{source:'waf',type:'ACCESS',data:{status:403}}];
 const conditions=[{field:'type',operator:'eq',value:'LOGIN_FAILED',threshold:2},{field:'data.status',operator:'eq',value:403,threshold:1}];
 assert.equal(matchesConditions(rows,{mode:'ALL',conditions}),true);
 assert.equal(matchesConditions(rows.slice(0,2),{mode:'ALL',conditions}),false);
 assert.equal(matchesConditions(rows.slice(0,2),{mode:'ANY',conditions}),true);
 assert.equal(correlationInput.safeParse({name:'bad',severity:'HIGH',config:{windowSeconds:0}}).success,false);
});
test('telemetry drops request secrets, headers, bodies and unknown fields before persistence',()=>{
 const clean=redactTelemetry({status:403,method:'GET',ruleId:'SQLI',message:'token=secret password=hidden',path:'/secret?token=hidden',headers:{authorization:'secret'},body:'secret',secret:'hidden'});
 assert.deepEqual(clean,{status:403,method:'GET',ruleId:'SQLI'});
});

import {Db} from '../src/db';
import {Platform} from '../src/platform';
import {CorrelationService,TelemetryController,WafPolicyTestController} from '../src/correlation';
test('persisted time-window correlation deduplicates source retries and isolates assets', {skip:!process.env.CORRELATION_TEST_ISOLATED},async()=>{
 assert.match(process.env.DATABASE_URL||'',/[?&]schema=correlation_test_[a-z0-9_]+(?:&|$)/);
 const db=new Db();const service=new CorrelationService(db,new Platform(db));const oldWafToken=process.env.WAF_TOKEN;
 try{
  const a=await db.asset.create({data:{hostname:'a',os:'Linux'}});const b=await db.asset.create({data:{hostname:'b',os:'Linux'}});
  const now=Date.now();const stamp=(n:number)=>new Date(now+n).toISOString();
  const rule=await db.correlationRule.create({data:{name:'Two signals',severity:'HIGH',config:{mode:'ALL',groupBy:'asset',windowSeconds:60,createIncident:true,conditions:[{field:'type',operator:'eq',value:'LOGIN_FAILED',threshold:2},{field:'data.status',operator:'eq',value:403,threshold:1}]}}});
  const row=(id:string,type:string,status:number,n=0)=>({id,type,timestamp:stamp(n),data:{status,body:'secret',headers:{Authorization:'secret'},message:'password=secret'}});
  await service.ingest('agent','agent:a',[row('old','LOGIN_FAILED',401,-120000)],{assetId:a.id});
  await service.ingest('agent','agent:b',[row('one','LOGIN_FAILED',401)],{assetId:b.id});
  await service.ingest('agent','agent:a',[row('one','LOGIN_FAILED',401)],{assetId:a.id});
  await service.ingest('agent','agent:a',[row('denied','ACCESS',403)],{assetId:a.id});
  assert.equal(await db.finding.count(),0,'old or different-asset signal incorrectly counted');
  const batch=[row('two','LOGIN_FAILED',401,-1)];
  await Promise.all([service.ingest('agent','agent:a',batch,{assetId:a.id}),service.ingest('agent','agent:a',batch,{assetId:a.id})]);
  assert.equal(await db.finding.count(),1);assert.equal(await db.incident.count(),1);assert.equal(await db.correlationMatch.count(),1);
  assert.equal((await db.finding.findFirstOrThrow()).occurrences,1);
  assert.doesNotMatch(JSON.stringify(await db.telemetryEvent.findMany()),/secret|password|Authorization/);
  const controller=new TelemetryController(db,service);
  await assert.rejects(()=>controller.access({headers:{authorization:'Bearer invalid'}},{events:[]}));
  const rows=await controller.list({user:{role:'ANALYST',dataScope:{restricted:true,assetIds:[b.id],businesses:[]}}},{});
  assert.equal(rows.total,1);assert.ok(rows.items.every(r=>r.assetId===b.id));
  await assert.rejects(()=>controller.list({user:{role:'ANALYST',dataScope:{canReadEvidence:false}}},{}));
  const site=await db.site.create({data:{name:'Web',hostname:'web.test',upstream:'http://127.0.0.1:1'}});
  await db.correlationRule.create({data:{name:'Site denied',severity:'MEDIUM',config:{mode:'ANY',groupBy:'site',windowSeconds:60,createIncident:false,conditions:[{field:'data.status',operator:'eq',value:403,threshold:1}]}}});
  process.env.WAF_TOKEN='waf-test-only';
  const access={nodeId:'node',events:[{id:'request-one',siteId:site.id,method:'GET',path:'/secret?token=hidden',status:403,timestamp:stamp(0),durationMicros:10}]};
  assert.equal((await controller.access({headers:{authorization:'Bearer waf-test-only'}},access)).accepted,1);
  assert.equal((await controller.access({headers:{authorization:'Bearer waf-test-only'}},access)).duplicates,1);
  assert.equal(await db.finding.count(),2);assert.equal(await db.incident.count(),1);
  assert.doesNotMatch(JSON.stringify(await db.telemetryEvent.findMany()),/secret|hidden|token/);

  const admin={user:{role:'ADMIN',email:'admin@test.local'}};
  const previousTestUrl=process.env.WAF_TEST_URL;try{process.env.WAF_TEST_URL='http://127.0.0.1:1';await assert.rejects(()=>new WafPolicyTestController(db,new Platform(db)).test(admin,{siteId:site.id,method:'GET',path:'/'}),(e:any)=>e.getStatus?.()===503);}finally{if(previousTestUrl===undefined)delete process.env.WAF_TEST_URL;else process.env.WAF_TEST_URL=previousTestUrl;}

  assert.deepEqual(await controller.policy(admin),{allowMessages:false});
  await assert.rejects(()=>controller.setPolicy({user:{role:'ANALYST'}},{allowMessages:true}));
  await controller.setPolicy(admin,{allowMessages:true});
  const rawRule=await db.correlationRule.create({data:{name:'Raw context',severity:'LOW',config:{mode:'ALL',groupBy:'asset',windowSeconds:30,createIncident:false,conditions:[{field:'data.message',operator:'contains',value:'failed',threshold:1}]}}});
  await service.ingest('agent','raw:asset-a',[{id:'raw-a',type:'LOG_LINE',timestamp:stamp(10),data:{message:'login failed token=raw-secret <img src=x onerror=window.rawLogExecuted=true>',body:'never'}}],{assetId:a.id});
  await service.ingest('agent','raw:asset-b',[{id:'raw-b',type:'LOG_LINE',timestamp:stamp(10),data:{message:'allowed context password=another-secret'}}],{assetId:b.id});
  const visible=await controller.list({user:{role:'ANALYST',dataScope:{restricted:true,assetIds:[b.id],businesses:[]}}},{});
  assert.equal(visible.total,2);assert.ok(visible.items.every(r=>r.assetId===b.id));assert.doesNotMatch(JSON.stringify(visible),/another-secret|raw-secret|login failed/);
  const raw=await db.telemetryEvent.findFirstOrThrow({where:{sourceKey:'raw:asset-a'}});assert.match((raw.data as any).message,/<img/);assert.doesNotMatch(JSON.stringify(raw.data),/raw-secret|never/);
  assert.equal(await db.finding.count({where:{externalId:{startsWith:rawRule.id}}}),1);
  await controller.setPolicy(admin,{allowMessages:false});
  const stored=await db.telemetryEvent.findFirstOrThrow();await db.telemetryEvent.update({where:{id:stored.id},data:{expiresAt:new Date(now-1)}});
  await controller.purge({user:{role:'ADMIN'}});assert.equal(await db.telemetryEvent.findUnique({where:{id:stored.id}}),null);
 }finally{if(oldWafToken===undefined)delete process.env.WAF_TOKEN;else process.env.WAF_TOKEN=oldWafToken;await db.$disconnect()}
});

test('explicit message opt-in redacts credentials while preserving ordinary log context',()=>{
 const data=redactTelemetry({message:'login failed user=alice db_password="prefixed-secret" client_secret=other-prefixed-secret password="two word secret" token=abc Authorization: Bearer TOPSECRET\n<img src=x onerror=window.rawLogExecuted=true>'},true);
 assert.match(data.message as string,/login failed user=alice/);assert.doesNotMatch(data.message as string,/two word secret|prefixed-secret|abc|TOPSECRET/);assert.match(data.message as string,/<img/);
});
