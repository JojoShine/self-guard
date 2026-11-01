import {test} from 'node:test';import assert from 'node:assert/strict';
import {evidenceObject,networkEvidence} from '../src/investigation';import {redactEvidence} from '../src/scope';
test('investigation presents only reported connections and labels configuration separately',()=>{
 const signals=[{id:'finding-a',evidence:JSON.stringify({siteId:'site-a',remoteIp:'192.0.2.0/24',method:'GET',path:'/login'})},{id:'finding-b',evidence:JSON.stringify({sourceIp:'10.0.0.1',destinationIp:'10.0.0.2',destinationPort:443})}];
 const result=networkEvidence(signals,[{id:'site-a',hostname:'shop.example',upstream:'http://backend:8080'}],[]);
 assert.equal(result.relations.length,3);assert.equal(result.relations.find(r=>r.kind==='CONFIGURED_ROUTING').basis.includes('不证明'),true);assert.equal(result.relations.find(r=>r.kind==='REPORTED_CONNECTION').port,'443');assert.equal(networkEvidence([{id:'empty',evidence:'unknown'}],[],[]).relations.length,0);
 const hidden=redactEvidence({role:'VIEWER',dataScope:{canReadEvidence:false}},{evidence:result});assert.equal(hidden.evidence,'[已隐藏]');
});
test('investigation preserves real evidence and never evaluates supplied content',()=>{
 const input={actual:'0644',expected:'0600',path:'/etc/app.conf'};assert.deepEqual(evidenceObject(JSON.stringify(JSON.stringify(input))),input);assert.deepEqual(evidenceObject('<script>bad</script>'),{});assert.deepEqual(evidenceObject('x'.repeat(100001)),{});
});

test('recorded WAF host and upstream remain historical facts after live site configuration changes',()=>{
 const signals=[{id:'snapshot-finding',evidence:JSON.stringify({siteId:'site',remoteIp:'198.51.100.7',action:'BLOCK',method:'POST',inspection:{siteVersion:2,siteHostname:'original.example',configuredUpstreamOrigin:'https://original-backend.example'}})}];
 const result=networkEvidence(signals,[{id:'site',hostname:'changed.example',upstream:'https://changed-backend.example/path?private=hidden'}],[]);
 assert.equal(result.relations.find(row=>row.kind==='REPORTED_REQUEST').to,'original.example');
 const historical=result.relations.find(row=>row.kind==='CONFIGURED_ROUTING_SNAPSHOT');assert.equal(historical.to,'https://original-backend.example');assert.match(historical.basis,/未转发/);
 const current=result.relations.find(row=>row.kind==='CONFIGURED_ROUTING');assert.equal(current.to,'https://changed-backend.example');assert.ok(!JSON.stringify(result).includes('private=hidden'));
 assert.equal(networkEvidence(signals,[],[]).relations.length,2);
});

import {randomBytes} from 'node:crypto';import {spawnSync} from 'node:child_process';import {Db} from '../src/db';import {investigationContext} from '../src/investigation';
test('real investigation context pages linked findings, enforces asset scope and protects referenced events',{skip:!process.env.DATABASE_URL},async()=>{
 const admin=new Db(),schema='investigation_'+randomBytes(8).toString('hex');let db:Db|undefined;
 try{
  await admin.$executeRawUnsafe('CREATE SCHEMA "'+schema+'"');const url=new URL(process.env.DATABASE_URL!);url.searchParams.set('schema',schema);const setup=spawnSync(process.execPath,['node_modules/prisma/build/index.js','db','push','--skip-generate'],{env:{...process.env,DATABASE_URL:url.toString()},encoding:'utf8'});assert.equal(setup.status,0,setup.stderr);db=new Db({datasourceUrl:url.toString()});
  const a=await db.asset.create({data:{hostname:'visible-host',os:'linux',business:'payment'}}),b=await db.asset.create({data:{hostname:'foreign-host-secret',os:'linux',business:'other'}});
  const site=await db.site.create({data:{name:'shop',hostname:'shop.example',upstream:'http://backend:8080'}});
  const event=await db.telemetryEvent.create({data:{source:'agent',externalId:'foreign-event',sourceKey:'fixture',assetId:b.id,type:'CONNECTION',occurredAt:new Date(),expiresAt:new Date(Date.now()+3600000),data:{sourceIp:'10.0.0.1',destinationIp:'10.0.0.2'}}});
  const ids:string[]=[];for(let index=0;index<21;index++){const f=await db.finding.create({data:{dedupKey:'finding-'+index,externalId:'finding-'+index,title:'权限风险 '+index,kind:'RISK',severity:'HIGH',source:'waf',assetId:a.id,evidence:JSON.stringify({actual:'0666',expected:'0600',siteId:site.id,remoteIp:'192.0.2.0/24',eventIds:[event.id]})}});ids.push(f.id)}
  const foreign=await db.finding.create({data:{dedupKey:'foreign',externalId:'foreign',title:'foreign-finding-secret',kind:'RISK',severity:'HIGH',source:'fixture',assetId:b.id,evidence:'foreign evidence'}});
  const incident=await db.incident.create({data:{title:'Visible incident',severity:'HIGH',assetIds:[a.id],links:{create:ids.map(findingId=>({findingId}))}}}),mixed=await db.incident.create({data:{title:'Mixed incident',severity:'HIGH',links:{create:[{findingId:ids[0]},{findingId:foreign.id}]}}});
  const user={role:'ANALYST',dataScope:{restricted:true,businesses:['payment'],assetIds:[],canReadEvidence:true}};
  const first=await investigationContext(db,user,'incidents',incident.id);assert.equal(first.total,21);assert.equal(first.evidence.findings.length,15);assert.equal(first.evidence.events.length,0);assert.equal(first.evidence.network.relations.length,0);assert.ok(!JSON.stringify(first).includes('foreign-host-secret'));
  const second=await investigationContext(db,user,'incidents',incident.id,2,15);assert.equal(second.evidence.findings.length,6);assert.equal(new Set([...first.evidence.findings,...second.evidence.findings].map(f=>f.id)).size,21);
  await assert.rejects(()=>investigationContext(db!,user,'incidents',mixed.id));await assert.rejects(()=>investigationContext(db!,user,'findings',foreign.id));
  const full=await investigationContext(db,{role:'ADMIN'},'findings',ids[0]);assert.equal(full.evidence.events.length,1);assert.ok(full.evidence.network.relations.some(r=>r.kind==='CONFIGURED_ROUTING'));assert.equal(redactEvidence({...user,dataScope:{...user.dataScope,canReadEvidence:false}},first).evidence,'[已隐藏]');
 }finally{await db?.$disconnect();await admin.$executeRawUnsafe('DROP SCHEMA "'+schema+'" CASCADE');await admin.$disconnect()}
});
