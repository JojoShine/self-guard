import 'reflect-metadata';
import {test} from 'node:test';
import assert from 'node:assert/strict';
import {randomBytes,createHash} from 'node:crypto';
import {spawnSync} from 'node:child_process';
import {Db} from '../src/db';
import {Platform} from '../src/platform';
import {VulnerabilityFeedsController,syncVulnerabilityFeed} from '../src/intelligence';
import {ScansController,processInventoryScans} from '../src/scans';
import {investigationContext} from '../src/investigation';

// Controlled publisher changes exercise the real transaction/matching pipeline;
// these are not claimed as newly published vendor advisories or actual exploits.
test('Alpine and KEV full refreshes preserve history, reject wrong scope and never auto-close a prior risk',{skip:!process.env.DATABASE_URL},async()=>{
 const admin=new Db(),schema='vendor_refresh_'+randomBytes(8).toString('hex');let db:Db|undefined,created=false;
 try{
  await admin.$executeRawUnsafe('CREATE SCHEMA "'+schema+'"');created=true;const url=new URL(process.env.DATABASE_URL!);url.searchParams.set('schema',schema);
  const migrated=spawnSync(process.execPath,['node_modules/prisma/build/index.js','migrate','deploy'],{env:{...process.env,DATABASE_URL:url.href},encoding:'utf8'});assert.equal(migrated.status,0,migrated.stderr);db=new Db({datasourceUrl:url.href});
  const user=await db.user.create({data:{email:'vendor-refresh@fixture.test',name:'Owned source refresh administrator',role:'ADMIN',passwordHash:'fixture'}}),req={user},feeds=new VulnerabilityFeedsController(db),scans=new ScansController(db),platform=new Platform(db),cve='CVE-2026-12345';
  const alpine=await feeds.create(req,{name:'Owned Alpine full refresh',provider:'ALPINE',config:{branch:'v3.23',repository:'main'}}),kev=await feeds.create(req,{name:'Owned KEV full refresh',provider:'CISA_KEV',config:{}});
  const alpineDocument=(fixed:string,branch='v3.23')=>({distroversion:branch,reponame:'main',packages:[{pkg:{name:'owned-source',secfixes:{[fixed]:[cve]}}}]}),kevDocument=(action:string)=>({catalogVersion:'owned-'+action,dateReleased:'2026-11-01T00:00:00Z',count:1,vulnerabilities:[{cveID:cve,vendorProject:'Owned fixture',product:'Owned package',vulnerabilityName:'Controlled source context',dateAdded:'2026-10-31',shortDescription:'Controlled source refresh fixture, not a real vendor disclosure.',requiredAction:action,dueDate:'2026-12-01'}]});
  const publish=(id:string,document:unknown)=>syncVulnerabilityFeed(db!,id,user.email,async()=>({document,sourceSha256:createHash('sha256').update(JSON.stringify(document)).digest('hex')}));
  const first=await publish(alpine.id,alpineDocument('1.1-r0')),priority=await publish(kev.id,kevDocument('Review owned fixture'));
  assert.equal(first.snapshot.status,'COMPLETE');assert.equal(priority.snapshot.status,'COMPLETE');const unchanged=await publish(alpine.id,alpineDocument('1.1-r0'));assert.equal(unchanged.snapshot.status,'UNCHANGED');assert.equal(unchanged.feed.currentSnapshotId,first.snapshot.id);
  const inventory={distribution:{id:'alpine',versionId:'3.23.4'},distributionCollection:{complete:true},packageCollection:{complete:true},packages:[{name:'owned-binary',origin:'owned-source',version:'1.0-r0',manager:'apk',architecture:'aarch64'}],ports:[{protocol:'tcp',address:'127.0.0.1',port:8080,state:'LISTEN'}],portCollection:{complete:true}},asset=await db.asset.create({data:{hostname:'Owned vendor refresh host',os:'linux',lastSeen:new Date(),inventory}}),plan=await scans.create(req,{name:'Owned two-source inventory check',feedIds:[alpine.id,kev.id],scope:{include:[{assetIds:[asset.id]}]},timing:{kind:'MANUAL',timezone:'UTC'}});
  const run=await scans.run(req,plan.id);await processInventoryScans(db,platform);assert.equal((await db.scanRun.findUniqueOrThrow({where:{id:run.id}})).status,'SUCCEEDED');assert.equal(await db.finding.count(),1);const finding=await db.finding.findFirstOrThrow();const context=await investigationContext(db,user,'findings',finding.id),proof=(context.evidence as any).findings[0].evidence;assert.equal(proof.component.version,'1.0-r0');assert.equal(proof.knownExploited,true);assert.deepEqual(new Set(proof.sources.map((row:any)=>row.provider)),new Set(['ALPINE','CISA_KEV']));assert.equal(proof.hostNetworkSnapshot.ports[0].address,'127.0.0.1');
  const wrongBranch=await publish(alpine.id,alpineDocument('1.0-r0','v3.22'));assert.equal(wrongBranch.snapshot.status,'FAILED');assert.equal(wrongBranch.feed.currentSnapshotId,first.snapshot.id);assert.equal((await feeds.records(req,alpine.id,{})).total,1);
  const brokenKev=await publish(kev.id,{...kevDocument('Incomplete controlled catalog'),count:2});assert.equal(brokenKev.snapshot.status,'FAILED');assert.equal(brokenKev.feed.currentSnapshotId,priority.snapshot.id);
  const corrected=await publish(alpine.id,alpineDocument('1.0-r0')),changedPriority=await publish(kev.id,kevDocument('Changed owned fixture action'));assert.equal(corrected.snapshot.status,'COMPLETE');assert.notEqual(corrected.snapshot.contentSha256,first.snapshot.contentSha256);assert.equal(changedPriority.snapshot.status,'COMPLETE');assert.notEqual(changedPriority.snapshot.id,priority.snapshot.id);
  assert.equal(await db.vulnerabilityRecord.count({where:{snapshotId:first.snapshot.id}}),1,'Old vendor source records must remain available for earlier run evidence');assert.equal(await db.vulnerabilityRecord.count({where:{snapshotId:priority.snapshot.id}}),1);
  const repeat=await scans.run(req,plan.id);await processInventoryScans(db,platform);assert.equal((await db.scanRun.findUniqueOrThrow({where:{id:repeat.id}})).status,'SUCCEEDED');assert.equal(await db.finding.count(),1);const preserved=await db.finding.findUniqueOrThrow({where:{id:finding.id}});assert.equal(preserved.status,finding.status);assert.equal(preserved.occurrences,finding.occurrences);assert.equal(preserved.evidence,finding.evidence,'A source correction is not independent proof that the host was repaired');
  assert.equal((await publish(alpine.id,alpineDocument('1.0-r0'))).snapshot.status,'UNCHANGED');assert.equal((await publish(kev.id,kevDocument('Changed owned fixture action'))).snapshot.status,'UNCHANGED');
 }finally{await db?.$disconnect();if(created)await admin.$executeRawUnsafe('DROP SCHEMA "'+schema+'" CASCADE');await admin.$disconnect()}
});
