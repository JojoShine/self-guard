import 'reflect-metadata';
import {test} from 'node:test';
import assert from 'node:assert/strict';
import {randomBytes} from 'node:crypto';
import {spawnSync} from 'node:child_process';
import {mkdtemp,rm,writeFile,mkdir} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join,resolve} from 'node:path';
import {Db} from '../src/db';
import {ProbeRuleLibraryController,runProbeRuleLibrarySync} from '../src/probe-rule-library';
import {ScanEndpointsController} from '../src/scan-endpoints';
import {ActiveScansController,processActiveScans} from '../src/active-scans';
import {Platform} from '../src/platform';

const cases=[
 {id:'http/cves/2000/CVE-2000-0760.yaml',path:'/examples/jsp/snp/anything.snp'},
 {id:'http/cves/2017/CVE-2017-16894.yaml',path:'/.env'},
 {id:'http/cves/2018/CVE-2018-12634.yaml',path:'/html/log'},
 {id:'http/misconfiguration/ace-admin-dashboard.yaml',path:'/'},
 {id:'http/exposed-panels/3cx-phone-management-panel.yaml',path:'/'}
];
test('full official library → native compile approval → controlled HTTP → real Nuclei proofs → risks, observations and distinct rescans',{
 skip:!process.env.DATABASE_URL||!process.env.GENERIC_NETWORK_CONTAINER||!process.env.GENERIC_NETWORK_WORKER||!process.env.SCAN_TEST_HOST,
 timeout:600000
},async()=>{
 const administrator=new Db(),schema='generic_http_'+randomBytes(8).toString('hex'),directory=await mkdtemp(join(tmpdir(),'generic-http-'));
 const original={worker:process.env.SCAN_WORKER_BINARY,directory:process.env.PROBE_RULE_LIBRARY_DIR,archive:process.env.PROBE_RULE_LIBRARY_ARCHIVE};let db:Db|undefined;
 process.env.PROBE_RULE_LIBRARY_DIR=join(directory,'library');process.env.PROBE_RULE_LIBRARY_ARCHIVE=resolve(__dirname,'../../../.artifacts/downloads/nuclei/nuclei-templates-10.5.1.zip');
 const rounds:Array<{mode:string;runId:string;confirmed:number;observed:number;notFound:number;outOfScope:number;requests:number}>=[];
 try{
  await administrator.$executeRawUnsafe('CREATE SCHEMA "'+schema+'"');const url=new URL(process.env.DATABASE_URL!);url.searchParams.set('schema',schema);
  const migration=spawnSync(process.execPath,['node_modules/prisma/build/index.js','migrate','deploy'],{cwd:resolve(__dirname,'..'),env:{...process.env,DATABASE_URL:url.href},encoding:'utf8',timeout:60000});assert.equal(migration.status,0,migration.stderr);
  db=new Db({datasourceUrl:url.href});const user=await db.user.create({data:{email:'generic-http@fixture.invalid',name:'Owned generic HTTP acceptance',role:'ADMIN',passwordHash:'owned-fixture'}}),req={user},library=new ProbeRuleLibraryController(db),endpoints=new ScanEndpointsController(db),plans=new ActiveScansController(db),platform=new Platform(db);
  await library.sync(req,{});const snapshot=await runProbeRuleLibrarySync(db);assert.ok(snapshot);assert.ok(snapshot.counts.total>=14000);assert.ok(snapshot.counts.compatible>=1000);assert.ok(snapshot.counts.unsupported>0);assert.equal(await db.probeTemplate.count(),0,'full catalog synchronization cannot activate checks');
  const activated=await library.activate(req,{snapshotSha256:snapshot.sha256,ids:cases.map(c=>c.id)});assert.equal(activated.created,5);assert.equal(activated.templateIds.length,5);
  const templates=await db.probeTemplate.findMany({where:{id:{in:activated.templateIds}}});for(const row of templates){assert.equal(row.status,'APPROVED');assert.equal(row.sourceKind,'NUCLEI_LIBRARY');assert.equal((row.validationReport as {validationKind:string}).validationKind,'NATIVE_TEMPLATE_COMPILE');assert.deepEqual(row.samples,[])}
  assert.equal(templates.filter(row=>row.purpose==='OBSERVATION'&&row.severity==='INFO').length,1);assert.equal(await db.scanEndpoint.count(),0);assert.equal(await db.scanPlan.count(),0);
  process.env.SCAN_WORKER_BINARY=process.env.GENERIC_NETWORK_WORKER;
  const asset=await db.asset.create({data:{hostname:'Owned generic rule HTTP fixture',os:'linux'}}),endpointIds:string[]=[];
  for(const [index,entry] of cases.entries()){
   const draft=await endpoints.create(req,{assetId:asset.id,name:'Owned response '+(index+1),hostname:process.env.SCAN_TEST_HOST,port:8101+index,protocol:'http',allowedPaths:[entry.path],excludedPaths:[]}),preview=await endpoints.preview(req,draft.id,{expectedVersion:draft.version});
   endpointIds.push((await endpoints.approve(req,draft.id,{expectedVersion:draft.version,previewHash:preview.previewHash})).id);
  }
  const choice={endpointIds,templateIds:activated.templateIds,scope:{include:[{assetIds:[asset.id]}]}},preview=await plans.preview(req,choice),plan=await plans.create(req,{...choice,name:'Owned generic native HTTP acceptance',timing:{kind:'MANUAL',timezone:'UTC',windows:[]},previewHash:preview.previewHash});
  for(const mode of ['positive','normal','auth','similar','positive']){
   const control=spawnSync(process.env.GENERIC_NETWORK_DOCKER||'/usr/local/bin/docker',['exec',process.env.GENERIC_NETWORK_CONTAINER!,'node','-e',`require('node:http').get('http://127.0.0.1:8101/__fixture/${mode}',r=>process.exit(r.statusCode===200?0:1)).on('error',()=>process.exit(1))`],{encoding:'utf8',timeout:20000});assert.equal(control.status,0,control.stderr);
   const run=await plans.run(req,plan.id);let status='QUEUED';for(let attempt=0;attempt<12;attempt++){await processActiveScans(db,platform);status=(await db.scanRun.findUniqueOrThrow({where:{id:run.id}})).status;if(!['QUEUED','RUNNING'].includes(status))break}
   assert.equal(status,'PARTIAL','explicit cross-product includes denied paths, which must not be called complete coverage');
   const probes=await db.scanProbe.findMany({where:{target:{runId:run.id}}});assert.equal(probes.length,25);
   const confirmed=probes.filter(p=>p.status==='CONFIRMED'),observed=probes.filter(p=>p.status==='OBSERVED'),notFound=probes.filter(p=>p.status==='NOT_FOUND'),outOfScope=probes.filter(p=>p.reason==='OUT_OF_SCOPE');
   assert.equal(confirmed.length,mode==='positive'?4:0,JSON.stringify(probes.map(p=>({name:p.templateName,status:p.status,reason:p.reason}))));assert.equal(observed.length,['positive','auth'].includes(mode)?1:0);assert.ok(observed.every(p=>!p.findingId));assert.equal(outOfScope.length,12);assert.equal(notFound.length+confirmed.length+observed.length,13);
   for(const probe of [...confirmed,...observed,...notFound]){
    const proof=probe.result as {evidence:{native?:{engineVersion:string;templateSha256:string};responseSha256?:string;connections?:Array<{destination:string}>}};const template=templates.find(t=>t.id===probe.templateId)!;const definition=template.definition as {rule:{nativeTemplate:{sha256:string}}};
    assert.equal(proof.evidence.native?.engineVersion,'3.11.1');assert.equal(proof.evidence.native?.templateSha256,definition.rule.nativeTemplate.sha256);assert.match(proof.evidence.responseSha256||'',/^[a-f0-9]{64}$/);assert.ok(proof.evidence.connections?.some(c=>c.destination.startsWith(process.env.SCAN_TEST_HOST!+':')));
   }
   assert.ok(confirmed.every(p=>p.findingId));const target=await db.scanTarget.findFirstOrThrow({where:{runId:run.id}});assert.equal(target.httpRequests,13);assert.equal(await db.finding.count(),4);assert.ok((await db.finding.findMany()).every(f=>f.status==='OPEN'&&f.occurrences===(rounds.length===4?2:1)),'negative rescans cannot close old findings; repeated positive must deduplicate');
   rounds.push({mode,runId:run.id,confirmed:confirmed.length,observed:observed.length,notFound:notFound.length,outOfScope:outOfScope.length,requests:target.httpRequests});
  }
  assert.equal(new Set(rounds.map(r=>r.runId)).size,5);
  const report={passed:true,verifiedAt:new Date().toISOString(),library:{version:snapshot.version,sha256:snapshot.sha256,...snapshot.counts},engine:'3.11.1',realNativeProof:true,rules:cases,rounds,findings:4,occurrences:2,businessTargetsScanned:false,fixture:'Owned HTTP response fixtures match real official template conditions; no real product installations or successful exploitation claimed.',temporarySchema:schema};
  if(process.env.GENERIC_NETWORK_REPORT){await mkdir(resolve(process.env.GENERIC_NETWORK_REPORT,'..'),{recursive:true});await writeFile(process.env.GENERIC_NETWORK_REPORT,JSON.stringify(report,null,2))}
 }finally{
  if(original.worker===undefined)delete process.env.SCAN_WORKER_BINARY;else process.env.SCAN_WORKER_BINARY=original.worker;
  if(original.directory===undefined)delete process.env.PROBE_RULE_LIBRARY_DIR;else process.env.PROBE_RULE_LIBRARY_DIR=original.directory;
  if(original.archive===undefined)delete process.env.PROBE_RULE_LIBRARY_ARCHIVE;else process.env.PROBE_RULE_LIBRARY_ARCHIVE=original.archive;
  await db?.$disconnect();await administrator.$executeRawUnsafe('DROP SCHEMA IF EXISTS "'+schema+'" CASCADE');await administrator.$disconnect();await rm(directory,{recursive:true,force:true});
 }
});
