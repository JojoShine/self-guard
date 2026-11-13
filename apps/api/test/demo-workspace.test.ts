import {test} from 'node:test';
import assert from 'node:assert/strict';
import {applyDemoCommand,newDemoWorkspace,demoCommandInput,demoWorkspaceKey,DemoWorkspaceService} from '../src/demo-workspace';
import {redactEvidence} from '../src/scope';
import {demoRequestAllowed} from '../src/public-demo';
import {Db} from '../src/db';
const user={email:'demo@selfguard.local'};
test('workspace keys are session-bound and never contain the bearer token',()=>{
 assert.notEqual(demoWorkspaceKey(user,'session-one'),demoWorkspaceKey(user,'session-two'));assert.ok(!demoWorkspaceKey(user,'session-one').includes('session-one'));
 assert.throws(()=>demoWorkspaceKey({email:'admin@example.invalid'},'session-one'));assert.throws(()=>demoWorkspaceKey(user,''));
});
test('only the exact experience endpoints allow writes; production routes remain denied',()=>{
 for(const method of ['GET','POST'])assert.equal(demoRequestAllowed(method,'/self-guard/api/demo-workspace','/self-guard'),true);
 for(const path of ['/api/demo-workspace/reset','/api/demo-workspace/','/api/assets','/api/probe-deployments','/api/database-instances','/api/active-scans'])assert.equal(demoRequestAllowed('POST',path,''),false);
 assert.equal(demoRequestAllowed('DELETE','/api/demo-workspace',''),false);
});
test('actual experience changes persist through a complete check and finding workflow',()=>{
 let state=newDemoWorkspace(1000);state=applyDemoCommand(state,{action:'ADD_ASSET',revision:0,name:'my example',profile:'OUTDATED'},1000);assert.equal(state.assets.length,3);
 state=applyDemoCommand(state,{action:'CREATE_SCAN',revision:1,name:'first check',assetIds:state.assets.slice(0,2).map(a=>a.id)},1000);assert.equal(state.scans[0].status,'READY');
 state=applyDemoCommand(state,{action:'EXECUTE_SCAN',revision:2,id:state.scans[0].id},1000);assert.equal(state.scans[0].status,'DONE');assert.equal(state.findings.length,1);
 state=applyDemoCommand(state,{action:'UPDATE_FINDING',revision:3,id:state.findings[0].id,status:'CONFIRMED'},1000);assert.equal(state.findings[0].status,'CONFIRMED');
 assert.throws(()=>applyDemoCommand(state,{action:'REMOVE_ASSET',revision:4,id:state.assets[0].id},1000),/任务/);
 assert.throws(()=>applyDemoCommand(state,{action:'EXECUTE_SCAN',revision:4,id:'00000000-0000-4000-8000-000000000000'},1000));
});
test('validation, optimistic concurrency, limits and expiry fail without mutating prior state',()=>{
 const state=newDemoWorkspace(1000),before=JSON.stringify(state);
 assert.equal(demoCommandInput.safeParse({action:'ADD_ASSET',revision:0,name:'x',profile:'CURRENT',workspaceKey:'other'}).success,false);
 assert.throws(()=>applyDemoCommand(state,{action:'ADD_ASSET',revision:1,name:'x',profile:'CURRENT'},1000),/刷新/);
 assert.throws(()=>applyDemoCommand(state,{action:'CREATE_SCAN',revision:0,name:'x',assetIds:['00000000-0000-4000-8000-000000000000']},1000));
 assert.throws(()=>applyDemoCommand(state,{action:'ADD_ASSET',revision:0,name:'x',profile:'CURRENT'},state.expiresAt),/到期/);
 assert.equal(JSON.stringify(state),before);
 let full=state;for(let i=0;i<18;i++)full=applyDemoCommand(full,{action:'ADD_ASSET',revision:full.revision,name:'x'+i,profile:'CURRENT'},1000);
 assert.throws(()=>applyDemoCommand(full,{action:'ADD_ASSET',revision:full.revision,name:'overflow',profile:'CURRENT'},1000),/20/);
});
test('SQL samples invoke the real framed parser and never execute user-supplied SQL',()=>{
 let state=newDemoWorkspace(1000);
 for(const sample of ['SIMPLE','PREPARED','TLS'] as const)state=applyDemoCommand(state,{action:'PARSE_SQL',revision:state.revision,sample},1000);
 assert.equal(state.sqlSamples[0].statements[0].sql,'SELECT 42 AS demo_value');assert.equal(state.sqlSamples[1].statements[0].stage,'EXECUTE');assert.deepEqual(state.sqlSamples[2].reasons,['TLS_NO_PLAINTEXT']);
 const redacted=redactEvidence({role:'VIEWER',dataScope:{restricted:true,canReadEvidence:false}},state);assert.equal(redacted.sqlSamples[0].statements[0].sql,'SELECT 42 AS demo_value');
 assert.equal(demoCommandInput.safeParse({action:'PARSE_SQL',revision:0,sample:'SIMPLE',sql:'DROP TABLE x'}).success,false);
});
test('service persists only isolated Setting state and reset leaves other sessions intact',async()=>{
 const values=new Map<string,unknown>(),db=new Db();
 const settings={findUnique:async({where}:{where:{key:string}})=>values.has(where.key)?{value:values.get(where.key)}:null,deleteMany:async()=>({count:0}),count:async()=>values.size,upsert:async({where,create}:{where:{key:string};create:{value:unknown}})=>{values.set(where.key,structuredClone(create.value));return{};}};
 Object.defineProperty(db,'$transaction',{value:async(work:(tx:unknown)=>Promise<unknown>)=>work({setting:settings,$queryRaw:async()=>[]})});
 Object.defineProperty(db,'setting',{value:settings});const service=new DemoWorkspaceService(db);
 try{let a=await service.read(user,'one');await service.command(user,'one',{action:'ADD_ASSET',revision:a.revision,name:'private-session-asset',profile:'CURRENT'});a=await service.read(user,'one');assert.equal(a.assets.length,3);const b=await service.read(user,'two');assert.equal(b.assets.length,2);
 await service.command(user,'two',{action:'ADD_ASSET',revision:b.revision,name:'second',profile:'CURRENT'});await service.command(user,'one',{action:'RESET',revision:a.revision});assert.equal((await service.read(user,'one')).assets.length,2);assert.equal((await service.read(user,'two')).assets.length,3);assert.equal(values.size,2);
 }finally{await db.$disconnect();}
});
