import {test} from 'node:test';
import assert from 'node:assert/strict';
import {onboardingInput,assertOnboardingTarget,onboardingJobState,isPlatformDatabase,monitorHealthInput} from '../src/database-onboarding';
const target={deployment:'DOCKER' as const,container:'postgres',port:5432,database:'selfguard'};
test('onboarding rejects target ambiguity and unregistered ports',()=>{
 const base={assetId:'00000000-0000-4000-8000-000000000001',action:'CHECK',target,expectedUpdatedAt:new Date().toISOString()};
 assert.equal(onboardingInput.safeParse(base).success,true);
 for(const change of [{container:'x;id'},{container:undefined},{port:0}])assert.equal(onboardingInput.safeParse({...base,target:{...target,...change}}).success,false);
 assert.throws(()=>assertOnboardingTarget({engine:'mysql',endpoints:[{address:'host',port:5432}]},target));
 assert.throws(()=>assertOnboardingTarget({engine:'postgresql',endpoints:[{address:'host',port:5433}]},target));
});
test('maintenance waiting and blocked never become successful install',()=>{
 assert.equal(onboardingJobState('WAITING_RESTART'),'WAITING_RESTART');assert.equal(onboardingJobState('BLOCKED'),'FAILED');assert.equal(onboardingJobState('INSTALLED'),'SUCCEEDED');
});
test('self database recognition does not depend solely on stable key',()=>{
 const url='postgresql://runtime:private@postgres:5432/selfguard';
 assert.equal(isPlatformDatabase({stableKey:'renamed',endpoints:[{address:'postgres',port:5432}]},target,null,url),true);
 assert.equal(isPlatformDatabase({stableKey:'other',endpoints:[]},target,{address:'postgres',port:5432,database:'selfguard'},url),true);
 assert.equal(isPlatformDatabase({stableKey:'other',endpoints:[]},{...target,database:'business'},null,url),false);
});
test('health rejects SQL, credentials and arbitrary detail text',()=>{
 const base={instanceId:'00000000-0000-4000-8000-000000000001',sourcePath:'/var/log/sql',status:'WAITING',version:'0.4.28',queuedBatches:0,acceptedEvents:0,invalidRecords:0,rotationGaps:0,detailCode:'WAITING_LOG'};
 assert.equal(monitorHealthInput.safeParse(base).success,true);
 assert.equal(monitorHealthInput.safeParse({...base,sql:'secret'}).success,false);
 assert.equal(monitorHealthInput.safeParse({...base,detailCode:'private sql'}).success,false);
});
import {Db} from '../src/db';
import {AgentDatabaseMonitorController} from '../src/database-onboarding';
import {hashToken} from '../src/security';
test('monitor refresh and health recheck token, archive, host and exact source path before writing',async()=>{
 const assetId='00000000-0000-4000-8000-000000000002',instanceId='00000000-0000-4000-8000-000000000001',sourcePath='/audit/native';
 const asset={id:assetId,archivedAt:null as Date|null,tokenHash:hashToken('test-token')};
 const instance={engine:'postgresql',archivedAt:null as Date|null,hostIds:[assetId],auditSources:[{assetId,path:sourcePath,format:'postgresql-csv-sql'}]};
 let writes=0;const db=new Db();
 const tx={$queryRaw:async()=>[],asset:{findUnique:async()=>asset,findUniqueOrThrow:async()=>asset},databaseInstance:{findUnique:async()=>instance},setting:{upsert:async()=>{writes++;return{};}}};
 Object.defineProperty(db,'$transaction',{value:async(fn:(value:typeof tx)=>Promise<unknown>)=>fn(tx)});
 const controller=new AgentDatabaseMonitorController(db),req={headers:{authorization:'Bearer test-token'}},query={instanceId,sourcePath};
 assert.deepEqual(await controller.get(req,query),{...query,assetId,format:'postgresql-csv-sql',engine:'postgresql',enabled:true});
 const health={...query,status:'READING',version:'0.4.28',queuedBatches:0,acceptedEvents:1,invalidRecords:0,rotationGaps:0,detailCode:'READING'};
 await controller.status(req,health);assert.equal(writes,1);
 await assert.rejects(()=>controller.get({headers:{}},query));
 await assert.rejects(()=>controller.get(req,{...query,sourcePath:'/audit/other'}));
 asset.tokenHash=hashToken('revoked');await assert.rejects(()=>controller.status(req,health));asset.tokenHash=hashToken('test-token');
 asset.archivedAt=new Date();await assert.rejects(()=>controller.status(req,health));asset.archivedAt=null;
 instance.hostIds=[];await assert.rejects(()=>controller.status(req,health));instance.hostIds=[assetId];
 instance.auditSources=[];await assert.rejects(()=>controller.status(req,health));assert.equal(writes,1);
 await db.$disconnect();
});
import {DatabaseOnboardingService} from '../src/database-onboarding';
import {AssetRemoteService} from '../src/asset-remote';
import {User} from '@prisma/client';
test('non-admin and disabled owners cannot enqueue remote operations',async()=>{
 const db=new Db(),service=new DatabaseOnboardingService(db,db,new AssetRemoteService(db));
 const user:User={id:'00000000-0000-4000-8000-000000000001',email:'test@example.invalid',name:'test',role:'VIEWER',disabled:false,dataScope:{},passwordHash:'unused',createdAt:new Date(),updatedAt:new Date()};
 await assert.rejects(()=>service.create(user,'id',{}),/管理员/);
 await assert.rejects(()=>service.create({...user,role:'ADMIN',disabled:true},'id',{}),/管理员/);
 await db.$disconnect();
});
test('queue collision is serialized per asset and rejects a changed instance version',async()=>{
 const db=new Db(),remote=new AssetRemoteService(db),service=new DatabaseOnboardingService(db,db,remote),now=new Date(),id='00000000-0000-4000-8000-000000000001',assetId='00000000-0000-4000-8000-000000000002';
 const instance={id,archivedAt:null,hostIds:[assetId],engine:'postgresql',endpoints:[{address:'postgres',port:5432}],updatedAt:now};
 Object.defineProperty(db,'databaseInstance',{value:{findFirst:async()=>instance}});
 Object.defineProperty(remote,'connection',{value:async()=>({asset:{id:assetId,tokenHash:'bound'},access:{address:'127.0.0.1',updatedAt:now}})});
 let locked=false,created=0,active=1,changed=false;
 const tx={$queryRaw:async()=>{locked=true;return[];},assetRemoteJob:{count:async()=>{assert.equal(locked,true);return active;},create:async()=>{created++;return{};}},databaseInstance:{findUniqueOrThrow:async()=>({...instance,updatedAt:changed?new Date(now.getTime()+1):now})}};
 Object.defineProperty(db,'$transaction',{value:async(fn:(value:typeof tx)=>Promise<unknown>)=>fn(tx)});
 const user:User={id,email:'test@example.invalid',name:'test',role:'ADMIN',disabled:false,dataScope:{},passwordHash:'unused',createdAt:now,updatedAt:now};
 const input={assetId,action:'CHECK',target,expectedUpdatedAt:now.toISOString()};
 await assert.rejects(()=>service.create(user,id,input),/已有操作/);assert.equal(created,0);
 active=0;changed=true;await assert.rejects(()=>service.create(user,id,input),/实例已变化/);assert.equal(created,0);
 await db.$disconnect();
});
import {databaseIdentityMatches} from '../src/database-onboarding';
import {createHash} from 'node:crypto';
test('actual database identity recognizes aliases without hostname or container names',()=>{
 const actual={database:'selfguard',startedEpoch:'1794451540.123456'},identity=createHash('sha256').update(actual.database+'|'+actual.startedEpoch).digest('hex');
 assert.equal(databaseIdentityMatches(identity,actual),true);
 assert.equal(databaseIdentityMatches(identity,{...actual,database:'other'}),false);
 assert.equal(databaseIdentityMatches(identity,{...actual,startedEpoch:'1794451541.123456'}),false);
 assert.equal(databaseIdentityMatches(undefined,actual),false);
 assert.equal(databaseIdentityMatches(identity,undefined),false);
});
