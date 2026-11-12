import {test} from 'node:test';
import assert from 'node:assert/strict';
import {baseAgentDatabaseSources,independentBinding,bindIndependentDatabaseSource} from '../src/database-monitor-binding';
import {Db} from '../src/db';
const instanceId='00000000-0000-4000-8000-000000000001',assetId='00000000-0000-4000-8000-000000000002';
const source={assetId,path:'/var/log/audit',format:'postgresql-csv-sql' as const},instance={id:instanceId,engine:'postgresql',auditSources:[source],updatedAt:new Date()};
test('base policy excludes only durable exact independent bindings',()=>{
 const binding=independentBinding(instanceId,source);
 assert.equal(baseAgentDatabaseSources(assetId,[instance],[]).length,1);
 assert.deepEqual(baseAgentDatabaseSources(assetId,[instance],[binding]),[]);
 for(const changed of [{...binding,key:binding.key+'x'},{...binding,value:{...binding.value,format:'postgresql-csv'}},{...binding,value:{...binding.value,assetId:instanceId}},{...binding,value:{...binding.value,sourcePath:'/other'}},{...binding,value:{...binding.value,instanceId:assetId}},{...binding,value:{...binding.value,extra:'x'}}])assert.equal(baseAgentDatabaseSources(assetId,[instance],[changed]).length,1);
 assert.deepEqual(baseAgentDatabaseSources(assetId,[{...instance,auditSources:[]}],[binding]),[]);
 assert.equal(baseAgentDatabaseSources(assetId,[{...instance,auditSources:[{...source,path:'/new'}]}],[binding]).length,1);
});
test('source and binding use same transaction and failed version update never writes binding',async()=>{
 const db=new Db();let count=1;const calls:string[]=[];
 Object.defineProperty(db,'databaseInstance',{value:{updateMany:async()=>{calls.push('source');return{count};}}});
 Object.defineProperty(db,'setting',{value:{upsert:async(input:unknown)=>{calls.push('binding');assert.deepEqual(input,{where:{key:independentBinding(instanceId,source).key},create:independentBinding(instanceId,source),update:{value:independentBinding(instanceId,source).value}});}}});
 await bindIndependentDatabaseSource(db,instance,source);assert.deepEqual(calls,['source','binding']);
 calls.length=0;count=0;await assert.rejects(()=>bindIndependentDatabaseSource(db,instance,source));assert.deepEqual(calls,['source']);await db.$disconnect();
});
import {AgentController} from '../src/components';
import {Platform} from '../src/platform';
test('actual Agent policy batch-loads persistent ownership and preserves manual sources',async()=>{
 const db=new Db(),manual={...source,path:'/var/log/manual'};let reads=0;
 Object.defineProperty(db,'asset',{value:{findUnique:async()=>({id:assetId,archivedAt:null,tags:[],business:null})}});
 Object.defineProperty(db,'databaseInstance',{value:{findMany:async()=>[{...instance,auditSources:[source,manual]}]}});
 Object.defineProperty(db,'setting',{value:{findMany:async(query:unknown)=>{reads++;assert.deepEqual(query,{where:{key:{startsWith:'database-monitor-binding:'+assetId+':'}}});return[independentBinding(instanceId,source)];}}});
 Object.defineProperty(db,'rule',{value:{findMany:async()=>[]}});
 const controller=new AgentController(db,new Platform(db)),result=await controller.policy({headers:{authorization:'Bearer test-token'},query:{capabilities:'data-security-v2'}});
 assert.equal(reads,1);assert.deepEqual(result.databaseSources,[{instanceId,engine:'postgresql',path:manual.path,service:manual.format}]);
 await db.$disconnect();
});
