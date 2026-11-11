import {test} from 'node:test';import assert from 'node:assert/strict';
import {instanceInput,instanceScope,assertInstanceScope} from '../src/database-instances';
test('instance model requires stable identity and preserves multiple hosts',()=>{
 const value={name:'orders',engine:'mysql',stableKey:'mysql-server-uuid',hostIds:['00000000-0000-4000-8000-000000000001','00000000-0000-4000-8000-000000000002'],owner:'dba',business:'payments',endpoints:[{address:'192.0.2.1',port:3306}]};
 assert.equal(instanceInput.parse(value).hostIds.length,2);assert.equal(instanceInput.safeParse({...value,stableKey:''}).success,false);
});
test('native PostgreSQL connection source is explicit and engine constrained',()=>{const value={name:'postgres',engine:'postgresql',stableKey:'postgres-main',owner:'dba',hostIds:['00000000-0000-4000-8000-000000000001'],auditSources:[{assetId:'00000000-0000-4000-8000-000000000001',path:'/var/log/postgresql/postgresql-14-main.log',format:'postgresql-stderr'}]};assert.equal(instanceInput.parse(value).auditSources[0].format,'postgresql-stderr');assert.throws(()=>assertDatabaseRuleEngine('mysql',{service:'postgresql-stderr'}));});
test('database scope is independent of visible host ids',async()=>{
 const user={role:'ANALYST',dataScope:{restricted:true,businesses:['orders'],assetIds:['host'],databaseInstanceIds:['instance']}};
 assert.deepEqual(instanceScope(user),{OR:[{business:{in:['orders']}},{id:{in:['instance']}}]});
 await assert.rejects(()=>assertInstanceScope({databaseInstance:{findFirst:async()=>null}} as never,user,'unseen'));
});
import {assertDatabaseRuleEngine} from '../src/database-instances';
test('server rejects database-specific rules bound to another engine',()=>{assert.throws(()=>assertDatabaseRuleEngine('oracle',{type:'DATABASE_SECURITY',key:'MYSQL_TLS_REQUIRED'}));assert.throws(()=>assertDatabaseRuleEngine('dm',{type:'DATABASE_AUTH',service:'mysql'}));assert.doesNotThrow(()=>assertDatabaseRuleEngine('mysql',{type:'DATABASE_ACTIVITY',engines:['mysql'],service:'audit-json'}));});
