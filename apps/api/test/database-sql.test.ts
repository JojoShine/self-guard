import {test} from 'node:test';
import assert from 'node:assert/strict';
import {databaseEventInput} from '../src/database-contract';
import {sealDatabaseSql,openDatabaseSql,sqlExpiresAt,canReadDatabaseSql} from '../src/database-sql';

test('SQL input is opt-in, bounded, and preserves original whitespace',()=>{
 const value={eventId:'session:1',instanceId:'00000000-0000-4000-8000-000000000001',timestamp:new Date().toISOString(),service:'postgresql',operation:'SELECT',user:'app',execution:{sql:" SELECT\n 'private-value' ",protocol:'SIMPLE',sqlState:'00000',durationMs:1.25}};
 assert.equal(databaseEventInput.parse(value).execution?.sql,value.execution.sql);
 assert.throws(()=>databaseEventInput.parse({...value,execution:{...value.execution,durationMs:-1}}));
 assert.throws(()=>databaseEventInput.parse({...value,execution:{...value.execution,sql:'x'.repeat(32769)}}));
});
test('SQL is encrypted, bound to its audit event, expires after seven days, and requires an independent grant',()=>{
 const previous=process.env.DATA_ENCRYPTION_KEY;process.env.DATA_ENCRYPTION_KEY='a'.repeat(64);
 try{const sql="SELECT 'private-value'",cipher=sealDatabaseSql('audit-one',sql);assert.ok(!cipher.includes('private-value'));assert.equal(openDatabaseSql('audit-one',cipher),sql);assert.throws(()=>openDatabaseSql('audit-two',cipher));
 assert.equal(sqlExpiresAt(new Date('2026-11-01T00:00:00Z')).toISOString(),'2026-11-08T00:00:00.000Z');
 assert.equal(canReadDatabaseSql({role:'ANALYST',email:'a'}),false);assert.equal(canReadDatabaseSql({role:'ANALYST',email:'a',dataScope:{canReadSqlEvidence:true}}),true);assert.equal(canReadDatabaseSql({role:'ANALYST',email:'a',dataScope:{canReadSqlEvidence:true,canReadEvidence:false}}),false);
 }finally{if(previous===undefined)delete process.env.DATA_ENCRYPTION_KEY;else process.env.DATA_ENCRYPTION_KEY=previous;}
});
