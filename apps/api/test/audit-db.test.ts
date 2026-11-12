import {test} from 'node:test';
import assert from 'node:assert/strict';
import {auditDatabaseUrl,assertAuditDatabaseBoundary} from '../src/audit-db';
const DATABASE_URL='postgresql://selfguard_runtime:runtime-private@postgres:5432/selfguard?schema=public';
const AUDIT_DATABASE_URL='postgresql://selfguard_sql_ingest:ingest-private@postgres:5432/selfguard?schema=public&sslmode=require&sslaccept=strict';
test('isolated audit URL preserves database binding and requires strict TLS without secret errors',()=>{
 assert.equal(auditDatabaseUrl({DATABASE_URL}),undefined);
 assert.equal(new URL(auditDatabaseUrl({DATABASE_URL,AUDIT_DATABASE_URL})!).searchParams.get('connection_limit'),'2');
 for(const value of [AUDIT_DATABASE_URL.replace('postgres:5432','elsewhere:5432'),AUDIT_DATABASE_URL.replace('/selfguard?','/other?'),AUDIT_DATABASE_URL.replace('schema=public','schema=other'),AUDIT_DATABASE_URL.replace('selfguard_sql_ingest','selfguard_runtime'),AUDIT_DATABASE_URL.replace('sslmode=require','sslmode=prefer'),AUDIT_DATABASE_URL.replace('sslaccept=strict','sslaccept=accept_invalid_certs'),AUDIT_DATABASE_URL+'&sslaccept=accept_invalid_certs',AUDIT_DATABASE_URL+'&options=-c%20role%3Dselfguard_runtime',AUDIT_DATABASE_URL+'&host=/tmp',AUDIT_DATABASE_URL+'&connection_limit=50']){
  assert.throws(()=>auditDatabaseUrl({DATABASE_URL,AUDIT_DATABASE_URL:value}),error=>error instanceof Error&&!error.message.includes('ingest-private')&&!error.message.includes('runtime-private'));
 }
});
const good={sessionUser:'selfguard_sql_ingest',currentUser:'selfguard_sql_ingest',database:'selfguard',schema:'public',ssl:true,superuser:false,createRole:false,createDb:false,replication:false,bypassRls:false,inheritsRuntime:true,runtimeCanBecomeIngest:false,runtimeSuperuser:false,duration:'-1',statement:'none',sampleDuration:'-1',transactionSample:'0',logDuration:'off',errorStatement:'panic'};
test('isolated role cannot be assumed by runtime and cannot log its own statements, including failures',()=>{
 assert.doesNotThrow(()=>assertAuditDatabaseBoundary(good));
 for(const mutation of [{runtimeCanBecomeIngest:true},{runtimeSuperuser:true},{inheritsRuntime:false},{ssl:false},{superuser:true},{currentUser:'selfguard_runtime'},{duration:'0'},{statement:'all'},{sampleDuration:'0'},{transactionSample:'1'},{logDuration:'on'},{errorStatement:'error'}])assert.throws(()=>assertAuditDatabaseBoundary({...good,...mutation}));
 assert.throws(()=>assertAuditDatabaseBoundary(undefined));
});
