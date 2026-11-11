import {test} from 'node:test';
import assert from 'node:assert/strict';
import {databaseCapabilities} from '../src/database-capabilities';
import {databaseEventInput} from '../src/database-contract';
test('capabilities distinguish commands, SQL and externally prepared audit sources across engines',()=>{
 for(const engine of ['postgresql','mysql','oracle','redis','dm','kingbase','vastbase']){
  const value=databaseCapabilities(engine);assert.equal(value.engine,engine);assert.ok(value.runtime.requirements.length);assert.ok(value.auditFormats.length);assert.ok(value.auditFormats.every(format=>format.notes.length>0));
 }
 assert.equal(databaseCapabilities('redis').rawStatement.kind,'COMMAND');
 assert.equal(databaseCapabilities('sqlserver').runtime.supported,false);
 assert.ok(databaseCapabilities('mysql').auditFormats.some(format=>format.value==='mysql-audit-sql-json'));
 assert.ok(!databaseCapabilities('mysql').auditFormats.some(format=>format.value.startsWith('postgresql')));
});
test('non-PostgreSQL audit does not invent SQLSTATE and Redis retains unknown-actor evidence',()=>{
 const base={eventId:'audit1',instanceId:'00000000-0000-4000-8000-000000000001',timestamp:'2026-11-11T01:00:00Z',service:'mysql',user:'app',operation:'SELECT',execution:{sql:'SELECT 1',protocol:'AUDIT'}};
 assert.equal(databaseEventInput.parse(base).execution?.sqlState,undefined);
 const command=databaseEventInput.parse({...base,service:'redis',user:'[unknown]',userKnown:false,operation:'OTHER',execution:{sql:'["GET","key"]',protocol:'COMMAND'}});
 assert.equal(command.userKnown,false);assert.equal(command.execution?.protocol,'COMMAND');
 assert.equal(databaseEventInput.safeParse({...base,execution:{sql:'x'.repeat(32769),protocol:'AUDIT'}}).success,false);
});
test('PostgreSQL execution keeps required SQLSTATE and DM advertises its TLS limitation',()=>{
 const base={eventId:'pg',instanceId:'00000000-0000-4000-8000-000000000001',timestamp:'2026-11-11T01:00:00Z',service:'postgresql',user:'app',operation:'SELECT'};
 for(const protocol of ['SIMPLE','EXTENDED','ERROR'])assert.equal(databaseEventInput.safeParse({...base,execution:{protocol,sql:'SELECT 1'}}).success,false);
 assert.equal(databaseCapabilities('dm').runtime.supported,false);
});
