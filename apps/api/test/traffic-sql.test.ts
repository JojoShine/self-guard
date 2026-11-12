import {test} from 'node:test';
import assert from 'node:assert/strict';
import {parseCapturedSql} from '../src/traffic-sql';
const pg=(kind:string,body:Buffer|string)=>{const payload=Buffer.isBuffer(body)?body:Buffer.from(body),out=Buffer.alloc(payload.length+5);out[0]=kind.charCodeAt(0);out.writeUInt32BE(payload.length+4,1);payload.copy(out,5);return out;};
const mysql=(command:number,body:Buffer|string)=>{const payload=Buffer.concat([Buffer.from([command]),Buffer.from(body)]),out=Buffer.alloc(payload.length+4);out.writeUIntLE(payload.length,0,3);payload.copy(out,4);return out;};
const prepare=(name:string,sql:string)=>pg('P',Buffer.concat([Buffer.from(name+'\0'+sql+'\0'),Buffer.alloc(2)]));
const bind=(portal:string,name:string)=>pg('B',Buffer.concat([Buffer.from(portal+'\0'+name+'\0'),Buffer.alloc(6)]));
const execute=(portal:string)=>pg('E',Buffer.concat([Buffer.from(portal+'\0'),Buffer.alloc(4)]));
test('PostgreSQL extracts original simple SQL including Unicode and whitespace',()=>{
 const sql='  SELECT \'中文\';\n';assert.deepEqual(parseCapturedSql('POSTGRESQL',pg('Q',sql+'\0')),{state:'EXTRACTED',statements:[{sql,stage:'QUERY'}],reasons:[]});
});
test('PostgreSQL differentiates prepare and same-request bound executions without parameter interpolation',()=>{
 assert.equal(parseCapturedSql('POSTGRESQL',prepare('s','SELECT $1')).statements[0].stage,'PREPARE');
 const result=parseCapturedSql('POSTGRESQL',Buffer.concat([prepare('s','SELECT $1'),bind('p','s'),execute('p'),pg('S','')]));assert.deepEqual(result.statements,[{sql:'SELECT $1',stage:'EXECUTE'}]);
 assert.equal(parseCapturedSql('POSTGRESQL',execute('s')).reasons[0],'PREPARED_CONTEXT_MISSING');
 const missing=parseCapturedSql('POSTGRESQL',Buffer.concat([prepare('s','SELECT 1'),execute('s')]));assert.equal(missing.state,'PARTIAL');assert.equal(missing.statements[0].stage,'PREPARE');
});
test('portal binding keeps original statement and closed portals lose context',()=>{
 const result=parseCapturedSql('POSTGRESQL',Buffer.concat([prepare('s','SELECT 1'),bind('p','s'),prepare('s','SELECT 2'),execute('p')]));assert.deepEqual(result.statements,[{sql:'SELECT 2',stage:'PREPARE'},{sql:'SELECT 1',stage:'EXECUTE'}]);
 const closed=parseCapturedSql('POSTGRESQL',Buffer.concat([prepare('s','SELECT 1'),bind('p','s'),pg('C','Pp\0'),execute('p')]));assert.ok(closed.reasons.includes('PREPARED_CONTEXT_MISSING'));
});
test('MySQL query and prepare are distinct; execute parameters never become SQL',()=>{
 assert.deepEqual(parseCapturedSql('MYSQL',mysql(3,'SELECT 42')).statements,[{sql:'SELECT 42',stage:'QUERY'}]);
 assert.equal(parseCapturedSql('MYSQL',mysql(0x16,'SELECT ?')).statements[0].stage,'PREPARE');
 const result=parseCapturedSql('MYSQL',mysql(0x17,'SELECT secret'));assert.equal(result.statements.length,0);assert.ok(result.reasons.includes('PREPARED_CONTEXT_MISSING'));
});
test('invalid framing, UTF8 and oversized SQL fail closed without partial plaintext',()=>{
 for(const body of [Buffer.concat([pg('Q','SELECT 1\0'),Buffer.from([81])]),pg('Q','SELECT 1'),pg('Q','SELECT 1\0extra')])assert.deepEqual(parseCapturedSql('POSTGRESQL',body).statements,[]);
 assert.equal(parseCapturedSql('POSTGRESQL',pg('Q',Buffer.from([0xc3,0x28,0]))).reasons[0],'INVALID_ENCODING');
 assert.equal(parseCapturedSql('MYSQL',mysql(3,'x'.repeat(32769))).reasons[0],'SQL_TOO_LARGE');
 assert.equal(parseCapturedSql('MYSQL',Buffer.alloc(1048577)).reasons[0],'REQUEST_TOO_LARGE');
 assert.equal(parseCapturedSql('POSTGRESQL',Buffer.concat(Array.from({length:101},()=>pg('Q','SELECT 1\0')))).reasons[0],'STATEMENT_LIMIT');
});
test('TLS and authentication messages are not SQL; unsupported protocols stay explicit',()=>{
 assert.equal(parseCapturedSql('POSTGRESQL',Buffer.from([0x16,3,3,0,5])).reasons[0],'TLS_NO_PLAINTEXT');
 assert.equal(parseCapturedSql('POSTGRESQL',Buffer.from('0000000804d2162f','hex')).reasons[0],'TLS_NO_PLAINTEXT');
 assert.equal(parseCapturedSql('POSTGRESQL',pg('p','password\0')).reasons[0],'AUTHENTICATION_MESSAGE');
 const authentication=mysql(3,'password');authentication[3]=1;assert.equal(parseCapturedSql('MYSQL',authentication).reasons[0],'AUTHENTICATION_MESSAGE');
 assert.equal(parseCapturedSql('REDIS',Buffer.from('SELECT password')).state,'UNSUPPORTED');
 assert.equal(parseCapturedSql('POSTGRESQL',pg('S','')).reasons[0],'NO_SQL_MESSAGE');
});
