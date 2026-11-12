import {test} from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp,rm,readFile,writeFile} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {createHash,randomUUID} from 'node:crypto';
import {AccessObservationService} from '../src/access-observation';
import {AccessEvidenceStore} from '../src/access-evidence';
import {Db} from '../src/db';
import {Platform} from '../src/platform';
const user={email:'reader@example.invalid',role:'ANALYST',dataScope:{canReadEvidence:true,canReadAccessEvidence:true,canReadSqlEvidence:true,restricted:true,assetIds:[randomUUID()],databaseInstanceIds:[randomUUID()]}};
async function fixture(){
 const root=await mkdtemp(join(tmpdir(),'packet-sql-')),store=new AccessEvidenceStore(root,'ab'.repeat(32)),sourceId=randomUUID(),eventId=randomUUID(),capturedAt=new Date(),sql='SELECT 42',payload=Buffer.from(sql+'\0'),request=Buffer.alloc(payload.length+5);request[0]=81;request.writeUInt32BE(payload.length+4,1);payload.copy(request,5);
 const binding={sourceId,eventId,direction:'REQUEST',sequence:0,capturedAt:capturedAt.toISOString(),sha256:createHash('sha256').update(request).digest('hex')},object=await store.put(binding,request);
 const chunk={...binding,id:randomUUID(),capturedAt,expiresAt:new Date(capturedAt.getTime()+7*86400000),object,bytes:request.length};
 const row={id:randomUUID(),sourceId,eventId,chunkIds:[chunk.id],requestBytes:BigInt(request.length),responseBytes:0n,source:{protocol:'POSTGRESQL'},startedAt:capturedAt,operation:'SELECT',completeness:'COMPLETE',metadata:{gaps:[] as string[]}};
 let visible=true;const audit:unknown[]=[],queries:unknown[]=[];const db=new Db();
 Object.defineProperty(db,'accessObservation',{value:{findFirst:async(query:unknown)=>{queries.push(query);return visible?row:null;}}});
 Object.defineProperty(db,'accessEvidenceChunk',{value:{findMany:async()=>[chunk],findFirst:async()=>chunk}});
 Object.defineProperty(db,'audit',{value:{create:async(value:unknown)=>{audit.push(value);return{};}}});
 const service=new AccessObservationService(db,new Platform(db));service.store=()=>store;
 return{service,row,chunk,audit,queries,root,deny:()=>{visible=false;},cleanup:async()=>{await db.$disconnect();await rm(root,{recursive:true,force:true});}};
}
test('packet SQL requires both independent grants before any lookup and respects record scope',async()=>{const f=await fixture();try{
 for(const scope of [{canReadAccessEvidence:false},{canReadSqlEvidence:false},{canReadEvidence:false}])await assert.rejects(()=>f.service.sql({...user,dataScope:{...user.dataScope,...scope}},f.row.id));
 assert.equal(f.queries.length,0);f.deny();await assert.rejects(()=>f.service.sql(user,f.row.id),/授权范围/);assert.equal(f.audit.length,0);assert.ok(JSON.stringify(f.queries).includes(user.dataScope.assetIds[0]));assert.ok(JSON.stringify(f.queries).includes(user.dataScope.databaseInstanceIds[0]));
}finally{await f.cleanup();}});
test('packet SQL uses authenticated encrypted chunks and read audit without persisting SQL',async()=>{const f=await fixture();try{
 const result=await f.service.sql(user,f.row.id);assert.equal(result.state,'EXTRACTED');assert.equal(result.statements[0].sql,'SELECT 42');assert.equal(f.audit.length,1);assert.equal(JSON.stringify(f.audit).includes('SELECT 42'),false);
 const detail=await f.service.detail(user,f.row.id);assert.equal(detail.canReadSql,true);assert.equal((await f.service.detail({...user,dataScope:{...user.dataScope,canReadSqlEvidence:false}},f.row.id)).canReadSql,false);
 const path=join(f.root,f.chunk.object),cipher=await readFile(path);cipher[cipher.length-1]^=1;await writeFile(path,cipher);await assert.rejects(()=>f.service.sql(user,f.row.id),/认证校验/);
}finally{await f.cleanup();}});
test('expired, missing, oversized and TLS evidence never decrypts or claims SQL',async()=>{const f=await fixture();try{
 f.chunk.expiresAt=new Date(0);assert.deepEqual((await f.service.sql(user,f.row.id)).reasons,['EVIDENCE_EXPIRED']);f.chunk.expiresAt=new Date(Date.now()+60000);
 f.chunk.sequence=1;assert.deepEqual((await f.service.sql(user,f.row.id)).reasons,['INCOMPLETE_EVIDENCE']);f.chunk.sequence=0;
 f.row.requestBytes=1048577n;assert.deepEqual((await f.service.sql(user,f.row.id)).reasons,['REQUEST_TOO_LARGE']);f.row.requestBytes=BigInt(f.chunk.bytes);
 f.row.metadata.gaps=['TLS_NO_PLAINTEXT'];assert.deepEqual((await f.service.sql(user,f.row.id)).reasons,['TLS_NO_PLAINTEXT']);assert.equal(f.audit.length,0);
}finally{await f.cleanup();}});
test('partial requests retain coverage gaps and authentication records are never opened',async()=>{const f=await fixture();try{
 f.row.completeness='PARTIAL';f.row.metadata.gaps=['CAPTURE_LOSS'];const partial=await f.service.sql(user,f.row.id);assert.equal(partial.state,'PARTIAL');assert.equal(partial.statements[0].sql,'SELECT 42');assert.ok(partial.reasons.includes('CAPTURE_LOSS'));
 f.row.completeness='UNSUPPORTED';assert.equal((await f.service.sql(user,f.row.id)).state,'UNSUPPORTED');
 const reads=f.audit.length;f.row.operation='LOGIN';assert.deepEqual((await f.service.sql(user,f.row.id)).reasons,['AUTHENTICATION_MESSAGE']);assert.equal(f.audit.length,reads);
}finally{await f.cleanup();}});
test('expiration while decrypting does not return previously recovered SQL',async()=>{const f=await fixture();try{
 const original=f.service.readChunk.bind(f.service);f.service.readChunk=async(...args)=>{const result=await original(...args);result.expiresAt=new Date(0);return result;};
 const result=await f.service.sql(user,f.row.id);assert.deepEqual(result.reasons,['EVIDENCE_EXPIRED']);assert.equal(result.statements.length,0);
}finally{await f.cleanup();}});
test('response evidence is never decoded as request SQL',async()=>{const f=await fixture();try{
 f.chunk.direction='RESPONSE';const result=await f.service.sql(user,f.row.id);assert.deepEqual(result.reasons,['BODY_NOT_CAPTURED']);assert.equal(f.audit.length,0);
}finally{await f.cleanup();}});
test('source list keeps instance and asset filters inside existing authorization scope',async()=>{
 const db=new Db(),queries:unknown[]=[],instanceId=user.dataScope.databaseInstanceIds[0],assetId=user.dataScope.assetIds[0];
 Object.defineProperty(db,'accessSource',{value:{findMany:async(q:unknown)=>{queries.push(q);return[];},count:async(q:unknown)=>{queries.push(q);return 0;}}});
 const service=new AccessObservationService(db,new Platform(db));await service.sources(user,{instanceId,assetId});
 for(const query of queries){const where=(query as {where:{AND:unknown[]}}).where;assert.ok(where.AND.some(part=>JSON.stringify(part)===JSON.stringify({instanceId})));assert.ok(where.AND.some(part=>JSON.stringify(part)===JSON.stringify({assetId})));assert.ok(JSON.stringify(where.AND[0]).includes('instance'));assert.ok(JSON.stringify(where.AND[0]).includes('asset'));}
 await assert.rejects(()=>service.sources(user,{instanceId:'invalid'}));await db.$disconnect();
});
