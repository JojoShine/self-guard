import {test} from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp,readFile,writeFile,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {createHash} from 'node:crypto';
import {accessEventInput,accessChunkInput,evidenceExpiresAt,assertEvidenceLive,accessGapCodes,probeHealthInput} from '../src/access-contract';
import {AccessEvidenceStore,accessEvidenceUsage} from '../src/access-evidence';
const source='7bcd88eb-3a3b-41f6-bb6e-776d72415856',event='ea6d345c-68c7-4cff-927d-589f82466af8';
test('probe health accepts every actual evidence gap rather than silently losing degraded status',()=>{for(const gap of accessGapCodes)assert.equal(probeHealthInput.safeParse({state:'DEGRADED',version:'0.1.0',capturedPackets:24,droppedPackets:null,queueBytes:32,pendingEvents:0,gap,configurationVersion:1}).success,true);});
test('access input preserves separate real operations and rejects untrusted identity, paths and oversized chunks',()=>{
 const base={eventId:event,startedAt:new Date().toISOString(),endedAt:new Date().toISOString(),sessionId:'session-1',operation:'GET',route:'/orders',result:'SUCCESS',completeness:'COMPLETE',gaps:[],requestBytes:0,responseBytes:0,chunks:[],objects:[]};
 assert.equal(accessEventInput.parse(base).route,'/orders');
 for(const change of [{businessUser:'forged header'},{route:'/orders?password=secret'},{result:'SAFE'},{gaps:['INVENTED']},{responseBytes:-1}])assert.equal(accessEventInput.safeParse({...base,...change}).success,false);
 assert.equal(accessEventInput.safeParse({...base,completeness:'COMPLETE',gaps:['CAPTURE_LOSS']}).success,false);
 assert.equal(accessChunkInput.safeParse({eventId:event,direction:'RESPONSE',sequence:0,capturedAt:new Date().toISOString(),sha256:'0'.repeat(64),data:Buffer.alloc(262145).toString('base64')}).success,false);
});
test('seven days uses capture time and rejects future capture and late access',()=>{
 const at=new Date('2026-01-01T00:00:00Z');assert.equal(evidenceExpiresAt(at).toISOString(),'2026-01-08T00:00:00.000Z');
 assert.doesNotThrow(()=>assertEvidenceLive(at,new Date('2026-01-07T23:59:59Z')));
 assert.throws(()=>assertEvidenceLive(at,new Date('2026-01-08T00:00:00Z')));
 assert.throws(()=>assertEvidenceLive(new Date('2026-01-09T00:00:00Z'),at));
});
test('evidence persists binary encrypted, is idempotent and binds source/event/sequence and checksum',async()=>{
 const dir=await mkdtemp(join(tmpdir(),'sg-evidence-'));const store=new AccessEvidenceStore(dir,'a'.repeat(64));
 try{const bytes=Buffer.from([0,255,1,0,127]),part={sourceId:source,eventId:event,direction:'RESPONSE' as const,sequence:0,capturedAt:new Date().toISOString(),sha256:createHash('sha256').update(bytes).digest('hex')};
  const object=await store.put(part,bytes);assert.equal(await store.put(part,bytes),object);
  const disk=await readFile(join(dir,object));assert.ok(!disk.includes(bytes));assert.deepEqual(await store.read(part,object),bytes);
  await assert.rejects(()=>store.put({...part,sha256:'0'.repeat(64)},bytes));
  await assert.rejects(()=>store.read({...part,sourceId:event},object));
  await assert.rejects(()=>store.read(part,'../outside'));
  disk[disk.length-1]^=1;await writeFile(join(dir,object),disk);await assert.rejects(()=>store.read(part,object));
 }finally{await rm(dir,{recursive:true,force:true});}
});
test('evidence remains readable through a configured key rotation without rewriting capture time',async()=>{
 const dir=await mkdtemp(join(tmpdir(),'sg-evidence-'));const original=new AccessEvidenceStore(dir,'a'.repeat(64)),bytes=Buffer.from('rotation-fixture');
 try{const binding={sourceId:source,eventId:event,direction:'RESPONSE',sequence:0,capturedAt:new Date().toISOString(),sha256:createHash('sha256').update(bytes).digest('hex')},object=await original.put(binding,bytes);const rotated=new AccessEvidenceStore(dir,'b'.repeat(64),['a'.repeat(64)]);assert.deepEqual(await rotated.read(binding,object),bytes);}finally{await rm(dir,{recursive:true,force:true});}
});
test('quota charges ciphertext framing and existing unreferenced objects',async()=>{
 const dir=await mkdtemp(join(tmpdir(),'sg-evidence-budget-')),store=new AccessEvidenceStore(dir,'a'.repeat(64));
 try{const bytes=Buffer.from('x'),part={sourceId:source,eventId:event,direction:'RESPONSE' as const,sequence:0,capturedAt:new Date().toISOString(),sha256:createHash('sha256').update(bytes).digest('hex')};
 await assert.rejects(()=>store.put(part,bytes,32),/配额/);const object=await store.put(part,bytes,33);assert.equal((await readFile(join(dir,object))).length,33);await assert.rejects(()=>store.put({...part,sequence:1},bytes,33),/配额/);assert.equal(await store.put(part,bytes,33),object);
 }finally{await rm(dir,{recursive:true,force:true});}
});

test('interrupted reservations and deletion recover without forgetting live ciphertext',async()=>{
 const dir=await mkdtemp(join(tmpdir(),'sg-evidence-recovery-')),store=new AccessEvidenceStore(dir,'a'.repeat(64));
 try{
  const bytes=Buffer.from('x'),part={sourceId:source,eventId:event,direction:'RESPONSE' as const,sequence:0,capturedAt:new Date().toISOString(),sha256:createHash('sha256').update(bytes).digest('hex')};
  const object=await store.put(part,bytes,33),pending='00000000-0000-4000-8000-000000000001.pending';
  await writeFile(join(dir,pending),Buffer.alloc(33));
  await writeFile(join(dir,'.usage.json'),JSON.stringify({version:1,bytes:33,put:{object,temporary:pending,bytes:33}}));
  assert.equal(await store.put(part,bytes,33),object);assert.equal((await accessEvidenceUsage(dir)).bytes,33);
  await assert.rejects(()=>readFile(join(dir,pending)),{code:'ENOENT'});
  await writeFile(join(dir,'.usage.json'),JSON.stringify({version:1,bytes:66,put:{object:'f'.repeat(64)+'.evidence',temporary:pending,bytes:33}}));
  assert.equal(await store.put(part,bytes,33),object);assert.equal((await accessEvidenceUsage(dir)).bytes,33);
  const second=await store.put({...part,sequence:1},bytes,66);await rm(join(dir,second));
  await writeFile(join(dir,'.usage.json'),JSON.stringify({version:1,bytes:66,remove:[{object,bytes:33},{object:second,bytes:33}]}));
  assert.equal(await store.put(part,bytes,33),object);assert.equal((await accessEvidenceUsage(dir)).bytes,33);
  await store.remove(object);assert.equal((await accessEvidenceUsage(dir)).bytes,0);
 }finally{await rm(dir,{recursive:true,force:true});}
});
