import {test} from 'node:test';
import assert from 'node:assert/strict';
import {generateKeyPairSync,sign} from 'node:crypto';
import {verifyExecutorResult} from '../src/executor-proof';

const keys=generateKeyPairSync('ed25519');
const publicKey=keys.publicKey.export({format:'der',type:'spki'}).subarray(-32).toString('base64');
const details={path:'/fixture/config',before:{mode:'0644',owners:['root','fixture']},after:{mode:'0600'}};
const result={success:true,evidence:'independent executor observed mode 0600',details};
const payload={taskId:'task-1',assetId:'asset-1',result};
function proof(value:unknown,raw?:Buffer){const bytes=raw||Buffer.from(JSON.stringify(value));return JSON.stringify({payload:bytes.toString('base64'),signature:sign(null,bytes,keys.privateKey).toString('base64')});}
function signed(value:any=payload){return {...result,details:{...details,executorProof:proof(value)}};}

test('executor proof authenticates exact bytes while comparing object values independently of order',()=>{
 assert.equal(verifyExecutorResult(publicKey,'task-1','asset-1',signed()),true);
 const reordered={result:{details:{after:{mode:'0600'},before:{owners:['root','fixture'],mode:'0644'},path:'/fixture/config'},evidence:result.evidence,success:true},assetId:'asset-1',taskId:'task-1'};
 assert.equal(verifyExecutorResult(publicKey,'task-1','asset-1',signed(reordered)),true);
 assert.equal(verifyExecutorResult(publicKey,'task-1','asset-1',{success:false,evidence:'failed safely',details:{executorProof:proof({taskId:'task-1',assetId:'asset-1',result:{success:false,evidence:'failed safely',details:{}}})}}),true);
});

test('executor proof cannot be replayed or edited in any result field',()=>{
 const incoming=signed();
 assert.equal(verifyExecutorResult(publicKey,'different-task','asset-1',incoming),false);
 assert.equal(verifyExecutorResult(publicKey,'task-1','different-asset',incoming),false);
 assert.equal(verifyExecutorResult(publicKey,'task-1','asset-1',{...incoming,success:false}),false);
 assert.equal(verifyExecutorResult(publicKey,'task-1','asset-1',{...incoming,evidence:'forged'}),false);
 assert.equal(verifyExecutorResult(publicKey,'task-1','asset-1',{...incoming,details:{...incoming.details,before:{mode:'0600',owners:['fixture','root']}}}),false);
 const envelope=JSON.parse(incoming.details.executorProof);const bytes=Buffer.from(envelope.payload,'base64');bytes[0]^=1;
 assert.equal(verifyExecutorResult(publicKey,'task-1','asset-1',{...incoming,details:{...incoming.details,executorProof:JSON.stringify({...envelope,payload:bytes.toString('base64')})}}),false);
 const other=generateKeyPairSync('ed25519');const otherKey=other.publicKey.export({format:'der',type:'spki'}).subarray(-32).toString('base64');
 assert.equal(verifyExecutorResult(otherKey,'task-1','asset-1',incoming),false);
});

test('executor proof rejects malformed, noncanonical, oversized and unexpected structures without throwing',()=>{
 const valid=signed();
 for(const key of ['',publicKey+'\n',Buffer.alloc(31).toString('base64'),'bad-key'])assert.equal(verifyExecutorResult(key,'task-1','asset-1',valid),false);
 assert.equal(verifyExecutorResult(publicKey,'task-1','asset-1',{success:true,evidence:result.evidence}),false);
 for(const invalid of ['{','null','[]','{}',JSON.stringify({payload:'',signature:''}),JSON.stringify({payload:'ab==',signature:Buffer.alloc(64).toString('base64')}),JSON.stringify({...JSON.parse(valid.details.executorProof),extra:true}),JSON.stringify({...JSON.parse(valid.details.executorProof),signature:Buffer.alloc(63).toString('base64')})]){
  assert.equal(verifyExecutorResult(publicKey,'task-1','asset-1',{...valid,details:{...valid.details,executorProof:invalid}}),false);
 }
 for(const malformed of [{...payload,extra:true},{...payload,result:{...result,extra:true}},{...payload,result:{success:'true',evidence:result.evidence,details}},{...payload,result:{success:true,evidence:result.evidence}},{...payload,result:{...result,details:[]}}])assert.equal(verifyExecutorResult(publicKey,'task-1','asset-1',signed(malformed)),false);
 const large={taskId:'task-1',assetId:'asset-1',result:{success:true,evidence:'x'.repeat(65536),details:{}}};
 assert.equal(verifyExecutorResult(publicKey,'task-1','asset-1',{...large.result,details:{executorProof:proof(large)}}),false);
});
