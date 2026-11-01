import {test} from 'node:test';
import assert from 'node:assert/strict';
import {generateKeyPairSync,verify} from 'node:crypto';
import {authorizeTask} from '../src/task-signing';

test('Ed25519 task authorization signs exact bytes, binds parameters and bounds validity',()=>{
 const previous=process.env.TASK_SIGNING_PRIVATE_KEY;
 const {privateKey,publicKey}=generateKeyPairSync('ed25519');
 const encoded=privateKey.export({format:'der',type:'pkcs8'}).toString('base64');
 try {
  delete process.env.TASK_SIGNING_PRIVATE_KEY;
  const now=Date.now();
  const task={id:'task-id',assetId:'asset-id',template:'CONFIG_VALUE',parameters:{path:'/fixture/config',key:'FEATURE',value:'yes',expectedValue:'no'},expiresAt:new Date(now+3600000)};
  assert.equal(authorizeTask(task),undefined);
  process.env.TASK_SIGNING_PRIVATE_KEY=encoded;
  const signed=authorizeTask(task)!;
  assert.deepEqual(Object.keys(signed).sort(),['payload','signature']);
  const payload=Buffer.from(signed.payload,'base64');
  assert.equal(verify(null,payload,publicKey,Buffer.from(signed.signature,'base64')),true);
  const data=JSON.parse(payload.toString('utf8'));
  assert.deepEqual(Object.keys(data),['id','assetId','template','parameters','expiresAt']);
  assert.equal(data.id,task.id);assert.equal(data.assetId,task.assetId);assert.equal(data.template,task.template);assert.deepEqual(data.parameters,task.parameters);
  const expires=Date.parse(data.expiresAt);
  assert.ok(expires>=now+5*60000&&expires<=Date.now()+5*60000);
  assert.ok(!JSON.stringify(signed).includes(encoded));
  const tampered=Buffer.from(JSON.stringify({...data,parameters:{...data.parameters,value:'malicious'}}));
  assert.equal(verify(null,tampered,publicKey,Buffer.from(signed.signature,'base64')),false);
  const assetTampered=Buffer.from(JSON.stringify({...data,assetId:'different-asset'}));
  assert.equal(verify(null,assetTampered,publicKey,Buffer.from(signed.signature,'base64')),false);
  const shortExpiry=new Date(Date.now()+60000);
  assert.equal(JSON.parse(Buffer.from(authorizeTask({...task,expiresAt:shortExpiry})!.payload,'base64').toString()).expiresAt,shortExpiry.toISOString());
  const windowEnd=new Date(Date.now()+30000);
  assert.equal(JSON.parse(Buffer.from(authorizeTask({...task,windowEnd})!.payload,'base64').toString()).expiresAt,windowEnd.toISOString());
  process.env.TASK_SIGNING_PRIVATE_KEY='not-a-valid-key';
  assert.throws(()=>authorizeTask(task));
  process.env.TASK_SIGNING_PRIVATE_KEY='';assert.equal(authorizeTask(task),undefined);
  const rsa=generateKeyPairSync('rsa',{modulusLength:2048});
  process.env.TASK_SIGNING_PRIVATE_KEY=rsa.privateKey.export({format:'der',type:'pkcs8'}).toString('base64');
  assert.throws(()=>authorizeTask(task));
 }finally{if(previous===undefined)delete process.env.TASK_SIGNING_PRIVATE_KEY;else process.env.TASK_SIGNING_PRIVATE_KEY=previous;}
});
