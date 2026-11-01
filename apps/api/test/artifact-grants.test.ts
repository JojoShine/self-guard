import {test} from 'node:test';import assert from 'node:assert/strict';import {generateKeyPairSync,sign} from 'node:crypto';import {verifyDownloadGrant} from '../src/artifact-grants';
test('artifact download grants are short-lived, purpose separated and bound to target, asset and exact release',()=>{
 const key=generateKeyPairSync('ed25519'),publicKey=key.publicKey.export({format:'der',type:'spki'}).subarray(-32).toString('base64'),now=new Date();
 const expected={id:'target',assetId:'asset',releaseId:'release',sha256:'a'.repeat(64)};
 const payload={id:expected.id,assetId:expected.assetId,template:'DOWNLOAD_AGENT_RELEASE',parameters:{releaseId:expected.releaseId,sha256:expected.sha256},expiresAt:new Date(now.getTime()+60000).toISOString()};
 const envelope=(value:any)=>{const raw=Buffer.from(JSON.stringify(value));return {payload:raw.toString('base64'),signature:sign(null,raw,key.privateKey).toString('base64')};};
 assert.equal(verifyDownloadGrant(envelope(payload),expected,publicKey,now),true);
 for(const change of [{id:'other'},{assetId:'other'},{releaseId:'other'},{sha256:'b'.repeat(64)}])assert.equal(verifyDownloadGrant(envelope(payload),{...expected,...change},publicKey,now),false);
 for(const change of [{template:'UPGRADE'},{expiresAt:new Date(now.getTime()-1).toISOString()},{expiresAt:new Date(now.getTime()+600001).toISOString()}])assert.equal(verifyDownloadGrant(envelope({...payload,...change}),expected,publicKey,now),false);
 assert.equal(verifyDownloadGrant({...envelope(payload),signature:Buffer.alloc(64).toString('base64')},expected,publicKey,now),false);
});
