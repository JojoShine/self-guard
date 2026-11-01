import test from 'node:test';
import assert from 'node:assert/strict';
import { assetScope, evidenceAllowed, redactEvidence, restricted } from '../src/scope';
test('asset scope uses union of explicit assets and business grants and fails closed when empty',()=>{
 const user={role:'ANALYST',dataScope:{restricted:true,businesses:['payments'],assetIds:['one'],canReadEvidence:false}};
 assert.deepEqual(assetScope(user),{OR:[{business:{in:['payments']}},{id:{in:['one']}}]});
 assert.deepEqual(assetScope({role:'VIEWER',dataScope:{restricted:true}}),{OR:[{business:{in:[]}},{id:{in:[]}}]});
 assert.equal(restricted({role:'ADMIN',dataScope:user.dataScope}),false);
 assert.deepEqual(assetScope({role:'ADMIN'}),{});
});
test('evidence grants are independent of asset visibility and redact nested evidence payloads',()=>{
 const user={role:'VIEWER',dataScope:{canReadEvidence:false}};
 assert.equal(evidenceAllowed(user),false);
 assert.equal(evidenceAllowed({role:'ADMIN',dataScope:user.dataScope}),true);
 assert.deepEqual(redactEvidence(user,{items:[{id:'x',evidence:'secret',parameters:{value:'secret'},inventory:{secret:true},inspection:{evidence:'secret',siteHostname:'private.test'},reason:'secret'}]}),{items:[{id:'x',evidence:'[已隐藏]',parameters:'[已隐藏]',inventory:'[已隐藏]',inspection:'[已隐藏]',reason:'[已隐藏]'}]});
});
