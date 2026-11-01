import {test} from 'node:test';
import assert from 'node:assert/strict';
import {executionOwner} from '../src/scan-authorization';

const user={id:'10000000-0000-4000-8000-000000000010',role:'ADMIN',disabled:false};
const identity={id:'10000000-0000-4000-8000-000000000020',name:'受控测试执行身份',version:3,enabled:true,scope:{allAuthorized:false,assetIds:['10000000-0000-4000-8000-000000000030'],businessIds:[]},approvedBy:'10000000-0000-4000-8000-000000000010',approvedAt:new Date('2026-11-01T00:00:00Z')};
const plan={creatorId:user.id,executionIdentityId:identity.id,executionIdentityVersion:3};
function fixture(row:any=identity){return {user:{findUnique:async()=>user},scanExecutionIdentity:{findUnique:async()=>row}}}

test('legacy owner execution keeps its previous authorization and does not request an identity',async()=>{
 assert.equal(await executionOwner({user:{findUnique:async()=>user}},{creatorId:user.id}),user);
 await assert.rejects(()=>executionOwner({user:{findUnique:async()=>({...user,disabled:true})}},{creatorId:user.id}),/负责人/);
});
test('disabled, missing or changed execution identity rejects an otherwise authorized owner',async()=>{
 await assert.rejects(()=>executionOwner(fixture(null),plan),/身份|授权/);
 await assert.rejects(()=>executionOwner(fixture({...identity,enabled:false}),plan),/身份|授权/);
 await assert.rejects(()=>executionOwner(fixture({...identity,version:4}),plan),/身份|授权/);
 await assert.rejects(()=>executionOwner(fixture(),{...plan,executionIdentityVersion:null}),/身份|授权/);
});
test('re-enabling an identity does not revive a plan bound to its former grant',async()=>{
 await assert.rejects(()=>executionOwner(fixture({...identity,enabled:true,version:5}),plan),/身份|授权/);
 assert.equal(await executionOwner(fixture({...identity,version:5}),{...plan,executionIdentityVersion:5}),user);
});
test('run execution cannot replace its frozen identity with another current binding',async()=>{
 const frozen={id:identity.id,name:identity.name,version:3,scope:identity.scope,approvedBy:identity.approvedBy,approvedAt:identity.approvedAt.toISOString()};
 assert.equal(await executionOwner(fixture(),plan,{executionIdentity:frozen}),user);
 for(const value of [null,{...frozen,id:'other-identity'},{...frozen,version:2},{...frozen,scope:{allAuthorized:true,assetIds:[],businessIds:[]}}])await assert.rejects(()=>executionOwner(fixture(),plan,{executionIdentity:value}),/身份|授权/);
 await assert.rejects(()=>executionOwner(fixture(),{creatorId:user.id},{executionIdentity:frozen}),/身份|授权/);
});
