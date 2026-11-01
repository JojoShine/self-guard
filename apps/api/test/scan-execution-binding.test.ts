import {test} from 'node:test';import assert from 'node:assert/strict';
import {bindExecutionIdentity,executionBindingValid} from '../src/scan-execution-identities';
const id='10000000-0000-4000-8000-000000000020',admin={id:'10000000-0000-4000-8000-000000000010',role:'ADMIN'},analyst={role:'ANALYST'};
const row={id,name:'受控身份',version:5,enabled:true,scope:{allAuthorized:true,assetIds:[],businessIds:[]},approvedBy:admin.id,approvedAt:new Date('2026-11-01T00:00:00Z')};
const previous={executionIdentityId:id,executionIdentityVersion:3},db={$queryRaw:async()=>[],user:{findUnique:async()=>admin},scanExecutionIdentity:{findUnique:async()=>row}};
test('ordinary edits preserve old binding; renewal and removal require explicit administrator action',async()=>{
 assert.deepEqual(await bindExecutionIdentity(db,admin,undefined,previous),previous);
 assert.deepEqual(await bindExecutionIdentity(db,analyst,undefined,previous),previous);
 await assert.rejects(()=>bindExecutionIdentity(db,analyst,id,previous),/管理员/);
 await assert.rejects(()=>bindExecutionIdentity(db,analyst,null,previous),/管理员/);
 assert.deepEqual(await bindExecutionIdentity(db,admin,id,previous,5),{executionIdentityId:id,executionIdentityVersion:5});
 await assert.rejects(()=>bindExecutionIdentity(db,admin,id,previous,3),/授权版本已变化/);
 await assert.rejects(()=>bindExecutionIdentity(db,admin,id,previous),/授权版本已变化/);
 assert.deepEqual(await bindExecutionIdentity(db,admin,null,previous),{executionIdentityId:null,executionIdentityVersion:null});
 await assert.rejects(()=>bindExecutionIdentity({...db,scanExecutionIdentity:{findUnique:async()=>({...row,enabled:false})}},admin,id),/启用/);
 await assert.rejects(()=>bindExecutionIdentity({...db,user:{findUnique:async()=>({...admin,disabled:true})}},admin,id),/授权已变化/);
});
test('list validity distinguishes an enabled grant from a stale plan binding',()=>{
 assert.equal(executionBindingValid({}),true);
 assert.equal(executionBindingValid({...previous,executionIdentity:row}),false);
 assert.equal(executionBindingValid({...previous,executionIdentityVersion:5,executionIdentity:row}),true);
 assert.equal(executionBindingValid({...previous,executionIdentityVersion:5,executionIdentity:{...row,enabled:false}}),false);
});
