import {test} from 'node:test';import assert from 'node:assert/strict';
import {InstallationService} from '../src/installations';

test('installation choices expose only existing authorized business names without evidence privileges',async()=>{
 let query:any;
 const svc=new InstallationService({businessGroup:{findMany:async(input:any)=>{query=input;return [{name:'payments'}]}}} as any);
 assert.deepEqual(await svc.installationOptions({role:'OPERATOR',dataScope:{restricted:true,canReadEvidence:false,businesses:['payments']}}),{businesses:[{name:'payments'}],requiresBusiness:true});
 assert.deepEqual(query.where,{name:{in:['payments']}});assert.deepEqual(query.select,{name:true});
 await svc.installationOptions({role:'ADMIN',dataScope:{restricted:true,businesses:[]}});assert.deepEqual(query.where,{});
 await svc.installationOptions({role:'OPERATOR',dataScope:{restricted:true,assetIds:['asset-only']}});assert.deepEqual(query.where,{name:{in:[]}});
 await assert.rejects(()=>svc.installationOptions({role:'VIEWER'}));
});
