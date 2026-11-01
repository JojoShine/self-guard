import {test} from 'node:test';
import assert from 'node:assert/strict';
import {randomBytes} from 'node:crypto';

test('HTTP record choices expose necessary identities and enforce actual account scope',{skip:!process.env.TEST_API_URL},async()=>{
 const database=new URL(process.env.DATABASE_URL!);assert.match(database.searchParams.get('schema')||'',/^http_acceptance_[a-f0-9]{24}$/,'HTTP fixture must use its owned acceptance schema');
 const suffix=randomBytes(6).toString('hex'),base=process.env.TEST_API_URL!,business='Choice HTTP '+suffix,privateBusiness='Private HTTP '+suffix;let token='';
 async function call(path:string,body?:unknown,method=body?'POST':'GET',credential=token){const response=await fetch(base+path,{method,headers:{'content-type':'application/json',...(credential?{authorization:'Bearer '+credential}:{})},...(body?{body:JSON.stringify(body)}:{})});return {status:response.status,data:await response.json()}}
 assert.equal((await call('/record-options/assets')).status,401);
 const login=await call('/auth/login',{email:process.env.ADMIN_EMAIL||'admin@selfguard.local',password:process.env.ADMIN_PASSWORD});assert.equal(login.status,200);token=login.data.token;
 const group=await call('/record-options/businesses',{name:business});assert.equal(group.status,201);assert.equal(group.data.id,business);assert.ok(group.data.stableId);
 const same=await call('/record-options/businesses',{name:' '+business+' '});assert.equal(same.data.stableId,group.data.stableId);
 const publicAsset=await call('/assets',{hostname:'HTTP authorized '+suffix,os:'linux',business}),privateAsset=await call('/assets',{hostname:'HTTP private '+suffix,os:'linux',business:privateBusiness});assert.equal(publicAsset.status,201);assert.equal(privateAsset.status,201);
 const email='record-options-http-'+suffix+'@fixture.test',password='Owned-http-choice-123!';
 assert.equal((await call('/users',{email,name:'Scoped choice operator',password,role:'ANALYST',dataScope:{restricted:true,businesses:[business],assetIds:[],canReadEvidence:false}})).status,201);
 const scoped=await call('/auth/login',{email,password});assert.equal(scoped.status,200);
 const choices=await call('/record-options/assets?q='+suffix,undefined,'GET',scoped.data.token);assert.equal(choices.status,200);assert.equal(choices.data.total,1);assert.equal(choices.data.items[0].id,publicAsset.data.id);assert.deepEqual(Object.keys(choices.data.items[0]).sort(),['archivedAt','business','hostname','id','ip']);
 const hidden=await call('/record-options/assets?selected='+privateAsset.data.id,undefined,'GET',scoped.data.token);assert.equal(hidden.status,200);assert.equal(hidden.data.total,0);
 const groups=await call('/record-options/businesses?q='+suffix,undefined,'GET',scoped.data.token);assert.equal(groups.status,200);assert.deepEqual(groups.data.items.map((row:any)=>row.id),[business]);
 assert.equal((await call('/record-options/businesses?selected='+encodeURIComponent(privateBusiness),undefined,'GET',scoped.data.token)).data.total,0);
 assert.equal((await call('/record-options/businesses',{name:'Denied '+suffix},'POST',scoped.data.token)).status,403);
 assert.equal((await call('/record-options/sites',undefined,'GET',scoped.data.token)).status,403);
 assert.equal((await call('/record-options/assets?selected=invalid')).status,400);assert.equal((await call('/record-options/users')).status,400);
});
