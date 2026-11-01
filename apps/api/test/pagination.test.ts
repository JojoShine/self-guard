import {test} from 'node:test';import assert from 'node:assert/strict';import {randomUUID} from 'node:crypto';import {Db} from '../src/db';import {Platform} from '../src/platform';
import {GovernanceController} from '../src/governance';
import {AssetHistoryController} from '../src/asset-history';

test('notification pagination uses an id tie-breaker for equal creation timestamps',async()=>{
 let options:any;
 const db={notification:{findMany:async(value:any)=>{options=value;return [];},count:async()=>0}};
 const controller=new GovernanceController(db as any,{} as any);
 await controller.notifications({user:{id:'reader',role:'ADMIN'}},{page:'2',pageSize:'15'});
 assert.deepEqual(options.orderBy,[{createdAt:'desc'},{id:'desc'}]);
 assert.equal(options.skip,15);assert.equal(options.take,15);
});
test('asset history pagination uses an id tie-breaker for equal creation timestamps',async()=>{
 let options:any;const id='11111111-1111-4111-8111-111111111111';
 const db={asset:{findFirst:async()=>({id})},assetChange:{findMany:async(value:any)=>{options=value;return [];},count:async()=>0}};
 await new AssetHistoryController(db as any).list({assetId:id,page:'2',pageSize:'30'},{user:{role:'ADMIN'}});
 assert.deepEqual(options.orderBy,[{createdAt:'desc'},{id:'desc'}]);
 assert.equal(options.skip,30);assert.equal(options.take,30);
});
test('all-asset detection traverses beyond first 1000 targets',{skip:!process.env.TEST_API_URL},async()=>{
 const db=new Db(),p=new Platform(db);const ids=Array.from({length:1001},()=>randomUUID());let ruleId='';
 try{
  await db.asset.createMany({data:ids.map(id=>({id,hostname:'pagination-fixture-'+id,os:'test-no-match',inventory:{packages:[]}}))});
  const rule=await db.rule.create({data:{name:'pagination fixture',kind:'VULNERABILITY',severity:'LOW',config:{package:'fixture',affectedVersion:'1',os:'test-no-match',advisory:'test only'}}});ruleId=rule.id;
  await p.runRule(rule.id,{},'test');
  assert.equal(await db.evaluation.count({where:{ruleId:rule.id,assetId:{in:ids}}}),1001);
 }finally{
  if(ruleId){await db.evaluation.deleteMany({where:{ruleId}});await db.rule.delete({where:{id:ruleId}});}
  await db.asset.deleteMany({where:{id:{in:ids}}});await db.$disconnect();
 }
});
