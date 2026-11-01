import {test} from 'node:test';
import assert from 'node:assert/strict';
import {PlatformController} from '../src/controllers';

const req={user:{role:'ADMIN'}};
test('WAF node lists apply pagination, search, heartbeat bounds and a stable order',async()=>{
 let options:any,where:any;
 const controller=new PlatformController({db:{wafNode:{findMany:async(v:any)=>{options=v;return [{id:'node-16'}];},count:async(v:any)=>{where=v.where;return 31;}}}} as any);
 const result=await controller.nodes({page:'2',pageSize:'15',q:'edge',sortBy:'lastSeen',order:'desc',createdFrom:'2026-10-01T00:00:00Z'},req);
 assert.deepEqual(result,{items:[{id:'node-16'}],total:31});
 assert.equal(options.take,15);assert.equal(options.skip,15);
 assert.deepEqual(options.orderBy,[{lastSeen:'desc'},{id:'asc'}]);
 assert.deepEqual(where,options.where);assert.equal(where.OR[0].id.contains,'edge');
 assert.equal(where.lastSeen.gte.toISOString(),'2026-10-01T00:00:00.000Z');
});
test('WAF access lists apply search, time filters and stable paging',async()=>{
 let options:any;
 const controller=new PlatformController({db:{wafAccess:{findMany:async(v:any)=>{options=v;return [];},count:async()=>0}}} as any);
 assert.deepEqual(await controller.access({page:'2',pageSize:'30',q:'403',nodeId:'edge',sortBy:'timestamp',order:'asc',createdTo:'2026-10-31T23:59:59Z'},req).then(({items,total})=>({items,total})),{items:[],total:0});
 assert.equal(options.skip,30);assert.equal(options.take,30);
 assert.deepEqual(options.orderBy,[{timestamp:'asc'},{id:'asc'}]);
 assert.equal(options.where.nodeId,'edge');assert.ok(options.where.OR.some((condition:any)=>condition.status===403));
 assert.equal(options.where.timestamp.lte.toISOString(),'2026-10-31T23:59:59.000Z');
});
