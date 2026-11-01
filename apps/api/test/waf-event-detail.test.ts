import {test} from 'node:test';
import assert from 'node:assert/strict';
import {Platform} from '../src/platform';

test('WAF event audit lookup accepts the original opaque event identifier without widening other filters',async()=>{
 let options:any;
 const db={audit:{findMany:async(value:any)=>{options=value;return [];},count:async()=>0}};
 const platform=new Platform(db as any),id='edge:request/7?part=a&part=b';
 await platform.list('audit',{resourceId:id},{role:'ADMIN'});
 assert.equal(options.where.resourceId,id);
 await assert.rejects(()=>platform.list('audit',{resourceId:'x'.repeat(501)},{role:'ADMIN'}));
 await assert.rejects(()=>platform.list('assets',{assetId:id},{role:'ADMIN'}));
 await platform.list('audit',{resourceId:id},{role:'ANALYST',dataScope:{restricted:true}});
 assert.deepEqual(options.where.id,{in:[]});
});
