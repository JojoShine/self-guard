import {test} from 'node:test';import assert from 'node:assert/strict';
import {accessObjectMappingsInput,resolveAccessObjects} from '../src/access-classification';
const at='2026-11-06T08:00:00.000Z';
test('HTTP classifications require an exact registered route and method and remain declared evidence',()=>{
 const mappings=accessObjectMappingsInput.parse([{kind:'HTTP_ROUTE',route:'/customers/export',methods:['GET'],objects:[{database:'crm',table:'customers',columns:['phone']}]}]);
 const result=resolveAccessObjects('HTTP',{route:'/customers/export',operation:'GET',objects:[],startedAt:at},mappings);
 assert.equal(result.objects[0].table,'customers');assert.equal(result.basis,'REGISTERED_HTTP_ROUTE');
 for(const event of [{route:'/customers/exported',operation:'GET'},{route:'/customers/export',operation:'POST'}])assert.equal(resolveAccessObjects('HTTP',{...event,objects:[],startedAt:at},mappings).objects.length,0);
});
test('PostgreSQL metadata matches database, relation and attribute exactly and expires after 24 hours',()=>{
 const mappings=accessObjectMappingsInput.parse([{kind:'POSTGRES_COLUMN',database:'crm',relationOid:123,attributeNumber:2,schema:'public',table:'customers',column:'phone',observedAt:'2026-11-06T07:00:00.000Z'}]);
 const event={operation:'SELECT',database:'crm',objects:[],startedAt:at,relations:[{database:'crm',relationOid:123,attributeNumber:2}]};
 assert.equal(resolveAccessObjects('POSTGRESQL',event,mappings).objects[0].columns[0],'phone');
 for(const relations of [[{database:'other',relationOid:123,attributeNumber:2}],[{database:'crm',relationOid:123,attributeNumber:3}]])assert.equal(resolveAccessObjects('POSTGRESQL',{...event,relations},mappings).objects.length,0);
 assert.equal(resolveAccessObjects('POSTGRESQL',{...event,startedAt:'2026-11-07T07:00:00.000Z'},mappings).status,'STALE');
 assert.equal(resolveAccessObjects('POSTGRESQL',{...event,startedAt:'2026-11-06T06:00:00.000Z'},mappings).objects.length,0);
});
test('unresolved PostgreSQL references stay partial alongside a resolved object',()=>{
 const mappings=accessObjectMappingsInput.parse([{kind:'POSTGRES_COLUMN',database:'crm',relationOid:123,attributeNumber:2,schema:'public',table:'customers',column:'phone',observedAt:'2026-11-06T07:00:00.000Z'}]);
 const r=resolveAccessObjects('POSTGRESQL',{operation:'SELECT',startedAt:at,objects:[],relations:[{database:'crm',relationOid:123,attributeNumber:2},{database:'crm',relationOid:456,attributeNumber:1}]},mappings);assert.equal(r.status,'PARTIAL');assert.equal(r.unresolved,1);
});
test('metadata rejects ambiguous references and query strings in route indexes',()=>{
 const row={kind:'POSTGRES_COLUMN',database:'crm',relationOid:123,attributeNumber:2,schema:'public',table:'customers',column:'phone',observedAt:at};
 assert.equal(accessObjectMappingsInput.safeParse([row,{...row,column:'email'}]).success,false);
 assert.equal(accessObjectMappingsInput.safeParse([{kind:'HTTP_ROUTE',route:'/customers?token=secret',methods:[],objects:[{database:'crm'}]}]).success,false);
});
