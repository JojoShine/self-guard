import {z} from 'zod';
import {databaseObjectInput} from './database-contract';

const name=z.string().trim().min(1).max(128);
export const postgresRelationInput=z.object({database:name,relationOid:z.number().int().min(1).max(4294967295),attributeNumber:z.number().int().min(1).max(32767)}).strict();
const httpMapping=z.object({kind:z.literal('HTTP_ROUTE'),route:z.string().startsWith('/').max(2048).refine(v=>!/[?#\r\n\0]/.test(v)),methods:z.array(z.enum(['GET','HEAD','POST','PUT','PATCH','DELETE','OPTIONS'])).max(7).default([]),objects:z.array(databaseObjectInput).min(1).max(32)}).strict();
const postgresMapping=postgresRelationInput.extend({kind:z.literal('POSTGRES_COLUMN'),schema:name,table:name,column:name,observedAt:z.string().datetime({offset:true})}).strict();
export const accessObjectMappingsInput=z.array(z.discriminatedUnion('kind',[httpMapping,postgresMapping])).max(512).refine(rows=>{
 const keys=rows.filter(r=>r.kind==='POSTGRES_COLUMN').map(r=>JSON.stringify([r.database,r.relationOid,r.attributeNumber]));return new Set(keys).size===keys.length;
},'同一数据库的对象编号与字段序号不能重复关联');
export type AccessObjectMapping=z.infer<typeof accessObjectMappingsInput>[number];
type ObjectReference=z.infer<typeof databaseObjectInput>;
type ObjectEvent={operation:string;route?:string;database?:string;startedAt:string;objects:ObjectReference[];relations?:z.infer<typeof postgresRelationInput>[]};
export function resolveAccessObjects(protocol:string,event:ObjectEvent,mappings:AccessObjectMapping[]){
 let objects=protocol==='HTTP'?[]:[...event.objects],basis='OBSERVED_PROTOCOL',unresolved=0,stale=false;
 if(protocol==='HTTP'){
  basis='REGISTERED_HTTP_ROUTE';objects=mappings.flatMap(m=>m.kind==='HTTP_ROUTE'&&m.route===event.route&&(!m.methods.length||m.methods.some(method=>method===event.operation))?m.objects:[]);
 }
 if(protocol==='POSTGRESQL'&&event.relations?.length){
  basis='POSTGRES_METADATA';
  for(const reference of event.relations){
   const match=mappings.find(m=>m.kind==='POSTGRES_COLUMN'&&m.database===reference.database&&m.relationOid===reference.relationOid&&m.attributeNumber===reference.attributeNumber);
   if(!match||match.kind!=='POSTGRES_COLUMN'||(event.database&&event.database!==reference.database)){unresolved++;continue}
   const age=Date.parse(event.startedAt)-Date.parse(match.observedAt);
   if(age<0||age>=86400000){unresolved++;stale=true;continue}
   objects.push({database:match.database,schema:match.schema,table:match.table,columns:[match.column]});
  }
 }
 const merged=new Map<string,ObjectReference>();
 for(const object of objects){const key=JSON.stringify([object.database,object.schema||'',object.table||'']);const prior=merged.get(key);if(prior){const columns=[...new Set([...prior.columns,...object.columns])];if(columns.length>128)unresolved++;prior.columns=columns.slice(0,128)}else if(merged.size<32)merged.set(key,{...object,columns:[...object.columns]});else unresolved++;}
 objects=[...merged.values()];
 return {objects,basis,status:objects.length?(unresolved?'PARTIAL':'RESOLVED'):(stale?'STALE':'UNRESOLVED'),unresolved};
}
