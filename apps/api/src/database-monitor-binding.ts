import {ConflictException} from '@nestjs/common';
import {Prisma} from '@prisma/client';
import {createHash} from 'node:crypto';
import {z} from 'zod';
import {instanceInput} from './database-instances';
import {databaseAuditSourceFormats} from './database-capabilities';
const bindingInput=z.object({instanceId:z.string().uuid(),assetId:z.string().uuid(),sourcePath:z.string().startsWith('/').max(4096),format:z.enum(databaseAuditSourceFormats),mode:z.literal('INDEPENDENT')}).strict();
type Source=z.infer<typeof instanceInput.shape.auditSources>[number];
export function independentBinding(instanceId:string,source:Source){
 const value=bindingInput.parse({instanceId,assetId:source.assetId,sourcePath:source.path,format:source.format,mode:'INDEPENDENT'});
 return{key:'database-monitor-binding:'+source.assetId+':'+createHash('sha256').update(instanceId+source.path).digest('hex'),value};
}
export function baseAgentDatabaseSources(assetId:string,instances:{id:string;engine:string;auditSources:unknown}[],bindings:{key:string;value:unknown}[]){
 const independent=new Set<string>();
 for(const row of bindings){const parsed=bindingInput.safeParse(row.value);if(!parsed.success||parsed.data.assetId!==assetId)continue;const v=parsed.data,expected=independentBinding(v.instanceId,{assetId:v.assetId,path:v.sourcePath,format:v.format});if(row.key===expected.key)independent.add(JSON.stringify([v.instanceId,v.assetId,v.sourcePath,v.format]));}
 return instances.flatMap(instance=>z.array(z.object({assetId:z.string(),path:z.string(),format:z.string()})).parse(instance.auditSources).filter(source=>source.assetId===assetId&&!independent.has(JSON.stringify([instance.id,source.assetId,source.path,source.format]))).map(source=>({instanceId:instance.id,engine:instance.engine,path:source.path,service:source.format})));
}
// The caller owns the identity/version-checked transaction: source and ownership must commit together.
export async function bindIndependentDatabaseSource(tx:Pick<Prisma.TransactionClient,'databaseInstance'|'setting'>,instance:{id:string;updatedAt:Date;auditSources:unknown},bound:Source){
 const sources=instanceInput.shape.auditSources.parse(instance.auditSources);
 if(sources.some(s=>s.assetId===bound.assetId&&s.path===bound.path&&s.format!==bound.format))throw new ConflictException();
 if(!sources.some(s=>s.assetId===bound.assetId&&s.path===bound.path&&s.format===bound.format))sources.push(bound);
 if(sources.length>20)throw new ConflictException();
 const changed=await tx.databaseInstance.updateMany({where:{id:instance.id,updatedAt:instance.updatedAt,archivedAt:null},data:{auditSources:sources}});
 if(!changed.count)throw new ConflictException();
 const binding=independentBinding(instance.id,bound);await tx.setting.upsert({where:{key:binding.key},create:binding,update:{value:binding.value}});
}
