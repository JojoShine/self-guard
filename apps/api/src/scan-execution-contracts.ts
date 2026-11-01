import {z} from 'zod';

const uniqueIds=(maximum:number)=>z.array(z.string().uuid()).max(maximum).refine(ids=>new Set(ids).size===ids.length,'选项不能重复').transform(ids=>[...ids].sort());
export const executionScopeInput=z.object({allAuthorized:z.boolean().default(false),assetIds:uniqueIds(1000).default([]),businessIds:uniqueIds(200).default([])}).strict().refine(scope=>scope.allAuthorized?!scope.assetIds.length&&!scope.businessIds.length:scope.assetIds.length+scope.businessIds.length>0,'请选择明确的资产或业务；全部范围需要单独明确选择');
export const executionIdentityInput=z.object({name:z.string().trim().min(1).max(200),scope:executionScopeInput,enabled:z.boolean().optional()}).strict();
export const frozenExecutionIdentity=z.object({id:z.string().uuid(),name:z.string().min(1).max(200),version:z.number().int().positive(),scope:executionScopeInput,approvedBy:z.string().uuid(),approvedAt:z.string().datetime({offset:true})}).strict();
export type FrozenExecutionIdentity=z.infer<typeof frozenExecutionIdentity>;
export function freezeExecutionIdentity(row:any):FrozenExecutionIdentity{return frozenExecutionIdentity.parse({id:row.id,name:row.name,version:row.version,scope:row.scope,approvedBy:row.approvedBy,approvedAt:new Date(row.approvedAt).toISOString()})}
export function executionScopeAllows(scope:z.infer<typeof executionScopeInput>,asset:{id:string},businessId?:string|null){return scope.allAuthorized||scope.assetIds.includes(asset.id)||!!businessId&&scope.businessIds.includes(businessId)}
export function intersectExecutionScope<T extends {id:string;businessId?:string|null}>(resolved:{selected:T[];skipped:Array<{id:string;reason:string}>;checkedAt:string},identity:FrozenExecutionIdentity|null){
 if(!identity)return resolved;
 const allowed=(asset:T)=>executionScopeAllows(identity.scope,asset,asset.businessId);
 return {...resolved,selected:resolved.selected.filter(allowed),skipped:[...resolved.skipped,...resolved.selected.filter(asset=>!allowed(asset)).map(asset=>({id:asset.id,reason:'EXECUTION_IDENTITY_SCOPE'}))]};
}
