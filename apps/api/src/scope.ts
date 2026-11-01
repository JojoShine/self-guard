import { map } from 'rxjs/operators';
import { Injectable, NestInterceptor, ExecutionContext, CallHandler, ForbiddenException, NotFoundException } from '@nestjs/common';
import { Prisma } from '@prisma/client';
import { z } from 'zod';

export const dataScopeInput = z.object({
  restricted: z.boolean().default(false),
  businesses: z.array(z.string().trim().min(1).max(200)).max(200).default([]),
  assetIds: z.array(z.string().uuid()).max(1000).default([]),
  canReadEvidence: z.boolean().default(true),
}).strict();
export function restricted(user: any) { return user?.role !== 'ADMIN' && user?.dataScope?.restricted === true; }
export function evidenceAllowed(user: any) { return user?.role === 'ADMIN' || user?.dataScope?.canReadEvidence !== false; }
export function assertEvidence(user: any) { if (!evidenceAllowed(user)) throw new ForbiddenException('没有读取证据的权限'); }
export function assertGlobal(user: any) { if (restricted(user)) throw new ForbiddenException('此操作需要完整数据范围'); }
export function assetScope(user: any): any {
  if (!restricted(user)) return {};
  return { OR: [{ business: { in: user.dataScope.businesses || [] } }, { id: { in: user.dataScope.assetIds || [] } }] };
}
const delegates: Record<string, string> = { assets:'asset', findings:'finding', tasks:'task', incidents:'incident', evaluations:'evaluation', sites:'site', rules:'rule', 'waf-events':'wafEvent', batches:'taskBatch' };
// Every linked asset/task must be visible; an incident with no asset context is organization-wide.
export async function resourceWhere(db: any, user: any, resource: string): Promise<any> {
  if (!restricted(user)) return {};
  const assets = assetScope(user);
  if (resource === 'assets') return assets;
  if (resource === 'findings' || resource === 'tasks') return { asset: { is: assets } };
  if (resource === 'rules') return {};
  if (resource === 'evaluations') {
    const ids = await db.asset.findMany({where:assets,select:{id:true}});
    return {assetId:{in:ids.map((a:any)=>a.id)}};
  }
  if (resource === 'incidents' || resource === 'batches') {
    const ids = (await db.asset.findMany({where:assets,select:{id:true}})).map((a:any)=>a.id);
    const taskIds = (await db.task.findMany({where:{assetId:{in:ids}},select:{id:true}})).map((t:any)=>t.id);
    if (resource === 'batches') {
      const rows = await db.$queryRaw(Prisma.sql`SELECT b.id FROM "TaskBatch" b WHERE EXISTS (SELECT 1 FROM "Task" t WHERE t."batchId"=b.id) AND NOT EXISTS (SELECT 1 FROM "Task" t WHERE t."batchId"=b.id AND NOT (t.id = ANY(${taskIds}::text[])))`);
      return {id:{in:rows.map((r:any)=>r.id)}};
    }
    const rows = await db.$queryRaw(Prisma.sql`SELECT i.id FROM "Incident" i WHERE i."assetIds" <@ ${ids}::text[] AND i."taskIds" <@ ${taskIds}::text[] AND (cardinality(i."assetIds")>0 OR cardinality(i."taskIds")>0 OR EXISTS (SELECT 1 FROM "IncidentFinding" l WHERE l."incidentId"=i.id))`);
    return {AND:[{id:{in:rows.map((r:any)=>r.id)}},{links:{every:{finding:{asset:{is:assets}}}}}]};
  }
  return {id:{in:[]}};
}
export async function assertScope(db: any, user: any, resource: string, id: string) {
  if (!delegates[resource]) { assertGlobal(user); return; }
  const found = await db[delegates[resource]].findFirst({where:{AND:[{id},await resourceWhere(db,user,resource)]},select:{id:true}});
  if (!found) throw new NotFoundException('记录不存在或不在授权范围');
}
export async function assertLinks(db: any, user: any, body: any) {
  if (!restricted(user) || !body || typeof body !== 'object') return;
  for (const [key,resource] of [['assetId','assets'],['findingId','findings'],['relatedRiskId','findings']] as const)
    if (body[key]) await assertScope(db,user,resource,body[key]);
  for (const [key,resource] of [['assetIds','assets'],['findingIds','findings'],['taskIds','tasks']] as const)
    for (const id of body[key] || []) await assertScope(db,user,resource,id);
}
const sensitive = new Set(['inspection','evidence','description','conclusion','verification','remainingRisks','reason','parameters','result','inventory','detail','body','data','config','path','remoteIp','message','fields','payload','headers']);
export function redactEvidence(user: any, value: any): any {
  if ((evidenceAllowed(user) && !restricted(user)) || value == null || typeof value !== 'object' || value instanceof Date) return value;
  if (Array.isArray(value)) return value.map(v=>redactEvidence(user,v));
  const ruleRecord = ['BASELINE','LOG','FIM','VULNERABILITY'].includes(value.kind) && value.config && typeof value.config === 'object';
  return Object.fromEntries(Object.entries(value).map(([key,v])=>{
    if (restricted(user) && ruleRecord && key === 'config') {
      const { applicability, exceptions, ...publicConfig } = v as any;
      return [key, redactEvidence(user, publicConfig)];
    }
    return [key,!evidenceAllowed(user)&&sensitive.has(key)&&v!=null?'[已隐藏]':redactEvidence(user,v)];
  }));
}

@Injectable()
export class ScopeResponseInterceptor implements NestInterceptor {
  intercept(context: ExecutionContext, next: CallHandler) {
    const user = context.switchToHttp().getRequest().user;
    return next.handle().pipe(map(value => redactEvidence(user, value)));
  }
}
