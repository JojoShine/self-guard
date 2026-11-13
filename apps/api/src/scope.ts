import {instanceScope,assertInstanceScope} from './database-instances';
import { map } from 'rxjs/operators';
import { Injectable, NestInterceptor, ExecutionContext, CallHandler, ForbiddenException, NotFoundException } from '@nestjs/common';
import { Prisma } from '@prisma/client';
import { z } from 'zod';
import {isPublicReadOnlyUser} from './public-demo';

export const dataScopeInput = z.object({
  databaseInstanceIds: z.array(z.string().uuid()).max(1000).default([]),
  restricted: z.boolean().default(false),
  businesses: z.array(z.string().trim().min(1).max(200)).max(200).default([]),
  assetIds: z.array(z.string().uuid()).max(1000).default([]),
  canReadEvidence: z.boolean().default(true),
  canReadSqlEvidence: z.boolean().default(false),
  canReadAccessEvidence: z.boolean().default(false),
  canExportAccessEvidence: z.boolean().default(false),
}).strict();
export function restricted(user: any) { return user?.role !== 'ADMIN' && user?.dataScope?.restricted === true; }
export function evidenceAllowed(user: any) { return isPublicReadOnlyUser(user) || user?.role === 'ADMIN' || user?.dataScope?.canReadEvidence !== false; }
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
  if (resource === 'findings') return {OR:[{instanceId:null,asset:{is:assets}},{instance:{is:instanceScope(user)}}]};
  if (resource === 'tasks') return { asset: { is: assets } };
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
    return {AND:[{id:{in:rows.map((r:any)=>r.id)}},{links:{every:{finding:await resourceWhere(db,user,'findings')}}}]};
  }
  return {id:{in:[]}};
}
export async function assertScope(db: any, user: any, resource: string, id: string) {
  if (!delegates[resource]) { assertGlobal(user); return; }
  const found = await db[delegates[resource]].findFirst({where:{AND:[{id},await resourceWhere(db,user,resource)]},select:{id:true}});
  if (!found) throw new NotFoundException('记录不存在或不在授权范围');
}
export async function assertLinks(db: any, user: any, body: any) {
  if (!body || typeof body !== 'object') return;
  if(body.instanceId)await assertInstanceScope(db,user,body.instanceId);
  if (!restricted(user)) return;
  for (const [key,resource] of [['assetId','assets'],['findingId','findings'],['relatedRiskId','findings']] as const)
    if (body[key]) await assertScope(db,user,resource,body[key]);
  for (const [key,resource] of [['assetIds','assets'],['findingIds','findings'],['taskIds','tasks']] as const)
    for (const id of body[key] || []) await assertScope(db,user,resource,id);
}
const sensitive = new Set(['inspection','evidence','description','conclusion','verification','remainingRisks','reason','parameters','result','inventory','detail','body','data','config','path','remoteIp','message','fields','payload','headers']);
const publicPrivateFields=new Set(['inspection','evidence','description','conclusion','verification','remainingrisks','reason','parameters','result','detail','details','body','payload','banner','bannerpreview','headers','request','response','raw','sql','statement','statements','query','querytext','command','commands','commandline','cmdline','cmd','argv','args','env','environment','environmentvariables','script','stdout','stderr','files','before','after','diff','changes','stack','lasterror','message','actiondetail','connectionstring','databaseurl','dsn','cookie','setcookie','authorization','value','expectedvalue','expected','matchvalue','pattern','content','contents','sourcetext','rawtext','downloadurl','artifacturl','trustroot']);
const publicAuditFields=new Set(['succeeded','rows','tls','sessionId','objects','columns','execution','sourceHost','application','permissionGranted','userKnown','returnCode','authentication','objectType','durationMs']);
function publicMetadata(value:unknown):unknown{
 if(value===null||value===undefined||value instanceof Date)return value;
 if(typeof value==='string'){
  // Even a harmless metadata field may contain an accidentally embedded credential.
  if(/-----BEGIN [^-]*(?:PRIVATE KEY|CERTIFICATE)-----|\b(?:Bearer|Basic)\s+\S+|(?:password|passwd|token|secret|api[_-]?key)\s*[=:]|[a-z][a-z0-9+.-]*:\/\/[^\s/]*@/i.test(value))return '[已隐藏]';
  if(/^(?:https?:\/\/|\/)/i.test(value))return value.split(/[?#]/,1)[0];
  return value;
 }
 if(Array.isArray(value))return value.map(publicMetadata);
 if(typeof value!=='object')return value;
 return Object.fromEntries(Object.entries(value).flatMap(([key,entry])=>{
  const normalized=key.replace(/[^a-z0-9]/gi,'').toLowerCase();
  if(normalized==='evidence')return [[key,'[已隐藏]']];
  if(/^can[A-Z_]/.test(key))return [[key,false]];
  if(normalized==='value'&&(typeof entry==='number'||typeof entry==='boolean'))return [[key,entry]];
  if(normalized==='result'&&typeof entry==='string'&&['SUCCESS','FAILURE','UNKNOWN'].includes(entry))return [[key,entry]];
  if(normalized==='details')return [[key,typeof entry==='string'?'[已隐藏]':publicMetadata(entry&&typeof entry==='object'&&!Array.isArray(entry)?Object.fromEntries(Object.entries(entry).filter(([field])=>publicAuditFields.has(field))):{})]];
  if(typeof entry==='boolean'&&/(?:configured|status|valid|issued|enabled)$/.test(normalized))return [[key,entry]];
  if(publicPrivateFields.has(normalized)||/password|passwd|secret|token|credential|privatekey|publickey|hostkey|apikey|encryptionkey|signingkey|ciphertext|hash|sha256|sqltext|sqlstatement|statementtext|rawsql|requestbody|responsebody|requestbase64|responsebase64|bodybase64|rawrequest|rawresponse|headers|authorization|cookie/.test(normalized))return [];
  return [[key,publicMetadata(entry)]];
 }));
}
export function redactEvidence(user: any, value: any): any {
  if(isPublicReadOnlyUser(user))return publicMetadata(value);
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
