import {authorizeHostWaf} from './host-waf-identity';
import {requestTraceInput} from './request-trace';
import {lockEventStorage,assertEventCapacity,telemetryRetentionDays} from "./storage";
import {ServiceUnavailableException,BadRequestException, Body, Controller, Get, Inject, Injectable, Param, Patch, Post, Query, Req, UnauthorizedException, UseGuards} from '@nestjs/common';
import {z} from 'zod';
import {Db} from './db';
import {Platform} from './platform';
import {AuthGuard, allow, bearer, component} from './auth';
import {hashToken} from './security';
import {parse, severity, text} from './validation';
import {assertEvidence, assertGlobal, assertScope, assetScope, restricted} from './scope';

const conditionInput=z.object({field:z.enum(['source','type','data.status','data.method','data.action','data.ruleId','data.outcome','data.category','data.message']),operator:z.enum(['eq','contains']).default('eq'),value:z.union([z.string().min(1).max(200),z.number().finite()]),threshold:z.number().int().min(1).max(1000).default(1)}).strict();
export const correlationConfig=z.object({mode:z.enum(['ALL','ANY']),groupBy:z.enum(['asset','site']),windowSeconds:z.number().int().min(1).max(86400),conditions:z.array(conditionInput).min(1).max(20),createIncident:z.boolean().default(false)}).strict();
export const correlationInput=z.object({name:text,severity,enabled:z.boolean().default(true),config:correlationConfig}).strict();
// Store a strict structured allowlist, never arbitrary log text, URLs, headers or bodies.
export function redactTelemetry(value:any,allowMessages=false){
 const out:Record<string,string|number>={};
 for(const key of ['status','durationMicros'])if(typeof value?.[key]==='number'&&Number.isFinite(value[key]))out[key]=value[key];
 for(const key of ['method','ruleId','action','outcome','category'])if(typeof value?.[key]==='string'&&/^[A-Za-z0-9_.:-]{1,100}$/.test(value[key]))out[key]=value[key];
 if(allowMessages&&typeof value?.message==='string')out.message=value.message.slice(0,4096)
  .replace(/(https?:\/\/)[^/\s:@]+:[^/\s@]+@/gi,'$1[REDACTED]@')
  .replace(/\b(?:authorization|proxy-authorization|cookie|set-cookie)\s*["']?\s*[:=]\s*[^\r\n]+/gi,'[REDACTED CREDENTIAL HEADER]')
  .replace(/\b([A-Za-z0-9_.-]*(?:password|passwd|pwd|token|api[-_]?key|secret|credential|session(?:id)?|access[-_]?token|refresh[-_]?token)[A-Za-z0-9_.-]*)\b\s*["']?\s*[:=]\s*(?:"[^"]*"|'[^']*'|[^\s,;&]+)/gi,'$1=[REDACTED]')
  .replace(/\bBearer\s+[A-Za-z0-9._~+\/=-]+/gi,'Bearer [REDACTED]');
 return out;
}
export function matchesConditions(rows:any[],config:{mode:string;conditions:any[]}){
 const matched=config.conditions.map(c=>rows.filter(row=>{const value=c.field.startsWith('data.')?row.data?.[c.field.slice(5)]:row[c.field];return c.operator==='contains'?typeof value==='string'&&value.includes(String(c.value)):value===c.value;}).length>=c.threshold);
 return config.mode==='ALL'?matched.every(Boolean):matched.some(Boolean);
}
// Sweep event time so delayed queue batches can complete a window whose last
// event was already persisted. Each record enters/leaves the counts once.
function* matchingWindows(records:any[],cfg:any,arrivingAt:Date){
 const counts=cfg.conditions.map(()=>0);let start=0;
 const matches=(row:any,c:any)=>matchesConditions([row],{mode:'ALL',conditions:[{...c,threshold:1}]});
 for(let end=0;end<records.length;end++){
  cfg.conditions.forEach((c:any,i:number)=>{if(matches(records[end],c))counts[i]++});
  while(records[start].occurredAt.getTime()<records[end].occurredAt.getTime()-cfg.windowSeconds*1000){cfg.conditions.forEach((c:any,i:number)=>{if(matches(records[start],c))counts[i]--});start++;}
  const ok=cfg.conditions.map((c:any,i:number)=>counts[i]>=c.threshold);
  if(records[end].occurredAt>=arrivingAt&&(cfg.mode==='ALL'?ok.every(Boolean):ok.some(Boolean)))yield {start,end,at:records[end].occurredAt as Date};
 }
}
const eventInput=z.object({id:z.string().min(1).max(200),type:z.string().regex(/^[A-Za-z0-9_.:-]{1,100}$/),timestamp:z.string().datetime(),data:z.record(z.string(),z.unknown()).default({})}).strict();
const eventsInput=z.object({events:z.array(eventInput).min(1).max(100)}).strict();
const accessInput=z.object({nodeId:z.string().regex(/^[A-Za-z0-9_.:-]{1,200}$/),events:z.array(z.object({id:z.string().min(1).max(200),siteId:z.union([z.string().uuid(),z.literal('')]),method:z.string().max(16),path:z.string().max(1024),context:requestTraceInput.optional(),status:z.number().int().min(100).max(599),timestamp:z.string().datetime(),durationMicros:z.number().int().nonnegative()}).strict()).min(1).max(100)}).strict();

@Injectable()
export class CorrelationService {
 constructor(@Inject(Db) readonly db:Db,@Inject(Platform) readonly p:Platform){}
 async ingest(source:string,sourceKey:string,rows:any[],context:{assetId?:string}={}){
  return this.db.$transaction(async tx=>{
   // Serialize one source batch so retry and concurrent delivery cannot increment alerts twice.
   await tx.$queryRaw`SELECT pg_advisory_xact_lock(hashtext(${sourceKey}))::text`;
   await lockEventStorage(tx);
   const now=new Date(),retentionDays=await telemetryRetentionDays(tx);let accepted=0,accessAccepted=0;
   const policy=await tx.setting.findUnique({where:{key:'telemetry:policy'}});const allowMessages=(policy?.value as any)?.allowMessages===true;
   const rules=await tx.correlationRule.findMany({where:{enabled:true}});
   for(const row of rows){
    const occurredAt=new Date(row.timestamp);
    if(occurredAt.getTime()>now.getTime()+300000||occurredAt.getTime()<now.getTime()-30*86400000)throw new BadRequestException('日志时间须在过去30天至未来5分钟内');
    if(row.siteId&&!(await tx.site.findUnique({where:{id:row.siteId},select:{id:true}})))throw new BadRequestException('站点不存在');
    if(source==='waf'&&row.type==='ACCESS'&&row.nodeId){
        const stored=await tx.wafAccess.createMany({data:[{id:row.id,nodeId:row.nodeId,siteId:row.siteId,method:row.method,path:row.path,status:row.status,timestamp:occurredAt,durationMicros:row.durationMicros,...(row.context?{context:row.context}:{})}],skipDuplicates:true});
        accessAccepted+=stored.count;
    }
    const inserted=await tx.telemetryEvent.createMany({data:[{source,sourceKey,externalId:row.id,assetId:context.assetId,siteId:row.siteId||null,type:row.type,occurredAt,expiresAt:new Date(now.getTime()+retentionDays*86400000),data:redactTelemetry(row.data,allowMessages)}],skipDuplicates:true});
    if(!inserted.count)continue;accepted++;
    for(const rule of rules){
     const cfg=parse(correlationConfig,rule.config);const groupId=cfg.groupBy==='asset'?context.assetId:row.siteId;if(!groupId)continue;
     const groupKey=cfg.groupBy+':'+groupId;
     await tx.$queryRaw`SELECT pg_advisory_xact_lock(hashtext(${rule.id+':'+groupKey}))::text`;
     const records=await tx.telemetryEvent.findMany({where:{...(cfg.groupBy==='asset'?{assetId:groupId}:{siteId:groupId}),occurredAt:{gte:new Date(occurredAt.getTime()-cfg.windowSeconds*1000),lte:new Date(occurredAt.getTime()+cfg.windowSeconds*1000)},expiresAt:{gt:now}},orderBy:[{occurredAt:'asc'},{id:'asc'}],take:50001});
     if(records.length>50000)throw new BadRequestException('关联窗口超过50000条记录；请缩短窗口');
     const considered=new Set<string>();
     for(const match of matchingWindows(records,cfg,occurredAt)){
     const windowStart=new Date(Math.floor(match.at.getTime()/(cfg.windowSeconds*1000))*cfg.windowSeconds*1000);
     if(considered.has(windowStart.toISOString()))continue;considered.add(windowStart.toISOString());
     if(await tx.correlationMatch.findUnique({where:{ruleId_groupKey_windowStart:{ruleId:rule.id,groupKey,windowStart}}}))continue;
     const windowRecords=records.slice(match.start,match.end+1);
     const evidence=JSON.stringify({ruleId:rule.id,groupKey,from:new Date(match.at.getTime()-cfg.windowSeconds*1000).toISOString(),to:match.at.toISOString(),eventCount:windowRecords.length,eventIds:windowRecords.slice(-100).map(r=>r.id),conditions:cfg.conditions});
     const finding=await this.p.ingest(tx,{externalId:rule.id+':'+groupKey+':'+windowStart.toISOString(),source:'correlation',title:rule.name,kind:'ALERT',severity:rule.severity,evidence},context.assetId);
     let incidentId:string|undefined;
     if(cfg.createIncident){const incident=await tx.incident.create({data:{title:rule.name,severity:rule.severity,type:'CORRELATION',description:evidence,assetIds:context.assetId?[context.assetId]:[],links:{create:{findingId:finding.id}}}});incidentId=incident.id;}
     await tx.correlationMatch.create({data:{ruleId:rule.id,groupKey,windowStart,findingId:finding.id,incidentId}});
     }
    }
   }
   await assertEventCapacity(tx,'telemetry',accepted);
   if(accessAccepted)await assertEventCapacity(tx,'access',accessAccepted);
   return {ok:true,accepted,duplicates:rows.length-accepted,retentionDays};
  },{timeout:30000});
 }
}
@Controller('telemetry')
export class TelemetryController {
 constructor(@Inject(Db) readonly db:Db,@Inject(CorrelationService) readonly service:CorrelationService){}
 @UseGuards(AuthGuard) @Get('policy') async policy(@Req()req:any){allow(req,['ADMIN']);const value=(await this.db.setting.findUnique({where:{key:'telemetry:policy'}}))?.value as any;return{allowMessages:value?.allowMessages===true};}
 @UseGuards(AuthGuard) @Patch('policy') async setPolicy(@Req()req:any,@Body()body:unknown){allow(req,['ADMIN']);const value=parse(z.object({allowMessages:z.boolean()}).strict(),body);return this.db.$transaction(async tx=>{await tx.setting.upsert({where:{key:'telemetry:policy'},create:{key:'telemetry:policy',value},update:{value}});await tx.audit.create({data:{actor:req.user.email,action:'TELEMETRY_POLICY',resource:'settings',detail:value}});return value;});}
 @Post('access') async access(@Req() req:any,@Body() body:unknown){const v=parse(accessInput,body);await authorizeHostWaf(this.db,req,v.events.map(row=>row.siteId),v.nodeId);if(req.hostWafNode&&v.events.some(row=>!row.id.startsWith(req.hostWafNode+':')||row.context&&!row.context.requestId.startsWith(req.hostWafNode+':')))throw new UnauthorizedException('访问记录的节点身份不一致');return this.service.ingest('waf','waf:'+v.nodeId,v.events.map(r=>({...r,nodeId:v.nodeId,type:'ACCESS',data:{status:r.status,method:r.method,durationMicros:r.durationMicros}})));}
 @Post('events') async events(@Req() req:any,@Body() body:unknown){const token=bearer(req);if(!token)throw new UnauthorizedException();const asset=await this.db.asset.findUnique({where:{tokenHash:hashToken(token)}});if(!asset||asset.archivedAt)throw new UnauthorizedException();const v=parse(eventsInput,body);return this.service.ingest('agent','agent:'+asset.id,v.events,{assetId:asset.id});}
 @UseGuards(AuthGuard) @Post('import') async importEvents(@Req() req:any,@Body() body:unknown){allow(req,['ADMIN','ANALYST']);const v=parse(eventsInput.extend({assetId:z.string().uuid()}),body);await assertScope(this.db,req.user,'assets',v.assetId);return this.service.ingest('import','import:'+req.user.id+':'+v.assetId,v.events,{assetId:v.assetId});}
 @UseGuards(AuthGuard) @Get() async list(@Req() req:any,@Query() query:unknown){assertEvidence(req.user);const v=parse(z.object({assetId:z.string().uuid().optional(),siteId:z.string().uuid().optional(),from:z.string().datetime().optional(),to:z.string().datetime().optional(),page:z.coerce.number().int().min(1).default(1),pageSize:z.coerce.number().int().min(1).max(100).default(20)}).strict(),query);
 const ids=restricted(req.user)?(await this.db.asset.findMany({where:assetScope(req.user),select:{id:true}})).map(a=>a.id):undefined;
 const where:any={AND:[...(ids?[{assetId:{in:ids}}]:[]),...(v.assetId?[{assetId:v.assetId}]:[]),...(v.siteId?[{siteId:v.siteId}]:[])],expiresAt:{gt:new Date()},occurredAt:{...(v.from?{gte:new Date(v.from)}:{}),...(v.to?{lte:new Date(v.to)}:{})}};
 const [items,total]=await Promise.all([this.db.telemetryEvent.findMany({where,orderBy:[{occurredAt:'desc'},{id:'asc'}],skip:(v.page-1)*v.pageSize,take:v.pageSize}),this.db.telemetryEvent.count({where})]);return {items,total,page:v.page,pageSize:v.pageSize,retentionDays:await telemetryRetentionDays(this.db)};}
 @UseGuards(AuthGuard) @Post('retention/purge') async purge(@Req() req:any){allow(req,['ADMIN']);return this.db.telemetryEvent.deleteMany({where:{expiresAt:{lte:new Date()}}});}
}
@Controller('correlation-rules')
@UseGuards(AuthGuard)
export class CorrelationController {
 constructor(@Inject(Db) readonly db:Db,@Inject(Platform) readonly p:Platform){}
 @Get() async list(@Req() req:any){assertGlobal(req.user);return {items:await this.db.correlationRule.findMany({orderBy:{createdAt:'desc'}})};}
 @Post() async create(@Req() req:any,@Body() body:unknown){allow(req,['ADMIN','ANALYST']);assertGlobal(req.user);const v=parse(correlationInput,body);return this.db.$transaction(async tx=>{const rule=await tx.correlationRule.create({data:v});await this.p.audit(tx,req.user.email,'CREATE','correlation-rules',rule.id);return rule;});}
 @Patch(':id') async patch(@Req() req:any,@Param('id') id:string,@Body() body:unknown){allow(req,['ADMIN','ANALYST']);assertGlobal(req.user);const v=parse(correlationInput.partial(),body);return this.db.$transaction(async tx=>{const rule=await tx.correlationRule.update({where:{id},data:v});await this.p.audit(tx,req.user.email,'UPDATE','correlation-rules',id);return rule;});}
}

@Controller('waf-policy-tests')
@UseGuards(AuthGuard)
export class WafPolicyTestController {
 constructor(@Inject(Db) readonly db:Db,@Inject(Platform) readonly p:Platform){}
 @Post() async test(@Req() req:any,@Body() body:unknown){
  allow(req,['ADMIN','ANALYST']);assertGlobal(req.user);
  const v=parse(z.object({siteId:z.string().uuid(),method:z.enum(['GET','POST','PUT','PATCH','DELETE','HEAD','OPTIONS','CONNECT','TRACE']),path:z.string().startsWith('/').max(16384),headers:z.record(z.string().max(100),z.string().max(16000)).default({}),body:z.string().max(500000).default(''),remoteIp:z.string().max(100).optional(),repeat:z.number().int().min(1).max(100).default(1)}).strict(),body);
  await assertScope(this.db,req.user,'sites',v.siteId);
  const address=process.env.WAF_TEST_URL;if(!address)throw new BadRequestException('未配置 WAF 测试管理地址');
  const url=new URL(address);if(url.username||url.password||url.search||url.hash||!['http:','https:'].includes(url.protocol))throw new BadRequestException('WAF 测试管理地址无效');
  if(url.protocol!=='https:'&&!['localhost','127.0.0.1','[::1]'].includes(url.hostname)&&process.env.WAF_DEVELOPMENT!=='true')throw new BadRequestException('WAF 测试管理连接需要 HTTPS');
  let response:Response;try{response=await fetch(address,{method:'POST',redirect:'error',signal:AbortSignal.timeout(15000),headers:{authorization:'Bearer '+(process.env.WAF_TEST_TOKEN||process.env.WAF_TOKEN),'content-type':'application/json'},body:JSON.stringify(v)});}catch{throw new ServiceUnavailableException('WAF 测试管理节点不可连接或响应超时');}
  if(!response.ok)throw new BadRequestException('WAF 节点拒绝测试：'+response.status);
  const result=await response.json();
  await this.p.audit(this.db,req.user.email,'TEST','sites',v.siteId,{repeat:v.repeat});
  return result;
 }
}
