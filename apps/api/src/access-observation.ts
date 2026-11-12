import {parseCapturedSql} from './traffic-sql';
import {accessObjectMappingsInput,resolveAccessObjects} from './access-classification';
import {Body,Controller,Get,Header,GoneException,Inject,Injectable,Param,Patch,Post,Query,Req,UseGuards,UnauthorizedException,ForbiddenException,NotFoundException,BadRequestException,ConflictException,HttpException,OnModuleInit,OnModuleDestroy,Logger} from '@nestjs/common';
import {AccessSource,Prisma} from '@prisma/client';
import {createHash} from 'node:crypto';
import {join} from 'node:path';
import {z} from 'zod';
import {Db} from './db';
import {effectiveAccessStorage} from './storage';
import {Platform} from './platform';
import {AuthGuard,allow,bearer} from './auth';
import {hashToken,newToken} from './security';
import {parse,pageInput} from './validation';
import {SecurityUser,SecurityRequest,engines} from './database-contract';
import {assetScope,assertScope,assertEvidence} from './scope';
import {instanceScope,assertInstanceScope} from './database-instances';
import {classificationBasis,classificationPolicy} from './data-governance';
import {accessProtocols,opensslProfileInput,probeHealthInput,accessEventInput,accessChunkInput,AccessEvent,evidenceExpiresAt,assertEvidenceLive} from './access-contract';
import {AccessEvidenceStore,EvidenceQuotaError} from './access-evidence';

export const accessRuleInput=z.object({id:z.string().regex(/^[a-zA-Z0-9_-]{1,80}$/),name:z.string().trim().min(1).max(160),category:z.enum(['ADMISSION','BEHAVIOR']),detector:z.enum(['AUTH_FAILURE','PERMISSION_DENIED','RETURN_VOLUME','SENSITIVE_READ','OPERATION','COVERAGE_GAP','HTTP_ERROR']),severity:z.enum(['INFO','LOW','MEDIUM','HIGH','CRITICAL']),minimumBytes:z.number().int().min(1).max(Number.MAX_SAFE_INTEGER).optional(),minimumLevel:z.number().int().min(1).max(10).optional(),operations:z.array(z.string().regex(/^[A-Z][A-Z0-9_]{0,31}$/)).max(32).default([])}).strict().superRefine((v,c)=>{if(v.detector==='RETURN_VOLUME'&&!v.minimumBytes)c.addIssue({code:'custom',message:'返回量规则需要字节阈值'});if(v.detector==='SENSITIVE_READ'&&!v.minimumLevel)c.addIssue({code:'custom',message:'敏感访问规则需要等级阈值'});if(v.detector==='OPERATION'&&!v.operations.length)c.addIssue({code:'custom',message:'操作规则需要操作列表'});});
const sourceFields=z.object({name:z.string().trim().min(1).max(160),assetId:z.string().uuid(),instanceId:z.string().uuid().optional(),protocol:z.enum(accessProtocols),mode:z.enum(['NETWORK','PLAINTEXT_EVENTS']),interface:z.string().regex(/^[a-zA-Z0-9_.:-]{1,32}$/),address:z.union([z.ipv4(),z.ipv6()]),port:z.number().int().min(1).max(65535),enabled:z.boolean().default(false),profile:opensslProfileInput.optional(),objectMappings:accessObjectMappingsInput.default([]),maxQueueBytes:z.number().int().min(1048576).max(1073741824).default(268435456),rules:z.array(accessRuleInput).max(30).default([])}).strict();
export const accessSourceInput=sourceFields.superRefine((v,c)=>{if(v.mode==='PLAINTEXT_EVENTS'&&!v.profile)c.addIssue({code:'custom',message:'进程明文观察需要固定进程及运行库评审信息'});if(v.mode==='NETWORK'&&v.profile)c.addIssue({code:'custom',message:'网络来源不能附带进程观察权限'});if(v.protocol!=='HTTP'&&!v.instanceId)c.addIssue({code:'custom',message:'数据组件观察源需要绑定实例'});if(new Set(v.rules.map(r=>r.id)).size!==v.rules.length)c.addIssue({code:'custom',message:'规则标识重复'});});
type ProbeRequest={headers:{authorization?:string}};
function validateSourceObjectMappings(source:{protocol:string;instanceId?:string|null;objectMappings:z.infer<typeof accessObjectMappingsInput>}){
 if(source.objectMappings.length&&!source.instanceId)throw new BadRequestException('对象关联需要绑定已授权的数据实例');
 if(source.objectMappings.some(m=>m.kind==='HTTP_ROUTE'?source.protocol!=='HTTP':source.protocol!=='POSTGRESQL'))throw new BadRequestException('对象关联类型与业务协议不符');
 if(source.objectMappings.some(m=>m.kind==='POSTGRES_COLUMN'&&Date.parse(m.observedAt)>Date.now()+300000))throw new BadRequestException('元数据快照时间超前超过五分钟');
}
export function accessCollectionState(source:{enabled:boolean;credentialValid:boolean;credentialIssued?:boolean;version:number;lastReportAt:Date|null;health:unknown},now=Date.now()){
 const parsed=probeHealthInput.partial().safeParse(source.health),health=parsed.success?parsed.data:{};
 const state=!source.enabled?'DISABLED':source.credentialIssued===false?'CONFIG_REQUIRED':!source.credentialValid?'IDENTITY_INVALID':!source.lastReportAt?'AWAITING_PROBE':now-source.lastReportAt.getTime()>180000?'STALE':health.configurationVersion!==source.version?'CONFIG_MISMATCH':health.state||'UNKNOWN';
 return {state,probeVersion:health.version||null,reportedConfigurationVersion:health.configurationVersion??null,expectedConfigurationVersion:source.version};
}
function safeSource(s:AccessSource){return {id:s.id,name:s.name,assetId:s.assetId,instanceId:s.instanceId,protocol:s.protocol,mode:s.mode,interface:s.interface,address:s.address,port:s.port,enabled:s.enabled,version:s.version,maxQueueBytes:s.maxQueueBytes,profile:s.profile,objectMappings:s.objectMappings,rules:s.rules,health:s.health,lastReportAt:s.lastReportAt,createdAt:s.createdAt,updatedAt:s.updatedAt};}
function sourceWhere(user:SecurityUser):Prisma.AccessSourceWhereInput{return{asset:{is:assetScope(user)},OR:[{instanceId:null},{instance:{is:instanceScope(user)}}]};}
function json(value:unknown):Prisma.InputJsonValue{return JSON.parse(JSON.stringify(value)) as Prisma.InputJsonValue;}
function serialize<T extends {requestBytes:bigint;responseBytes:bigint}>(r:T){return {...r,requestBytes:Number(r.requestBytes),responseBytes:Number(r.responseBytes)};}
export function accessRuleMatches(rule:z.infer<typeof accessRuleInput>,event:AccessEvent,level:number|null){
 if(rule.operations.length&&!rule.operations.includes(event.operation))return false;
 if(rule.detector==='HTTP_ERROR')return event.statusCode!==undefined&&event.statusCode>=400;
 if(rule.detector==='AUTH_FAILURE')return event.authentication==='FAILURE';
 if(rule.detector==='PERMISSION_DENIED')return event.permission==='DENIED';
 if(rule.detector==='RETURN_VOLUME')return event.responseBytes>=(rule.minimumBytes||Infinity);
 if(rule.detector==='SENSITIVE_READ')return level!==null&&level>=(rule.minimumLevel||Infinity)&&event.result==='SUCCESS'&&(rule.minimumBytes===undefined||event.responseBytes>=rule.minimumBytes)&&['GET','SELECT','MGET','HGET','HGETALL','LRANGE','SMEMBERS','ZRANGE','SCAN','EXPORT'].includes(event.operation);
 if(rule.detector==='COVERAGE_GAP')return event.completeness!=='COMPLETE';
 return rule.detector==='OPERATION';
}
@Injectable()
export class AccessObservationService implements OnModuleInit,OnModuleDestroy{
 private ingressActive=0;
 async ingress<T>(work:()=>Promise<T>):Promise<T>{if(this.ingressActive>=2)throw new HttpException('探针交付繁忙，请保留本地加密队列后重试',503);this.ingressActive++;try{return await work();}finally{this.ingressActive--;}}
 private cleanupTimer?:ReturnType<typeof setInterval>;private cleaning=false;
 onModuleInit(){this.cleanupTimer=setInterval(()=>{if(this.cleaning)return;this.cleaning=true;void this.cleanup().catch(()=>Logger.warn('Access evidence cleanup incomplete; expired access remains denied','AccessEvidence')).finally(()=>{this.cleaning=false})},60000);this.cleanupTimer.unref();}
 onModuleDestroy(){if(this.cleanupTimer)clearInterval(this.cleanupTimer);}
 constructor(@Inject(Db)private db:Db,@Inject(Platform)private platform:Platform){}
 store(){return new AccessEvidenceStore(process.env.ACCESS_EVIDENCE_DIR||join(process.cwd(),'.data','access-evidence'),process.env.DATA_ENCRYPTION_KEY||'',process.env.DATA_ENCRYPTION_PREVIOUS_KEY?[process.env.DATA_ENCRYPTION_PREVIOUS_KEY]:[]);}
 private async source(user:SecurityUser,id:string){const s=await this.db.accessSource.findFirst({where:{AND:[{id},sourceWhere(user)]}});if(!s)throw new NotFoundException('观察源不存在或不在授权范围');return s;}
 async createSource(user:SecurityUser,body:unknown){allow({user},['ADMIN']);assertEvidence(user);const v=parse(accessSourceInput,body);return this.db.$transaction(async tx=>{
  await assertScope(tx,user,'assets',v.assetId);const a=await tx.asset.findUniqueOrThrow({where:{id:v.assetId}});if(a.archivedAt)throw new ConflictException('主机已归档');
  if(v.instanceId){const instance=await assertInstanceScope(tx,user,v.instanceId);if(instance.archivedAt||!instance.hostIds.includes(v.assetId))throw new BadRequestException('实例未授权此主机采集');if(v.protocol!=='HTTP'&&instance.engine!==v.protocol.toLowerCase())throw new BadRequestException('实例与协议不符');}
  validateSourceObjectMappings(v);const s=await tx.accessSource.create({data:v});await tx.audit.create({data:{actor:user.email,action:'ACCESS_SOURCE_CREATE',resource:'access-sources',resourceId:s.id,detail:{assetId:v.assetId,instanceId:v.instanceId,protocol:v.protocol,enabled:v.enabled}}});return safeSource(s);
 });}
 async updateSource(user:SecurityUser,id:string,body:unknown){allow({user},['ADMIN']);const v=parse(z.object({version:z.number().int().min(1),enabled:z.boolean().optional(),rules:z.array(accessRuleInput).max(30).optional(),instanceId:z.string().uuid().nullable().optional(),objectMappings:accessObjectMappingsInput.optional()}).strict(),body);await this.source(user,id);return this.db.$transaction(async tx=>{
  await tx.$queryRaw`SELECT id FROM "AccessSource" WHERE id=${id} FOR UPDATE`;const current=await tx.accessSource.findUniqueOrThrow({where:{id}});
  const instanceId=v.instanceId===undefined?current.instanceId:v.instanceId;
  if(v.instanceId!==undefined&&v.instanceId!==current.instanceId&&current.protocol!=='HTTP')throw new BadRequestException('数据库来源不能更换实例，请新建明确来源');
  if(instanceId!==current.instanceId&&await tx.accessObservation.count({where:{sourceId:id}}))throw new ConflictException('此来源已有访问记录，不能更换实例归属；请新建来源，保留历史证据与授权范围');
  if(instanceId){const instance=await assertInstanceScope(tx,user,instanceId);if(instance.archivedAt||!instance.hostIds.includes(current.assetId))throw new BadRequestException('实例未授权此主机采集');}
  const objectMappings=v.objectMappings??(instanceId!==current.instanceId?[]:accessObjectMappingsInput.parse(current.objectMappings));validateSourceObjectMappings({protocol:current.protocol,instanceId,objectMappings});const changed=await tx.accessSource.updateMany({where:{id,version:v.version},data:{enabled:v.enabled,rules:v.rules,instanceId,objectMappings,version:{increment:1},...(v.enabled===false?{tokenHash:null,issuedAssetTokenHash:null}:{})}});if(!changed.count)throw new ConflictException('观察源已变化，请刷新');await tx.audit.create({data:{actor:user.email,action:'ACCESS_SOURCE_UPDATE',resource:'access-sources',resourceId:id,detail:json(v)}});return safeSource(await tx.accessSource.findUniqueOrThrow({where:{id}}));
 });}
 async sources(user:SecurityUser,query:unknown){const v=parse(pageInput.extend({instanceId:z.string().uuid().optional()}),query),where:Prisma.AccessSourceWhereInput={AND:[sourceWhere(user),...(v.assetId?[{assetId:v.assetId}]:[]),...(v.instanceId?[{instanceId:v.instanceId}]:[])]};const [items,total]=await Promise.all([this.db.accessSource.findMany({where,include:{asset:{select:{tokenHash:true,archivedAt:true,lastSeen:true,inventory:true}},instance:{select:{archivedAt:true,hostIds:true}}},orderBy:{createdAt:'desc'},take:v.pageSize,skip:(v.page-1)*v.pageSize}),this.db.accessSource.count({where})]);const accesses=items.length?await this.db.accessObservation.groupBy({by:['sourceId'],where:{sourceId:{in:items.map(s=>s.id)}},_max:{startedAt:true}}):[];
 return {items:items.map(s=>{const credentialValid=!!s.tokenHash&&!!s.asset.tokenHash&&s.issuedAssetTokenHash===s.asset.tokenHash&&!s.asset.archivedAt&&(!s.instance||(!s.instance.archivedAt&&s.instance.hostIds.includes(s.assetId)));const diagnostics=z.object({agentDiagnostics:z.object({version:z.string()})}).safeParse(s.asset.inventory);return {...safeSource(s),collection:accessCollectionState({...s,credentialValid,credentialIssued:!!s.tokenHash}),agent:{version:diagnostics.success?diagnostics.data.agentDiagnostics.version:null,lastSeen:s.asset.lastSeen},lastAccessAt:accesses.find(row=>row.sourceId===s.id)?._max.startedAt||null};}),total,canManage:user.role==='ADMIN'};}
 async issueCredential(user:SecurityUser,id:string){allow({user},['ADMIN']);const s=await this.source(user,id),token=newToken();return this.db.$transaction(async tx=>{
  await tx.$queryRaw`SELECT id FROM "AccessSource" WHERE id=${id} FOR UPDATE`;const current=await tx.accessSource.findUniqueOrThrow({where:{id}}),asset=await tx.asset.findUniqueOrThrow({where:{id:s.assetId}});if(!current.enabled||asset.archivedAt||!asset.tokenHash)throw new ConflictException('需要启用观察源及有效Agent身份');
  await tx.accessSource.update({where:{id},data:{tokenHash:hashToken(token),issuedAssetTokenHash:asset.tokenHash}});await tx.audit.create({data:{actor:user.email,action:'ACCESS_PROBE_CREDENTIAL',resource:'access-sources',resourceId:id}});return {token,sourceId:id,configuration:safeSource(current)};
 });}
 async probeIdentity(req:ProbeRequest){const token=bearer(req);if(!token)throw new UnauthorizedException();const s=await this.db.accessSource.findUnique({where:{tokenHash:hashToken(token)},include:{asset:true,instance:true}});if(!s||!s.enabled||s.asset.archivedAt||!s.asset.tokenHash||s.issuedAssetTokenHash!==s.asset.tokenHash||s.instance?.archivedAt||(s.instance&&!s.instance.hostIds.includes(s.assetId)))throw new UnauthorizedException('探针授权已失效');return s;}
 private async lockSource(tx:Prisma.TransactionClient,s:AccessSource){await tx.$queryRaw`SELECT id FROM "AccessSource" WHERE id=${s.id} FOR UPDATE`;const current=await tx.accessSource.findUniqueOrThrow({where:{id:s.id},include:{asset:true,instance:true}});if(!current.enabled||current.tokenHash!==s.tokenHash||!current.asset.tokenHash||current.issuedAssetTokenHash!==current.asset.tokenHash||current.asset.archivedAt||current.instance?.archivedAt||(current.instance&&!current.instance.hostIds.includes(s.assetId)))throw new UnauthorizedException('探针授权已失效');return current;}
 async receiveChunk(source:AccessSource,body:unknown){const v=parse(accessChunkInput,body);assertEvidenceLive(new Date(v.capturedAt));const bytes=Buffer.from(v.data,'base64');if(createHash('sha256').update(bytes).digest('hex')!==v.sha256)throw new BadRequestException('分段校验失败');return this.db.$transaction(async tx=>{
  const s=await this.lockSource(tx,source),key={sourceId:s.id,eventId:v.eventId,direction:v.direction,sequence:v.sequence};const old=await tx.accessEvidenceChunk.findUnique({where:{sourceId_eventId_direction_sequence:key}});
  if(old){if(old.sha256!==v.sha256||old.bytes!==bytes.length||old.capturedAt.toISOString()!==new Date(v.capturedAt).toISOString())throw new ConflictException('同一分段内容冲突');if(!old.object)throw new ConflictException('证据已清理');return {persisted:true,duplicate:true,id:old.id,sha256:v.sha256,sequence:v.sequence,direction:v.direction,eventId:v.eventId};}
  if(await tx.accessObservation.findUnique({where:{sourceId_eventId:{sourceId:s.id,eventId:v.eventId}}}))throw new ConflictException('已确认访问不能追加分段');
  await tx.$queryRaw`SELECT pg_advisory_xact_lock(hashtext(current_schema()),hashtext('access-evidence-capacity'))::text`;
  const count=await tx.accessEvidenceChunk.count({where:{object:{not:null}}}),capacity=await effectiveAccessStorage(tx);if(count>=capacity.indexLimit*4)throw new HttpException('访问证据分段索引已达容量上限，请清理到期记录',507);

  const binding={...key,capturedAt:new Date(v.capturedAt).toISOString(),sha256:v.sha256},object=await this.store().put(binding,bytes,capacity.quotaBytes).catch(error=>{if(error instanceof EvidenceQuotaError)throw new HttpException('证据存储已达配额，未确认分段应保留在探针队列',507);throw error});const row=await tx.accessEvidenceChunk.create({data:{...binding,capturedAt:new Date(v.capturedAt),expiresAt:evidenceExpiresAt(new Date(v.capturedAt)),bytes:bytes.length,object}});return {persisted:true,duplicate:false,id:row.id,sha256:v.sha256,sequence:v.sequence,direction:v.direction,eventId:v.eventId};
 },{timeout:30000});}
 async receiveEvent(source:AccessSource,body:unknown){const v=parse(accessEventInput,body);if(Date.parse(v.endedAt)>Date.now()+300000)throw new BadRequestException('访问时间超前');const digest=createHash('sha256').update(JSON.stringify(v)).digest('hex');return this.db.$transaction(async tx=>{
  const s=await this.lockSource(tx,source),old=await tx.accessObservation.findUnique({where:{sourceId_eventId:{sourceId:s.id,eventId:v.eventId}}});if(old){if(old.manifestSha256!==digest)throw new ConflictException('访问标识内容冲突');return {accepted:true,duplicate:true,id:old.id,eventId:v.eventId};}
  await tx.$queryRaw`SELECT pg_advisory_xact_lock(hashtext(current_schema()),hashtext('access-evidence-capacity'))::text`;const capacity=await effectiveAccessStorage(tx);if(await tx.accessObservation.count()>=capacity.indexLimit)throw new HttpException('访问索引已达配置上限，未确认事件应保留在探针队列',507);
  const chunkIds:string[]=[];for(const c of v.chunks){const row=await tx.accessEvidenceChunk.findUnique({where:{sourceId_eventId_direction_sequence:{sourceId:s.id,eventId:v.eventId,direction:c.direction,sequence:c.sequence}}});if(!row||!row.object||row.sha256!==c.sha256||row.bytes!==c.bytes||row.capturedAt.toISOString()!==new Date(c.capturedAt).toISOString())throw new ConflictException('证据尚未完整持久化');assertEvidenceLive(row.capturedAt);if(Date.parse(c.capturedAt)<Date.parse(v.startedAt)-300000||Date.parse(c.capturedAt)>Date.parse(v.endedAt)+300000)throw new BadRequestException('分段时间不在访问范围');chunkIds.push(row.id);}
  const policy=await classificationPolicy(tx),definitions=s.instanceId?await tx.dataClassification.findMany({where:{instanceId:s.instanceId,status:'ACTIVE'}}):[];
  // Classification consumes observed objects; no SQL keyword guessing or claimed end-user identity.
  const instance=s.instanceId?await tx.databaseInstance.findUniqueOrThrow({where:{id:s.instanceId}}):null;
  const service=engines.find(engine=>engine===(s.protocol==='HTTP'?instance?.engine:s.protocol.toLowerCase()));
  const resolution=resolveAccessObjects(s.protocol,v,accessObjectMappingsInput.parse(s.objectMappings));
  const classificationEvent=service?{service,database:s.protocol==='HTTP'||resolution.objects.length?undefined:v.database,operation:'OTHER' as const,user:v.databaseUser||'UNKNOWN',objects:resolution.objects,columns:[]}:undefined;
  const rawBasis=classificationEvent?classificationBasis(classificationEvent,definitions,'INFO',policy):{status:'UNCLASSIFIED',level:null,severity:'INFO',policyVersion:policy.version,definitions:[]};
  const basis={...rawBasis,status:(resolution.unresolved||v.gaps.some(g=>g==='CORRELATION_UNKNOWN'||g==='RESOURCE_LIMIT'||g==='PARSE_ERROR'))&&rawBasis.level!==null?'PARTIAL':rawBasis.status,objectResolution:{basis:resolution.basis,status:resolution.status,unresolved:resolution.unresolved,configurationVersion:s.version}};
  const matchedRules=parse(z.array(accessRuleInput),s.rules).filter(rule=>accessRuleMatches(rule,v,basis.level));
  const assessments=matchedRules.map(rule=>{const evaluated=classificationEvent?classificationBasis(classificationEvent,definitions,rule.severity,policy):{...basis,severity:rule.severity};return {ruleId:rule.id,name:rule.name,category:rule.category,detector:rule.detector,sourceVersion:s.version,baseSeverity:rule.severity,classificationFloor:basis.level===null?null:basis.severity,finalSeverity:evaluated.severity,minimumBytes:rule.minimumBytes,minimumLevel:rule.minimumLevel,operations:rule.operations};});
  const riskAssessment={status:assessments.length?'ALERT':'ORDINARY',evaluatedAt:new Date().toISOString(),sourceVersion:s.version,policyVersion:policy.version,rules:assessments,meaning:'数据等级描述敏感程度；仅命中配置规则时生成告警，最终等级不低于该规则和数据映射要求'};
  if(s.instanceId){for(const o of resolution.objects){const objects=[{database:o.database,schema:'',table:'',column:''},...(o.table?[{database:o.database,schema:o.schema||'',table:o.table,column:''},...o.columns.map(column=>({database:o.database,schema:o.schema||'',table:o.table!,column}))]:[])];for(const object of objects){const key={instanceId:s.instanceId,...object};await tx.dataObject.upsert({where:{instanceId_database_schema_table_column:key},create:{...key,source:s.protocol==='HTTP'?'DECLARED_INTERFACE':'AUDIT_OBSERVED'},update:{lastSeen:new Date()}});}}}
  const {chunks:_,...metadata}=v;const row=await tx.accessObservation.create({data:{sourceId:s.id,eventId:v.eventId,manifestSha256:digest,chunkIds,startedAt:new Date(v.startedAt),endedAt:new Date(v.endedAt),sessionId:v.sessionId,operation:v.operation,route:v.route,sourceIp:v.sourceIp,databaseUser:v.databaseUser,result:v.result,completeness:v.completeness,requestBytes:BigInt(v.requestBytes),responseBytes:BigInt(v.responseBytes),level:basis.level,classification:json(basis),metadata:json({...metadata,classifiedObjects:resolution.objects,riskAssessment})}});
  const ids:string[]=[];for(const assessment of assessments){const finding=await this.platform.ingest(tx,{externalId:`access:${s.id}:${v.eventId}:${assessment.ruleId}:v${s.version}`,title:assessment.name,kind:'ALERT',severity:assessment.finalSeverity,source:'access-observation',assetId:s.assetId,...(s.instanceId?{instanceId:s.instanceId}:{}),evidence:JSON.stringify({type:'ACCESS_OBSERVATION',accessId:row.id,sourceId:s.id,ruleId:assessment.ruleId,sourceVersion:s.version,category:assessment.category,completeness:v.completeness,classification:basis,riskAssessment:assessment,action:'DETECT_ONLY'})});ids.push(finding.id);}
  if(ids.length)await tx.accessObservation.update({where:{id:row.id},data:{findingIds:ids}});return {accepted:true,duplicate:false,id:row.id,eventId:v.eventId};
 },{timeout:30000});}
 async list(user:SecurityUser,query:unknown){const v=parse(pageInput.extend({sourceId:z.string().uuid().optional(),instanceId:z.string().uuid().optional(),sessionId:z.string().max(128).optional(),objectDatabase:z.string().max(128).optional(),objectSchema:z.string().max(128).optional(),objectTable:z.string().max(128).optional(),objectColumn:z.string().max(128).optional(),route:z.string().max(2048).optional(),operation:z.string().max(32).optional(),result:z.enum(['SUCCESS','FAILURE','UNKNOWN']).optional(),completeness:z.enum(['COMPLETE','PARTIAL','UNSUPPORTED']).optional(),level:z.coerce.number().int().min(1).max(10).optional()}),query);const where:Prisma.AccessObservationWhereInput={source:{is:{AND:[sourceWhere(user),...(v.assetId?[{assetId:v.assetId}]:[]),...(v.instanceId?[{instanceId:v.instanceId}]:[])]}},...(v.sourceId?{sourceId:v.sourceId}:{}),...(v.sessionId?{sessionId:v.sessionId}:{}),...(v.objectDatabase||v.objectSchema||v.objectTable||v.objectColumn?{OR:['objects','classifiedObjects'].map(key=>({metadata:{path:[key],array_contains:[{...(v.objectDatabase?{database:v.objectDatabase}:{}),...(v.objectSchema?{schema:v.objectSchema}:{}),...(v.objectTable?{table:v.objectTable}:{}),...(v.objectColumn?{columns:[v.objectColumn]}:{})}]}}))}:{}),...(v.route?{route:{contains:v.route}}:{}),...(v.operation?{operation:v.operation}:{}),...(v.result?{result:v.result}:{}),...(v.completeness?{completeness:v.completeness}:{}),...(v.level?{level:v.level}:{}),...(v.createdFrom||v.createdTo?{startedAt:{...(v.createdFrom?{gte:new Date(v.createdFrom)}:{}),...(v.createdTo?{lte:new Date(v.createdTo)}:{})}}:{})};const [rows,total]=await Promise.all([this.db.accessObservation.findMany({where,include:{source:{select:{name:true,assetId:true,instanceId:true,protocol:true,address:true,port:true}}},orderBy:[{startedAt:'desc'},{id:'desc'}],take:v.pageSize,skip:(v.page-1)*v.pageSize}),this.db.accessObservation.count({where})]);return {items:rows.map(serialize),total};}
 async detail(user:SecurityUser,id:string){const row=await this.db.accessObservation.findFirst({where:{id,source:{is:sourceWhere(user)}},include:{source:{select:{name:true,assetId:true,instanceId:true,protocol:true,address:true,port:true,mode:true}}}});if(!row)throw new NotFoundException('访问记录不存在或不在授权范围');const chunks=await this.db.accessEvidenceChunk.findMany({where:{sourceId:row.sourceId,eventId:row.eventId,id:{in:row.chunkIds}},select:{id:true,direction:true,sequence:true,capturedAt:true,expiresAt:true,sha256:true,bytes:true,object:true},orderBy:[{direction:'asc'},{sequence:'asc'}]});return {...serialize(row),chunks:chunks.map(({object,...c})=>({...c,available:!!object&&c.expiresAt>new Date()})),canReadSql:user.role==='ADMIN'||(user.dataScope?.canReadEvidence!==false&&user.dataScope?.canReadAccessEvidence===true&&user.dataScope?.canReadSqlEvidence===true),canReadRaw:user.role==='ADMIN'||(user.dataScope?.canReadEvidence!==false&&user.dataScope?.canReadAccessEvidence===true),canExportRaw:user.role==='ADMIN'||(user.dataScope?.canReadEvidence!==false&&user.dataScope?.canExportAccessEvidence===true)};}
 async sql(user:SecurityUser,id:string){
  assertEvidence(user);if(user.role!=='ADMIN'&&(user.dataScope?.canReadAccessEvidence!==true||user.dataScope?.canReadSqlEvidence!==true))throw new ForbiddenException('需要原始访问证据与 SQL 原文的独立读取权限');
  const row=await this.detail(user,id),base={protocol:row.source.protocol,source:'PACKET_REQUEST' as const,observedAt:row.startedAt};
  const unavailable=(reason:string)=>({...base,state:'UNAVAILABLE' as const,statements:[] as {sql:string;stage:'QUERY'|'PREPARE'|'EXECUTE'}[],reasons:[reason]});
  const metadata=z.object({gaps:z.array(z.string()).optional()}).safeParse(row.metadata),gaps=metadata.success?metadata.data.gaps||[]:[];
  if(gaps.includes('TLS_NO_PLAINTEXT'))return unavailable('TLS_NO_PLAINTEXT');
  if(['LOGIN','AUTH','AUTHENTICATE','AUTHENTICATION','STARTUP'].includes(row.operation))return unavailable('AUTHENTICATION_MESSAGE');
  if(row.requestBytes>1048576||!Number.isSafeInteger(row.requestBytes)||row.requestBytes<0)return unavailable('REQUEST_TOO_LARGE');
  const parts=row.chunks.filter(c=>c.direction==='REQUEST').sort((a,b)=>a.sequence-b.sequence);
  if(!parts.length)return unavailable(gaps.includes('EVIDENCE_EXPIRED')?'EVIDENCE_EXPIRED':'BODY_NOT_CAPTURED');
  const expired=()=>parts.some(c=>c.expiresAt.getTime()<=Date.now()||evidenceExpiresAt(c.capturedAt).getTime()<=Date.now());
  if(expired())return unavailable('EVIDENCE_EXPIRED');
  if(parts.some((c,i)=>c.sequence!==i||!c.available)||parts.reduce((sum,c)=>sum+c.bytes,0)!==row.requestBytes)return unavailable('INCOMPLETE_EVIDENCE');
  const buffers:Buffer[]=[];let expiresAt=new Date(Math.min(...parts.map(c=>Math.min(c.expiresAt.getTime(),evidenceExpiresAt(c.capturedAt).getTime()))));
  for(const c of parts){
   let read:Awaited<ReturnType<AccessObservationService['readChunk']>>;
   try{read=await this.readChunk(user,id,c.id,'READ');}catch(error){if(error instanceof GoneException)return unavailable('EVIDENCE_EXPIRED');throw error;}
   if(expired()||read.expiresAt.getTime()<=Date.now())return unavailable('EVIDENCE_EXPIRED');
   const bytes=Buffer.from(read.data,'base64');if(read.sha256!==c.sha256||read.bytes!==c.bytes||bytes.length!==c.bytes||createHash('sha256').update(bytes).digest('hex')!==c.sha256)throw new ConflictException('证据分段绑定校验失败');
   expiresAt=new Date(Math.min(expiresAt.getTime(),read.expiresAt.getTime()));buffers.push(bytes);
  }
  const parsed=parseCapturedSql(row.source.protocol,Buffer.concat(buffers,row.requestBytes));
  const mapped=gaps.map(gap=>['CAPTURE_LOSS','MIDSTREAM','CORRELATION_UNKNOWN','BODY_NOT_CAPTURED','EVIDENCE_EXPIRED','PROTOCOL_UNSUPPORTED'].includes(gap)?gap:gap==='PARSE_ERROR'?'INVALID_FRAME':'INCOMPLETE_EVIDENCE');
  const reasons=[...new Set([...parsed.reasons,...mapped])];
  const state=row.completeness==='UNSUPPORTED'?'UNSUPPORTED':row.completeness==='PARTIAL'&&parsed.state==='EXTRACTED'?'PARTIAL':parsed.state;
  if(row.completeness!=='COMPLETE'&&!reasons.length)reasons.push('INCOMPLETE_EVIDENCE');
  if(expired()||expiresAt.getTime()<=Date.now())return unavailable('EVIDENCE_EXPIRED');
  return {...base,...parsed,state,reasons,expiresAt};
 }
 async readChunk(user:SecurityUser,id:string,chunkId:string,purpose:'READ'|'EXPORT'){
  assertEvidence(user);if(user.role!=='ADMIN'&&!(purpose==='EXPORT'?user.dataScope?.canExportAccessEvidence:user.dataScope?.canReadAccessEvidence))throw new ForbiddenException('没有读取原始访问证据的独立权限');
  const row=await this.detail(user,id),c=await this.db.accessEvidenceChunk.findFirst({where:{id:chunkId,sourceId:row.sourceId,eventId:row.eventId,AND:[{id:{in:row.chunkIds}}]}});if(!c||!c.object)throw new NotFoundException('证据不存在或已清理');assertEvidenceLive(c.capturedAt);const bytes=await this.store().read({...c,capturedAt:c.capturedAt.toISOString()},c.object);assertEvidenceLive(c.capturedAt);
  await this.db.audit.create({data:{actor:user.email,action:purpose==='EXPORT'?'ACCESS_EVIDENCE_EXPORT':'ACCESS_EVIDENCE_READ',resource:'access-observations',resourceId:id,detail:{chunkId:c.id,direction:c.direction,sequence:c.sequence,bytes:c.bytes,sha256:c.sha256}}});assertEvidenceLive(c.capturedAt);return {data:bytes.toString('base64'),encoding:'base64',sha256:c.sha256,bytes:c.bytes,expiresAt:c.expiresAt};
 }
 async health(source:AccessSource,body:unknown){const v=parse(probeHealthInput,body);return this.db.$transaction(async tx=>{await this.lockSource(tx,source);await tx.accessSource.update({where:{id:source.id},data:{health:v,lastReportAt:new Date()}});return{accepted:true};});}
 async cleanup(manual=false){return this.db.$transaction(async tx=>{
  await tx.$queryRaw`SELECT pg_advisory_xact_lock(hashtext(current_schema()),hashtext('access-evidence-capacity'))::text`;
  let deleted=0,indicesDeleted=0;const deadline=Date.now()+5000;let store:AccessEvidenceStore|undefined;
  while(Date.now()<deadline){const rows=await tx.accessEvidenceChunk.findMany({where:{object:{not:null},expiresAt:{lte:new Date()}},take:500});if(!rows.length)break;store=store||this.store();await store.removeMany(rows.map(row=>row.object!));await tx.accessEvidenceChunk.updateMany({where:{id:{in:rows.map(row=>row.id)}},data:{object:null}});deleted+=rows.length;}
  if(process.env.DATA_ENCRYPTION_KEY){const known=await tx.accessEvidenceChunk.findMany({where:{object:{not:null}},select:{object:true}});await (store||this.store()).cleanupOrphans(new Set(known.map(row=>row.object!)),new Date(Date.now()-3600000));}
  const capacity=await effectiveAccessStorage(tx);if(manual||capacity.automaticCleanup){const cutoff=new Date(Date.now()-capacity.indexDays*86400000),old=await tx.accessObservation.findMany({where:{createdAt:{lt:cutoff}},select:{id:true},take:500});if(old.length)indicesDeleted=(await tx.accessObservation.deleteMany({where:{id:{in:old.map(row=>row.id)}}})).count;await tx.$executeRaw`DELETE FROM "AccessEvidenceChunk" WHERE id IN (SELECT c.id FROM "AccessEvidenceChunk" c WHERE c.object IS NULL AND c."capturedAt"<${cutoff} AND NOT EXISTS (SELECT 1 FROM "AccessObservation" o WHERE o."sourceId"=c."sourceId" AND o."eventId"=c."eventId") LIMIT 500)`;}
  return {deleted,indicesDeleted};
 },{timeout:30000});}

}
@Controller('access-observations') @UseGuards(AuthGuard)
export class AccessObservationsController{
 constructor(@Inject(AccessObservationService)private service:AccessObservationService){}
 @Get()list(@Req()r:SecurityRequest,@Query()q:unknown){return this.service.list(r.user,q);}
 @Get(':id')detail(@Req()r:SecurityRequest,@Param('id')id:string){return this.service.detail(r.user,id);}
 @Get(':id/sql') @Header('Cache-Control','no-store')sql(@Req()r:SecurityRequest,@Param('id')id:string){return this.service.sql(r.user,id);}
 @Get(':id/chunks/:chunkId')read(@Req()r:SecurityRequest,@Param('id')id:string,@Param('chunkId')chunkId:string,@Query('purpose')purpose:unknown){return this.service.readChunk(r.user,id,chunkId,parse(z.enum(['READ','EXPORT']).default('READ'),purpose));}
}
@Controller('access-sources') @UseGuards(AuthGuard)
export class AccessSourcesController{
 constructor(@Inject(AccessObservationService)private service:AccessObservationService){}
 @Get()list(@Req()r:SecurityRequest,@Query()q:unknown){return this.service.sources(r.user,q);}
 @Post()create(@Req()r:SecurityRequest,@Body()b:unknown){return this.service.createSource(r.user,b);}
 @Patch(':id')update(@Req()r:SecurityRequest,@Param('id')id:string,@Body()b:unknown){return this.service.updateSource(r.user,id,b);}
 @Post(':id/credential')credential(@Req()r:SecurityRequest,@Param('id')id:string){return this.service.issueCredential(r.user,id);}
 @Post('cleanup')cleanup(@Req()r:SecurityRequest){allow(r,['ADMIN']);return this.service.cleanup(true);}
}
@Controller('access-probe')
export class AccessProbeController{
 constructor(@Inject(AccessObservationService)private service:AccessObservationService){}
 @Get('configuration')async configuration(@Req()r:ProbeRequest){return this.service.ingress(async()=>safeSource(await this.service.probeIdentity(r)));}
 @Post('chunks')async chunk(@Req()r:ProbeRequest,@Body()b:unknown){return this.service.ingress(async()=>this.service.receiveChunk(await this.service.probeIdentity(r),b));}
 @Post('events')async event(@Req()r:ProbeRequest,@Body()b:unknown){return this.service.ingress(async()=>this.service.receiveEvent(await this.service.probeIdentity(r),b));}
 @Post('health')async health(@Req()r:ProbeRequest,@Body()b:unknown){return this.service.ingress(async()=>this.service.health(await this.service.probeIdentity(r),b));}
}
