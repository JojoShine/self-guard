import {BadRequestException,Body,ConflictException,Controller,ForbiddenException,Get,Headers,HttpException,Inject,NotFoundException,Param,Patch,Post,Query,Req,UnauthorizedException,UseGuards} from '@nestjs/common';
import {NetworkSensor,Prisma,User} from '@prisma/client';
import {randomBytes} from 'node:crypto';
import {z} from 'zod';
import {Db} from './db';
import {AuthGuard} from './auth';
import {assertEvidence,assertScope,assetScope} from './scope';
import {parse} from './validation';
import {hashToken} from './security';
import {configuredPlatform} from './agent-platform';
import {Platform} from './platform';
import {networkSensorInput,networkSensorPatch,networkEventQuery,networkBatchInput,networkHealthInput,NetworkBatch} from './network-sensor-contract';

type Request={user:User};
type Tx=Prisma.TransactionClient;
const retentionMs=7*24*3600000;
const receiptRetentionMs=8*24*3600000;
function publicSensor(row:NetworkSensor){const {tokenHash,...value}=row;return {...value,hasCredential:!!tokenHash}}
// Object key order is not part of an event's identity, but every value is.
export function networkContentHash(value:unknown):string {
 function canonical(v:unknown):unknown {if(Array.isArray(v))return v.map(canonical);if(v&&typeof v==='object')return Object.fromEntries(Object.entries(v).sort(([a],[b])=>a.localeCompare(b)).map(([k,x])=>[k,canonical(x)]));return v}
 return hashToken(JSON.stringify(canonical(value)));
}
async function liveWriter(tx:Tx,id:string){
 await tx.$queryRaw`SELECT id FROM "User" WHERE id=${id} FOR SHARE`;
 const user=await tx.user.findUnique({where:{id}});
 if(!user||user.disabled||!['ADMIN','OPERATOR'].includes(user.role))throw new ForbiddenException('来源所有者当前授权已失效');
 assertEvidence(user);return user;
}
async function authorizedAsset(tx:Tx,user:User,assetId:string){
 await tx.$queryRaw`SELECT id FROM "Asset" WHERE id=${assetId} FOR SHARE`;
 await assertScope(tx,user,'assets',assetId);
 const asset=await tx.asset.findUniqueOrThrow({where:{id:assetId}});
 if(asset.archivedAt||!asset.tokenHash)throw new ForbiddenException('来源需要仍已接入且未归档的资产');
 return asset;
}
async function lockSensor(tx:Tx,id:string){
 await tx.$queryRaw`SELECT id FROM "NetworkSensor" WHERE id=${id} FOR UPDATE`;
 const row=await tx.networkSensor.findUnique({where:{id}});if(!row)throw new NotFoundException('网络来源不存在');return row;
}
export async function authenticateSensor(tx:Tx,id:string,authorization:string|undefined){
 const row=await lockSensor(tx,id);
 const token=/^Bearer ([A-Za-z0-9_-]{43})$/.exec(authorization||'')?.[1];
 if(!row.enabled||!token||!row.tokenHash||hashToken(token)!==row.tokenHash)throw new UnauthorizedException('网络来源凭据无效或来源已停用');
 const owner=await liveWriter(tx,row.ownerId);await authorizedAsset(tx,owner,row.assetId);return row;
}
export async function createNetworkSensor(db:Db,userId:string,body:unknown){const input=parse(networkSensorInput,body);return db.$transaction(async tx=>{
 const user=await liveWriter(tx,userId);await authorizedAsset(tx,user,input.assetId);
 const row=await tx.networkSensor.create({data:{...input,ownerId:user.id}});
 await tx.audit.create({data:{actor:user.email,action:'NETWORK_SENSOR_CREATE',resource:'network-sensors',resourceId:row.id,detail:{assetId:row.assetId,version:row.version}}});return publicSensor(row);
});}
export async function patchNetworkSensor(db:Db,userId:string,id:string,body:unknown){const {expectedUpdatedAt,...input}=parse(networkSensorPatch,body);return db.$transaction(async tx=>{
 const row=await lockSensor(tx,id),user=await liveWriter(tx,userId);await authorizedAsset(tx,user,row.assetId);
 if(row.updatedAt.getTime()!==Date.parse(expectedUpdatedAt))throw new ConflictException('来源已被其他操作更新，请刷新后重试');
 const updated=await tx.networkSensor.update({where:{id},data:{...input,ownerId:user.id,tokenHash:null,updatedAt:new Date(Math.max(Date.now(),row.updatedAt.getTime()+1)),version:{increment:1}}});
 await tx.audit.create({data:{actor:user.email,action:'NETWORK_SENSOR_UPDATE',resource:'network-sensors',resourceId:id,detail:{assetId:row.assetId,version:updated.version,enabled:updated.enabled}}});return publicSensor(updated);
});}
export async function issueSensorCredential(db:Db,userId:string,id:string){
 const platform=await configuredPlatform(db);if(!platform)throw new BadRequestException('请先配置并验证平台接入入口');
 return db.$transaction(async tx=>{const row=await lockSensor(tx,id),user=await liveWriter(tx,userId);await authorizedAsset(tx,user,row.assetId);
 const token=randomBytes(32).toString('base64url');await tx.networkSensor.update({where:{id},data:{tokenHash:hashToken(token),ownerId:user.id,updatedAt:new Date(Math.max(Date.now(),row.updatedAt.getTime()+1)),version:{increment:1}}});
 await tx.audit.create({data:{actor:user.email,action:'NETWORK_SENSOR_CREDENTIAL',resource:'network-sensors',resourceId:id,detail:{assetId:row.assetId,version:row.version+1}}});
 return {schema:'selfguard-suricata-config-v1',server:platform.server,sensorId:id,assetId:row.assetId,token,evePath:row.evePath,...(row.ruleFile?{ruleFile:row.ruleFile}:{}),...(row.expectedRuleSha256?{expectedRuleSha256:row.expectedRuleSha256}:{}),...(platform.caCertificate?{caCertificate:platform.caCertificate}:{}),identityPath:'/var/lib/selfguard-agent/identity.json',stateDir:'/var/lib/selfguard-suricata/'+id,readFromStart:false};
 });
}
export function validateNetworkBatch(body:unknown,now=Date.now()){
 const batch=parse(networkBatchInput,body);
 if(Date.parse(batch.health.observedAt)>now+300000||batch.health.rulesModifiedAt&&Date.parse(batch.health.rulesModifiedAt)>now+300000||batch.events.some(e=>Date.parse(e.occurredAt)>now+300000))throw new BadRequestException('事件或健康时间不能超过当前时间5分钟');
 return batch;
}
export async function storeNetworkBatch(tx:Tx,platform:Pick<Platform,'ingest'>,sensor:NetworkSensor,batch:NetworkBatch){
 const contentSha256=networkContentHash(batch),now=new Date(),cutoff=new Date(now.getTime()-retentionMs);
 const previous=await tx.networkSensorBatch.findUnique({where:{sensorId_batchId:{sensorId:sensor.id,batchId:batch.batchId}}});
 if(previous){if(previous.contentSha256!==contentSha256)throw new ConflictException('批次标识已用于不同内容');return previous.result}
 await cleanupSensorReceipts(tx,sensor.id);
 if(await tx.networkSensorBatch.count({where:{sensorId:sensor.id}})>=100000)throw new HttpException('批次确认记录已达预算，请保留待确认批次并稍后重试',429);
 let identityCount=await tx.networkSensorEventIdentity.count({where:{sensorId:sensor.id}});
 const live=batch.mode==='LIVE';
 let accepted=0,duplicates=0,expired=0,lastEvent=sensor.lastEventAt,lastStats=sensor.lastStatsAt,stats:Prisma.InputJsonValue|undefined=undefined;
 for(const event of batch.events){
  const eventHash=networkContentHash(event),old=await tx.networkSensorEventIdentity.findUnique({where:{sensorId_eventId:{sensorId:sensor.id,eventId:event.eventId}}});
  if(old){if(old.contentSha256!==eventHash)throw new ConflictException('事件标识已用于不同内容');duplicates++;continue}
  if(identityCount>=100000)throw new HttpException('事件幂等记录已达预算，请保留待确认批次并稍后重试',429);
  identityCount++;
  await tx.networkSensorEventIdentity.create({data:{sensorId:sensor.id,eventId:event.eventId,contentSha256:eventHash}});
  const occurredAt=new Date(event.occurredAt);if(occurredAt<cutoff){expired++;continue}
  const row=await tx.networkSensorEvent.create({data:{...event,occurredAt,mode:batch.mode,sensorId:sensor.id,assetId:sensor.assetId,contentSha256:eventHash}});
  if(event.eventType==='alert'){
   const alert=event.metadata.alert!;
   const finding=await platform.ingest(tx,{source:'suricata',externalId:sensor.id+':'+event.eventId,title:alert.signature.trim()||'Suricata alert '+alert.signatureId,kind:'ALERT',severity:alert.severity===1?'HIGH':alert.severity===2?'MEDIUM':alert.severity===3?'LOW':'INFO',evidence:JSON.stringify({...event,sensorId:sensor.id,eventRecordId:row.id,assetRole:'SENSOR_HOST',action:'DETECT_ONLY',engineAction:alert.action,mode:batch.mode})},sensor.assetId);
   await tx.networkSensorEvent.update({where:{id:row.id},data:{findingId:finding.id}});
  }
  accepted++;if(!lastEvent||occurredAt>lastEvent)lastEvent=occurredAt;
  if(live&&event.eventType==='stats'&&(!lastStats||occurredAt>lastStats)){lastStats=occurredAt;stats=event.metadata.stats!}
 }
 // Replay can import historical events, but cannot establish reader or engine liveness.
 const previousHealth=networkHealthInput.safeParse(sensor.health);
 const healthIsNew=live&&Date.parse(batch.health.observedAt)>=now.getTime()-300000&&(!previousHealth.success||Date.parse(batch.health.observedAt)>=Date.parse(previousHealth.data.observedAt));
 // Heartbeats must not invalidate an in-progress configuration edit.
 await tx.networkSensor.update({where:{id:sensor.id},data:{updatedAt:sensor.updatedAt,lastEventAt:lastEvent,lastStatsAt:lastStats,stats,lastMode:batch.mode,...(healthIsNew?{lastReportedAt:now,health:batch.health}:{})}});
 await tx.networkSensorEvent.deleteMany({where:{sensorId:sensor.id,occurredAt:{lt:cutoff}}});
 const boundary=await tx.networkSensorEvent.findMany({where:{sensorId:sensor.id},orderBy:[{occurredAt:'desc'},{id:'asc'}],skip:49999,take:1,select:{id:true,occurredAt:true}});
 if(boundary[0])await tx.networkSensorEvent.deleteMany({where:{sensorId:sensor.id,OR:[{occurredAt:{lt:boundary[0].occurredAt}},{occurredAt:boundary[0].occurredAt,id:{gt:boundary[0].id}}]}});
 const result={sensorId:sensor.id,batchId:batch.batchId,persisted:true,accepted,duplicates,expired};
 await tx.networkSensorBatch.create({data:{sensorId:sensor.id,batchId:batch.batchId,contentSha256,result}});
 return result;
}
export async function listSensorEvents(db:Db,user:User,query:unknown){assertEvidence(user);const q=parse(networkEventQuery,query);const cutoff=new Date(Date.now()-retentionMs);const where:Prisma.NetworkSensorEventWhereInput={asset:{is:assetScope(user)},...(q.sensorId?{sensorId:q.sensorId}:{}),...(q.assetId?{assetId:q.assetId}:{}),...(q.flowId?{flowId:q.flowId}:{}),...(q.eventType?{eventType:q.eventType}:{}),occurredAt:{gte:q.from?new Date(Math.max(cutoff.getTime(),Date.parse(q.from))):cutoff,...(q.to?{lte:new Date(q.to)}:{})}};
 const [items,total]=await Promise.all([db.networkSensorEvent.findMany({where,orderBy:[{occurredAt:'desc'},{id:'asc'}],skip:(q.page-1)*q.pageSize,take:q.pageSize,include:{sensor:{select:{id:true,name:true,assetId:true}}}}),db.networkSensorEvent.count({where})]);return {items,total,page:q.page,pageSize:q.pageSize,retentionDays:7,flowWarning:'flow ID 仅用于同一来源及指定时间范围内关联，跨引擎重启可能重复'};
}
@Controller('network-sensors') @UseGuards(AuthGuard)
export class NetworkSensorsController{
 constructor(@Inject(Db)private db:Db){}
 @Get()async list(@Req()req:Request,@Query()query:unknown){assertEvidence(req.user);const q=parse(z.object({assetId:z.string().uuid().optional()}).strict(),query);const items=await this.db.networkSensor.findMany({where:{asset:{is:assetScope(req.user)},...(q.assetId?{assetId:q.assetId}:{})},orderBy:[{createdAt:'desc'},{id:'asc'}],include:{asset:{select:{hostname:true}}}});return {items:items.map(row=>({...publicSensor(row),asset:row.asset}))}}
 @Post()create(@Req()req:Request,@Body()body:unknown){return createNetworkSensor(this.db,req.user.id,body)}
 @Patch(':id')patch(@Req()req:Request,@Param('id')id:string,@Body()body:unknown){return patchNetworkSensor(this.db,req.user.id,id,body)}
 @Post(':id/credential')credential(@Req()req:Request,@Param('id')id:string){return issueSensorCredential(this.db,req.user.id,id)}
 @Get('events')events(@Req()req:Request,@Query()query:unknown){return listSensorEvents(this.db,req.user,query)}
 @Get('events/:id')async event(@Req()req:Request,@Param('id')id:string){assertEvidence(req.user);const row=await this.db.networkSensorEvent.findFirst({where:{id,asset:{is:assetScope(req.user)},occurredAt:{gte:new Date(Date.now()-retentionMs)}},include:{sensor:{select:{id:true,name:true,assetId:true}}}});if(!row)throw new NotFoundException('事件不存在或已过期');return row}
}
@Controller('sensor-ingest')
export class SensorIngestController{
 constructor(@Inject(Db)private db:Db,@Inject(Platform)private platform:Platform){}
 @Get(':id/config')config(@Param('id')id:string,@Headers('authorization')auth:string|undefined){return this.db.$transaction(async tx=>{const s=await authenticateSensor(tx,id,auth);return {sensorId:s.id,assetId:s.assetId,enabled:true,version:s.version}})}
 @Post(':id/batches')batches(@Param('id')id:string,@Headers('authorization')auth:string|undefined,@Body()body:unknown){const batch=validateNetworkBatch(body);return this.db.$transaction(async tx=>{const s=await authenticateSensor(tx,id,auth);return storeNetworkBatch(tx,this.platform,s,batch)},{timeout:30000})}
}

// Query endpoints also enforce the cutoff, including while a source is offline.
async function cleanupSensorReceipts(db:Tx,sensorId?:string){
 const createdAt={lt:new Date(Date.now()-receiptRetentionMs)};
 await db.networkSensorBatch.deleteMany({where:{...(sensorId?{sensorId}:{}),createdAt}});
 await db.networkSensorEventIdentity.deleteMany({where:{...(sensorId?{sensorId}:{}),createdAt}});
}
// Metadata and dedup receipts have independent bounded retention. Receipts retain
// a day of overlap beyond the accepted event horizon; capacity exhaustion applies
// backpressure instead of discarding identities for recent accepted events.
export async function cleanupNetworkSensorEvents(db:Db){await db.networkSensorEvent.deleteMany({where:{occurredAt:{lt:new Date(Date.now()-retentionMs)}}});await cleanupSensorReceipts(db);}
