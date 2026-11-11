import {databaseRuntimePolicyInput,genericDatabaseMetricInput,GenericDatabaseMetric,runtimeEngines} from './database-runtime-contract';
import {BadRequestException,Body,ConflictException,Controller,Get,Inject,Param,Patch,Req,UseGuards} from '@nestjs/common';
import {OperationalMonitor,Prisma} from '@prisma/client';import {z} from 'zod';
import {AuthGuard,allow} from './auth';import {Db} from './db';import type {Platform} from './platform';import {assertEvidence,assertScope} from './scope';import {assertInstanceScope} from './database-instances';import type {SecurityRequest} from './database-contract';import {parse} from './validation';
import {hostMetricInput,hostPolicyInput,postgresMetricInput,postgresPolicyInput,consecutiveExceeded,HostMetric,PostgresMetric} from './monitoring-contract';
const retentionMs=24*3600000;
export function publicMonitor(m:OperationalMonitor){return{id:m.id,kind:m.kind,enabled:m.enabled,version:m.version,config:m.config,status:m.status,lastAttemptAt:m.lastAttemptAt,lastSuccessAt:m.lastSuccessAt,lastError:m.lastError,lastMetric:m.lastMetric,passwordConfigured:!!m.credential};}
export function monitorState(m:OperationalMonitor|null,now=Date.now()){
 if(!m)return'UNCONFIGURED';if(['ERROR','AUTHORIZATION_REVOKED','HISTORY_FULL','UNAVAILABLE','UNSUPPORTED'].includes(m.status))return m.status;if(!m.enabled)return'DISABLED';if(!m.lastSuccessAt)return'WAITING';if(now-m.lastSuccessAt.getTime()>180000)return'STALE';return m.status;
}
export async function monitorView(db:Db,m:OperationalMonitor|null,kind:'HOST'|'POSTGRESQL'|'DATABASE'){
 const samples=m?await db.monitoringSample.findMany({where:{monitorId:m.id,capturedAt:{gte:new Date(Date.now()-retentionMs)},...(kind!=='HOST'?{data:{path:['configurationVersion'],equals:m.version}}:{})},orderBy:{capturedAt:'asc'},take:1440,select:{capturedAt:true,data:true}}):[];
 return{monitor:m?publicMonitor(m):null,state:monitorState(m),samples,retentionHours:24,policy:kind==='HOST'?hostPolicyInput.parse(m?.config||{}):(m?.kind==='DATABASE'?databaseRuntimePolicyInput:postgresPolicyInput).parse((m?.config as {policy?:unknown}|null)?.policy||{}),checkedAt:new Date(),staleAfterSeconds:180};
}
type Point=HostMetric|PostgresMetric|GenericDatabaseMetric;
export async function storeMonitoringPoint(tx:Prisma.TransactionClient,p:Pick<Platform,'ingest'>,monitor:OperationalMonitor,metric:Point){
 const at=new Date(metric.capturedAt),now=Date.now();if(at.getTime()>now+60000)throw new BadRequestException('监控采样时间超前超过60秒，请核对时钟');if(at.getTime()<now-retentionMs)return{stored:false,reason:'EXPIRED'};
 await tx.$queryRaw`SELECT pg_advisory_xact_lock(hashtext(current_schema()),hashtext('monitoring-history'))::text`;
 const current=await tx.operationalMonitor.findUniqueOrThrow({where:{id:monitor.id}}),bucket=new Date(Math.floor(at.getTime()/60000)*60000);
 await tx.monitoringSample.deleteMany({where:{monitorId:monitor.id,capturedAt:{lt:new Date(now-retentionMs)}}});
 let added=false,full=false;
 if(!await tx.monitoringSample.findUnique({where:{monitorId_bucket:{monitorId:monitor.id,bucket}}})){
  const boundary=await tx.monitoringSample.findMany({where:{monitorId:monitor.id},orderBy:{capturedAt:'desc'},skip:1439,take:1,select:{capturedAt:true,id:true}});
  if(boundary[0]){if(at<=boundary[0].capturedAt)return{stored:false,reason:'OLDER_THAN_WINDOW'};await tx.monitoringSample.delete({where:{id:boundary[0].id}});}
  if(await tx.monitoringSample.count()>=144000)full=true;
  else{await tx.monitoringSample.create({data:{monitorId:monitor.id,bucket,capturedAt:at,data:metric}});added=true;}
 }
 const newer=!current.lastSuccessAt||at>current.lastSuccessAt;
 if(newer){const status=full?'HISTORY_FULL':metric.schema==='selfguard-postgres-metrics-v1'?'OK':metric.status;await tx.operationalMonitor.update({where:{id:monitor.id},data:{lastMetric:metric,lastSuccessAt:at,status,lastError:full?'指标历史已达144000点预算；当前值保留，历史采样存在缺口':null,failureCount:0}});}
 if(added&&newer&&at.getTime()>=now-180000)await evaluateMonitor(tx,p,current);
 return{stored:added,reason:full?'HISTORY_FULL':added?'STORED':'DUPLICATE_BUCKET'};
}
async function evaluateMonitor(tx:Prisma.TransactionClient,p:Pick<Platform,'ingest'>,m:OperationalMonitor){
 const host=m.kind==='HOST',policy=host?hostPolicyInput.parse(m.config):(m.kind==='DATABASE'?databaseRuntimePolicyInput:postgresPolicyInput).parse((m.config as {policy:unknown}).policy);
 if(!policy.alertsEnabled)return;
 const rows=(await tx.monitoringSample.findMany({where:{monitorId:m.id,...(!host?{data:{path:['configurationVersion'],equals:m.version}}:{})},orderBy:{capturedAt:'desc'},take:policy.consecutive})).reverse();
 const points=rows.map(row=>({at:row.capturedAt,host:hostMetricInput.safeParse(row.data),db:z.union([postgresMetricInput,genericDatabaseMetricInput]).safeParse(row.data)}));
 const checks:{key:string;title:string;threshold:number;comparison?:'gte'|'lt';values:(number|undefined)[]}[]=[];
 if(host){const v=hostPolicyInput.parse(policy);checks.push({key:'cpu',title:'CPU使用率持续偏高',threshold:v.cpuPercent,values:points.map(p=>p.host.success&&!p.host.data.issues.includes('CONTAINER_NAMESPACE')?p.host.data.cpu.usedPercent:undefined)},{key:'memory',title:'内存使用率持续偏高',threshold:v.memoryPercent,values:points.map(p=>p.host.success&&!p.host.data.issues.includes('CONTAINER_NAMESPACE')?p.host.data.memory?.usedPercent:undefined)});
  const mounts=new Set(points.flatMap(p=>p.host.success&&!p.host.data.issues.includes('CONTAINER_NAMESPACE')?p.host.data.filesystems.map(f=>f.mount):[]));for(const mount of mounts){checks.push({key:'disk:'+mount,title:'文件系统容量持续偏高：'+mount,threshold:v.diskPercent,values:points.map(p=>p.host.success&&!p.host.data.issues.includes('CONTAINER_NAMESPACE')?p.host.data.filesystems.find(f=>f.mount===mount)?.usedPercent:undefined)},{key:'inode:'+mount,title:'文件系统inode使用率持续偏高：'+mount,threshold:v.inodePercent,values:points.map(p=>p.host.success&&!p.host.data.issues.includes('CONTAINER_NAMESPACE')?p.host.data.filesystems.find(f=>f.mount===mount)?.inodeUsedPercent:undefined)});}
 }else{const v=databaseRuntimePolicyInput.parse(policy),values=(key:'connectionsPercent'|'blocking'|'longTransactions'|'longQueries'|'cacheHitPercent')=>points.map(p=>p.db.success?p.db.data[key]:undefined);
  checks.push({key:'connections',title:'数据库连接使用率持续偏高',threshold:v.connectionsPercent,values:values('connectionsPercent')},{key:'blocking',title:'数据库持续存在锁等待',threshold:v.blockingSessions,values:values('blocking')},{key:'transactions',title:'数据库持续存在长事务',threshold:v.longTransactions,values:points.map(p=>p.db.success&&p.db.data.transactionAgeSeconds===v.transactionAgeSeconds?p.db.data.longTransactions:undefined)},{key:'queries',title:'数据库持续存在长查询',threshold:v.longQueries,values:points.map(p=>p.db.success&&p.db.data.queryAgeSeconds===v.queryAgeSeconds?p.db.data.longQueries:undefined)},{key:'cache',title:'数据库缓存命中率持续偏低',threshold:v.cacheHitBelow,comparison:'lt',values:values('cacheHitPercent')});
  checks.push({key:'memory',title:'数据库内存使用率持续偏高',threshold:v.memoryPercent,values:points.map(p=>p.db.success&&'memoryPercent'in p.db.data?p.db.data.memoryPercent:undefined)});
  const deltas=points.map(p=>p.db.success?p.db.data.deadlocksIncrease:undefined);if(consecutiveExceeded(points.map((p,i)=>({at:p.at,value:deltas[i]===undefined?undefined:0})),0,policy.consecutive)&&deltas.reduce<number>((sum,n)=>sum+(n||0),0)>=v.deadlocksIncrease)checks.push({key:'deadlocks',title:'数据库监控窗口内发生死锁',threshold:v.deadlocksIncrease,values:points.map(()=>deltas.reduce<number>((sum,n)=>sum+(n||0),0))});
 }
 for(const check of checks){const values=points.map((p,i)=>({at:p.at,value:check.values[i]}));if(!consecutiveExceeded(values,check.threshold,policy.consecutive,check.comparison))continue;
  const finding=await p.ingest(tx,{externalId:m.id+':'+check.key,title:check.title,kind:'ALERT',severity:'HIGH',source:host?'host-resource-monitor':'database-monitor',...(m.assetId?{assetId:m.assetId}:{}),...(m.instanceId?{instanceId:m.instanceId}:{}),evidence:JSON.stringify({type:'OPERATIONAL_MONITOR',monitorId:m.id,metric:check.key,threshold:check.threshold,comparison:check.comparison||'gte',consecutive:policy.consecutive,samples:values.map(s=>({capturedAt:s.at.toISOString(),value:s.value})),action:'DETECT_ONLY',note:'资源恢复后仍需人工复查，不自动关闭问题'})});
  const owner=m.assetId?(await tx.asset.findUnique({where:{id:m.assetId},select:{owner:true}}))?.owner:m.instanceId?(await tx.databaseInstance.findUnique({where:{id:m.instanceId},select:{owner:true}}))?.owner:null;if(owner)await tx.finding.updateMany({where:{id:finding.id,owner:null},data:{owner}});
 }
}
export async function storeHostMetrics(tx:Prisma.TransactionClient,p:Pick<Platform,'ingest'>,assetId:string,raw:unknown){
 const metric=parse(hostMetricInput,raw);if(Date.parse(metric.capturedAt)>Date.now()+60000)throw new BadRequestException('监控采样时间超前超过60秒');if(Date.parse(metric.capturedAt)<Date.now()-retentionMs)return{stored:false,reason:'EXPIRED'};
 const monitor=await tx.operationalMonitor.upsert({where:{assetId},create:{assetId,kind:'HOST',config:hostPolicyInput.parse({})},update:{}});return storeMonitoringPoint(tx,p,monitor,metric);
}
export async function cleanupMonitoring(db:Db){return db.monitoringSample.deleteMany({where:{capturedAt:{lt:new Date(Date.now()-retentionMs)}}});}
export async function checkHostMonitorHealth(db:Db,p:Pick<Platform,'ingest'>){
 const cutoff=new Date(Date.now()-180000),due=await db.operationalMonitor.findMany({where:{kind:'HOST',enabled:true,lastSuccessAt:{lt:cutoff},asset:{archivedAt:null,tokenHash:{not:null}},OR:[{lastAttemptAt:null},{lastAttemptAt:{lt:new Date(Date.now()-55000)}}]},orderBy:{lastAttemptAt:{sort:'asc',nulls:'first'}},take:100,select:{id:true}});
 for(const candidate of due)await db.$transaction(async tx=>{
  await tx.$queryRaw`SELECT pg_advisory_xact_lock(hashtext(current_schema()),hashtext(${'host-health:'+candidate.id}))::text`;
  const m=await tx.operationalMonitor.findUnique({where:{id:candidate.id},include:{asset:true}});
  if(!m||!m.enabled||!m.asset||m.asset.archivedAt||!m.asset.tokenHash||!m.lastSuccessAt||m.lastSuccessAt>=cutoff)return;
  await tx.operationalMonitor.update({where:{id:m.id},data:{lastAttemptAt:new Date()}});if(!hostPolicyInput.parse(m.config).alertsEnabled)return;
  const finding=await p.ingest(tx,{externalId:m.id+':availability',title:'主机资源监控超过3分钟未收到新样本',kind:'ALERT',severity:'HIGH',source:'host-resource-monitor',assetId:m.asset.id,evidence:JSON.stringify({monitorId:m.id,lastSuccessAt:m.lastSuccessAt,staleAfterSeconds:180,action:'DETECT_ONLY',note:'核查采集服务和网络；恢复采样后仍需人工复查'})});
  if(m.asset.owner)await tx.finding.updateMany({where:{id:finding.id,owner:null},data:{owner:m.asset.owner}});
 });
}
@Controller() @UseGuards(AuthGuard)
export class MonitoringController{
 constructor(@Inject(Db)private db:Db){}
 @Get('assets/:id/resource-monitor')async host(@Req()req:SecurityRequest,@Param('id')id:string){assertEvidence(req.user);await assertScope(this.db,req.user,'assets',id);const m=await this.db.operationalMonitor.findUnique({where:{assetId:id}});const result=await monitorView(this.db,m,'HOST');if(!m){const asset=await this.db.asset.findUniqueOrThrow({where:{id}});return{...result,state:asset.lastSeen?'NEEDS_AGENT_UPDATE':'WAITING'}}return result;}
 @Patch('assets/:id/resource-monitor')async hostPolicy(@Req()req:SecurityRequest,@Param('id')id:string,@Body()body:unknown){allow(req,['ADMIN','OPERATOR']);assertEvidence(req.user);const v=parse(hostPolicyInput.extend({expectedVersion:z.number().int().min(0)}),body);return this.db.$transaction(async tx=>{await assertScope(tx,req.user,'assets',id);await tx.$queryRaw`SELECT pg_advisory_xact_lock(hashtext(current_schema()),hashtext(${'host-monitor:'+id}))::text`;const old=await tx.operationalMonitor.findUnique({where:{assetId:id}});if((old?.version||0)!==v.expectedVersion)throw new ConflictException('监控配置已变化，请刷新');const{expectedVersion,...config}=v;const m=await tx.operationalMonitor.upsert({where:{assetId:id},create:{assetId:id,kind:'HOST',config,version:1},update:{config,version:{increment:1}}});await tx.audit.create({data:{actor:req.user.email,action:'HOST_MONITOR_POLICY',resource:'assets',resourceId:id,detail:{config,version:m.version}}});return publicMonitor(m)});}
 @Get('database-instances/:id/runtime-monitor')async database(@Req()req:SecurityRequest,@Param('id')id:string){assertEvidence(req.user);const instance=await assertInstanceScope(this.db,req.user,id);const m=await this.db.operationalMonitor.findUnique({where:{instanceId:id}});return{...await monitorView(this.db,m,'POSTGRESQL'),engine:instance.engine,supported:runtimeEngines.includes(instance.engine as typeof runtimeEngines[number]),endpoints:instance.endpoints};}
}
