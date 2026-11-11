import {BadRequestException,Body,ConflictException,Controller,Inject,Injectable,Logger,Param,Patch,Post,Req,UseGuards} from '@nestjs/common';
import {OperationalMonitor,Prisma} from '@prisma/client';import {Client} from 'pg';import {createHash,randomUUID,X509Certificate} from 'node:crypto';import {z} from 'zod';
import {Db} from './db';import {Platform} from './platform';import {AuthGuard,allow} from './auth';import {assertEvidence,dataScopeInput} from './scope';import {assertInstanceScope,instanceInput} from './database-instances';import {seal,unseal} from './maintenance';import {parse} from './validation';import type {SecurityRequest} from './database-contract';
import {databaseRuntimeInput,genericDatabaseMetricInput,runtimeEngines,GenericDatabaseMetric} from './database-runtime-contract';import {readMysqlMetrics,readRedisMetrics} from './database-native-metrics';import {readVendorDatabaseMetrics} from './database-vendor-metrics';
import {postgresMonitorInput,postgresMetricInput,postgresRates,PostgresMetric} from './monitoring-contract';import {publicMonitor,monitorView,storeMonitoringPoint,cleanupMonitoring,checkHostMonitorHealth} from './monitoring';
type Config=z.infer<typeof postgresMonitorInput>|z.infer<typeof databaseRuntimeInput>;
function engineOf(m:OperationalMonitor){return m.kind==='POSTGRESQL'?'postgresql':z.enum(runtimeEngines).parse((m.config as {engine?:unknown}).engine)}
function storedConfig(m:OperationalMonitor):Config{if(m.kind==='POSTGRESQL')return postgresMonitorInput.parse(m.config);const {engine,...connection}=m.config as Record<string,Prisma.JsonValue>;return databaseRuntimeInput.parse(connection)}
export function monitorPublicConfig(config:Config){const{password,...publicConfig}=config;return publicConfig;}
function binding(instanceId:string,c:Config,engine='postgresql'){return createHash('sha256').update(JSON.stringify([instanceId,c.address,c.port,c.database,c.username,c.tls,c.caCertificate,...(engine==='postgresql'?[]:[engine])])).digest('hex');}
export function sealMonitorPassword(instanceId:string,config:Config,password:string,engine='postgresql'){return seal(JSON.stringify({binding:binding(instanceId,config,engine),password}));}
export function openMonitorPassword(instanceId:string,config:Config,cipher:string,engine='postgresql'){const raw:unknown=JSON.parse(unseal(cipher));const v=z.object({binding:z.string(),password:z.string()}).strict().parse(raw);if(v.binding!==binding(instanceId,config,engine))throw new BadRequestException('监控凭据与当前实例入口或TLS配置不匹配，请重新填写密码');return v.password;}
export function validateMonitorCA(value:string){if(!value)return;const blocks=value.match(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g)||[];if(!blocks.length||value.replace(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g,'').trim())throw new BadRequestException('只能提供PEM格式CA证书，不接受私钥或其他内容');try{for(const block of blocks)new X509Certificate(block)}catch{throw new BadRequestException('请提供有效PEM格式的可信CA证书')}}
function targetRegistered(instance:{engine:string;archivedAt:Date|null;endpoints:Prisma.JsonValue},config:Config,engine='postgresql'){return instance.engine===engine&&!instance.archivedAt&&instanceInput.shape.endpoints.parse(instance.endpoints).some(e=>e.address===config.address&&e.port===config.port);}
class MonitorReadError extends Error{constructor(readonly safeCode:string){super(safeCode);}}
function safeFailure(error:unknown){if(error instanceof Error){if(error.message==='DATABASE_STATISTICS_UNAVAILABLE')return'连接身份可验证，但没有取得任何受支持的运行统计；请核对只读统计权限和版本';if(error.message==='DM_TLS_VERIFICATION_UNAVAILABLE')return'当前达梦驱动无法验证服务器证书及主机身份，正式连接未启用；请提供支持严格TLS验证的受信任客户端';if(error.message==='DATABASE_DRIVER_UNAVAILABLE')return'当前部署尚未提供此数据库的受信任驱动，请先完成驱动部署';if(error.message==='DATABASE_ENGINE_MISMATCH')return'实际数据库产品身份与登记引擎不匹配，未保存采样';if(error.message==='ORACLE_THIN_VERSION_UNSUPPORTED')return'当前Oracle Thin驱动不支持该版本；11g需要独立部署并验收的Oracle Client';if(error.message==='ORACLE_CUSTOM_CA_UNAVAILABLE')return'当前Node运行时不支持隔离设置Oracle可信CA，未绕过证书验证';}const code=error instanceof Error&&/^WRONGPASS|^NOAUTH/.test(error.message)?'WRONGPASS':error instanceof Error&&/^NOPERM/.test(error.message)?'NOPERM':error instanceof Error&&'safeCode'in error?String(error.safeCode):typeof error==='object'&&error!==null&&'code'in error?String(error.code):'';if(['28P01','28000'].includes(code))return'监控账号认证失败，请核对独立账号与密码';if(code==='42501'||code==='STATS_PERMISSION')return'监控账号缺少pg_read_all_stats统计权限，请由数据库管理员授予最小读取权限';if(code==='STATISTICS_DISABLED')return'数据库统计采集未开启，当前不能提供完整运行指标';if(['DEPTH_ZERO_SELF_SIGNED_CERT','SELF_SIGNED_CERT_IN_CHAIN','UNABLE_TO_VERIFY_LEAF_SIGNATURE','ERR_TLS_CERT_ALTNAME_INVALID','CERT_HAS_EXPIRED','UNABLE_TO_GET_ISSUER_CERT_LOCALLY'].includes(code))return'TLS证书验证失败，请核对入口域名、有效期和可信CA；未绕过验证';if(code==='UNSUPPORTED_VERSION')return'当前数据库产品身份或版本尚未支持，请核对实际版本与接入能力';if(['ER_ACCESS_DENIED_ERROR','WRONGPASS','NOAUTH'].includes(code))return'监控账号认证失败，请核对独立账号与密码';if(['ER_SPECIFIC_ACCESS_DENIED_ERROR','ER_TABLEACCESS_DENIED_ERROR','NOPERM'].includes(code))return'监控账号缺少所需只读统计权限';if(code==='MYSQL_TLS_DNS_REQUIRED')return'MySQL严格TLS验证当前需要登记证书匹配的DNS入口，请先登记域名后重试';if(code==='57014')return'只读监控查询超时，请核对数据库负载与连接预算';return'数据库只读检查失败，请核对网络、登记入口、账号和采集预算；未返回连接秘密';}

export async function readPostgresMetrics(config:Config,password:string,configurationVersion:number,previous?:PostgresMetric):Promise<PostgresMetric>{
 const started=performance.now(),client=new Client({host:config.address,port:config.port,database:config.database,user:config.username,password,application_name:'selfguard-operational-monitor',connectionTimeoutMillis:3000,query_timeout:5000,statement_timeout:3000,ssl:config.tls?{rejectUnauthorized:true,...(config.caCertificate?{ca:config.caCertificate}:{})}:false});
 try{
  await client.connect();await client.query('BEGIN READ ONLY');await client.query("SET LOCAL search_path = pg_catalog");
  const permission=await client.query<{allowed:boolean;activities:string;counts:string}>("SELECT pg_has_role(current_user,'pg_read_all_stats','USAGE') AS allowed,current_setting('track_activities') AS activities,current_setting('track_counts') AS counts");if(!permission.rows[0].allowed)throw new MonitorReadError('STATS_PERMISSION');if(permission.rows[0].activities!=='on'||permission.rows[0].counts!=='on')throw new MonitorReadError('STATISTICS_DISABLED');
  const result=await client.query<Record<string,unknown>>(`SELECT current_database() AS database,current_setting('server_version') AS version,current_setting('max_connections')::int AS "maxConnections",
   (SELECT count(*) FROM pg_stat_activity WHERE backend_type='client backend' AND pid<>pg_backend_pid()) AS connections,
   (SELECT count(*) FROM pg_stat_activity WHERE backend_type='client backend' AND pid<>pg_backend_pid() AND state='active') AS active,
   (SELECT count(*) FROM pg_stat_activity WHERE backend_type='client backend' AND pid<>pg_backend_pid() AND state LIKE 'idle in transaction%') AS "idleInTransaction",
   (SELECT count(*) FROM pg_stat_activity WHERE backend_type='client backend' AND pid<>pg_backend_pid() AND state='active' AND wait_event_type IS NOT NULL) AS waiting,
   (SELECT count(*) FROM pg_stat_activity WHERE backend_type='client backend' AND pid<>pg_backend_pid() AND state='active' AND wait_event_type='Lock') AS blocking,
   (SELECT count(*) FROM pg_stat_activity WHERE backend_type='client backend' AND pid<>pg_backend_pid() AND xact_start<now()-make_interval(secs=>$1)) AS "longTransactions",
   (SELECT count(*) FROM pg_stat_activity WHERE backend_type='client backend' AND pid<>pg_backend_pid() AND state='active' AND query_start<now()-make_interval(secs=>$2)) AS "longQueries",
   COALESCE((SELECT greatest(0,max(extract(epoch FROM now()-xact_start))) FROM pg_stat_activity WHERE backend_type='client backend' AND pid<>pg_backend_pid()),0) AS "longestTransactionSeconds",
   COALESCE((SELECT greatest(0,max(extract(epoch FROM now()-query_start))) FROM pg_stat_activity WHERE backend_type='client backend' AND pid<>pg_backend_pid() AND state='active'),0) AS "longestQuerySeconds",
   xact_commit AS commits,xact_rollback AS rollbacks,deadlocks,blks_hit AS "blocksHit",blks_read AS "blocksRead",
   pg_database_size(current_database()) AS "databaseBytes",COALESCE(stats_reset,pg_postmaster_start_time())::text || ':' || pg_postmaster_start_time()::text || ':' || current_database() AS "resetAt"
   FROM pg_stat_database WHERE datname=current_database()`,[config.policy.transactionAgeSeconds,config.policy.queryAgeSeconds]);
  await client.query('COMMIT');const r=result.rows[0];if(!r||!/^([1-9][0-9]*)\./.test(String(r.version))||Number(String(r.version).split('.')[0])<14)throw new MonitorReadError('UNSUPPORTED_VERSION');
  const n=(key:string)=>{const value=Number(r[key]);if(!Number.isFinite(value)||value<0||value>Number.MAX_SAFE_INTEGER)throw new MonitorReadError('INVALID_COUNTER');return value};
  const blocksHit=n('blocksHit'),blocksRead=n('blocksRead'),maxConnections=n('maxConnections'),connections=n('connections');
  const metric=postgresMetricInput.parse({schema:'selfguard-postgres-metrics-v1',configurationVersion,capturedAt:new Date().toISOString(),database:String(r.database),version:String(r.version),resetAt:createHash('sha256').update(String(r.resetAt)).digest('hex'),transactionAgeSeconds:config.policy.transactionAgeSeconds,queryAgeSeconds:config.policy.queryAgeSeconds,maxConnections,connections,connectionsPercent:Math.min(100,100*connections/maxConnections),active:n('active'),idleInTransaction:n('idleInTransaction'),waiting:n('waiting'),blocking:n('blocking'),longTransactions:n('longTransactions'),longQueries:n('longQueries'),longestTransactionSeconds:n('longestTransactionSeconds'),longestQuerySeconds:n('longestQuerySeconds'),commits:n('commits'),rollbacks:n('rollbacks'),deadlocks:n('deadlocks'),databaseBytes:n('databaseBytes'),...(blocksHit+blocksRead>0?{cacheHitPercent:100*blocksHit/(blocksHit+blocksRead)}:{}),latencyMs:performance.now()-started});return{...metric,...postgresRates(previous?.configurationVersion===configurationVersion?previous:undefined,metric)};
 }finally{await client.end();}
}

@Injectable()
export class PostgresMonitoringService{
 private timer?:ReturnType<typeof setInterval>;private running=false;
 constructor(@Inject(Db)private db:Db,@Inject(Platform)private platform:Platform){}
 onModuleInit(){this.timer=setInterval(()=>void this.tick(),60000);this.timer.unref();}
 onModuleDestroy(){if(this.timer)clearInterval(this.timer);}
 private async authorized(tx:Prisma.TransactionClient,m:OperationalMonitor,config:Config){
  if(!m.instanceId||!m.ownerId)return false;const owner=await tx.user.findUnique({where:{id:m.ownerId}}),instance=await tx.databaseInstance.findUnique({where:{id:m.instanceId}});if(!owner||owner.disabled||!['ADMIN','ANALYST'].includes(owner.role)||!instance||!targetRegistered(instance,config,engineOf(m)))return false;
  try{const user={...owner,dataScope:parse(dataScopeInput,owner.dataScope||{})};assertEvidence(user);await assertInstanceScope(tx,user,m.instanceId);return true}catch(error){if(error instanceof Error&&'getStatus'in error)return false;throw error;}
 }
 async poll(id:string,manual=false){
  const token=randomUUID(),now=new Date();const claimed=await this.db.$transaction(async tx=>{
   const m=await tx.operationalMonitor.findUnique({where:{id}});if(!m||!['POSTGRESQL','DATABASE'].includes(m.kind)||(!manual&&!m.enabled))return null;if(m.leaseUntil&&m.leaseUntil>now)return null;const config=storedConfig(m);
   if(!await this.authorized(tx,m,config)){await tx.operationalMonitor.update({where:{id},data:{enabled:false,status:'AUTHORIZATION_REVOKED',lastError:'原监控授权、实例入口或账号权限范围已变化，请重新配置'}});return null;}
   const changed=await tx.operationalMonitor.updateMany({where:{id,version:m.version,OR:[{leaseUntil:null},{leaseUntil:{lte:now}}]},data:{leaseToken:token,leaseUntil:new Date(now.getTime()+30000),lastAttemptAt:now}});return changed.count?{m,config}:null;
  });
  if(!claimed)return{checked:false};let metric:PostgresMetric|GenericDatabaseMetric|undefined,failure:string|undefined;
  try{if(!claimed.m.credential)throw new MonitorReadError('MISSING_CREDENTIAL');const engine=engineOf(claimed.m),password=openMonitorPassword(claimed.m.instanceId!,claimed.config,claimed.m.credential,engine);if(engine==='postgresql'){const previous=postgresMetricInput.safeParse(claimed.m.lastMetric);metric=await readPostgresMetrics(claimed.config,password,claimed.m.version,previous.success?previous.data:undefined)}else{const previous=genericDatabaseMetricInput.safeParse(claimed.m.lastMetric),config=databaseRuntimeInput.parse(claimed.config),prior=previous.success?previous.data:undefined;metric=engine==='mysql'?await readMysqlMetrics(config,password,claimed.m.version,prior):engine==='redis'?await readRedisMetrics(config,password,claimed.m.version,prior):await readVendorDatabaseMetrics(engine,config,password,claimed.m.version,prior);}}catch(error){failure=safeFailure(error);}
  return this.db.$transaction(async tx=>{
   const m=await tx.operationalMonitor.findUniqueOrThrow({where:{id}});if(m.leaseToken!==token||m.version!==claimed.m.version)return{checked:false};
   if(!await this.authorized(tx,m,claimed.config)){await tx.operationalMonitor.update({where:{id},data:{enabled:false,status:'AUTHORIZATION_REVOKED',lastError:'采集期间授权发生变化，结果未保存',leaseToken:null,leaseUntil:null}});return{checked:false};}
   if(metric)await storeMonitoringPoint(tx,this.platform,m,metric);
   else{const failures=m.failureCount+1;await tx.operationalMonitor.update({where:{id},data:{status:'ERROR',lastError:failure||'只读检查失败',failureCount:failures}});if(failures>=3&&claimed.config.policy.alertsEnabled)await this.platform.ingest(tx,{externalId:m.id+':availability',title:'数据库运行监控连续检查失败',kind:'ALERT',severity:'HIGH',source:'database-monitor',instanceId:m.instanceId!,evidence:JSON.stringify({monitorId:m.id,failures,lastSuccessAt:m.lastSuccessAt,reason:failure,action:'DETECT_ONLY'})});}
   await tx.operationalMonitor.updateMany({where:{id,leaseToken:token},data:{leaseToken:null,leaseUntil:null}});return{checked:true,success:!!metric};
  },{timeout:15000});
 }
 async tick(){if(this.running)return;this.running=true;try{
  await cleanupMonitoring(this.db);await checkHostMonitorHealth(this.db,this.platform);
  const cutoff=new Date(Date.now()-55000),deadline=Date.now()+50000;
  while(Date.now()<deadline){
   const due=await this.db.operationalMonitor.findMany({where:{kind:{in:['POSTGRESQL','DATABASE']},enabled:true,AND:[{OR:[{lastAttemptAt:null},{lastAttemptAt:{lte:cutoff}}]},{OR:[{leaseUntil:null},{leaseUntil:{lte:new Date()}}]}]},orderBy:{lastAttemptAt:{sort:'asc',nulls:'first'}},take:10,select:{id:true}});
   if(!due.length)break;
   for(let i=0;i<due.length;i+=2)await Promise.all(due.slice(i,i+2).map(m=>this.poll(m.id)));
  }
 }catch{Logger.warn('Database monitoring cycle incomplete; explicit states and last successful samples remain available','DatabaseMonitoring')}finally{this.running=false}}

}
@Controller('database-instances') @UseGuards(AuthGuard)
export class PostgresMonitoringController{
 constructor(@Inject(Db)private db:Db,@Inject(PostgresMonitoringService)private service:PostgresMonitoringService){}
 @Patch(':id/runtime-monitor')async configure(@Req()req:SecurityRequest,@Param('id')id:string,@Body()body:unknown){
  allow(req,['ADMIN','ANALYST']);assertEvidence(req.user);if(!req.user.id)throw new BadRequestException('缺少登录身份');const request=parse(z.object({connection:z.unknown(),expectedVersion:z.number().int().min(0)}).strict(),body),instance=await assertInstanceScope(this.db,req.user,id),engine=z.enum(runtimeEngines).parse(instance.engine);const v={expectedVersion:request.expectedVersion,connection:engine==='postgresql'?parse(postgresMonitorInput,request.connection):parse(databaseRuntimeInput,request.connection)};if(engine!=='redis'&&(!v.connection.username||!v.connection.database))throw new BadRequestException('请填写数据库名称及独立监控账号');if(engine==='redis'&&!/^\d{1,5}$/.test(v.connection.database||'0'))throw new BadRequestException('Redis数据库必须为数字编号');
  validateMonitorCA(v.connection.caCertificate);
  return this.db.$transaction(async tx=>{await tx.$queryRaw`SELECT pg_advisory_xact_lock(hashtext(current_schema()),hashtext(${'postgres-monitor:'+id}))::text`;const instance=await assertInstanceScope(tx,req.user,id);if(!targetRegistered(instance,v.connection,engine))throw new BadRequestException('监控只支持登记且未归档的数据库实例入口，请先核对实例地址和端口');
   const old=await tx.operationalMonitor.findUnique({where:{instanceId:id}});if((old?.version||0)!==v.expectedVersion)throw new ConflictException('监控配置已变化，请刷新');const config={...monitorPublicConfig(v.connection),...(engine==='postgresql'?{}:{engine})};let credential=old?.credential;
   if(v.connection.password)credential=sealMonitorPassword(id,v.connection,v.connection.password,engine);else{if(!credential)throw new BadRequestException('首次配置需要独立监控账号密码');openMonitorPassword(id,v.connection,credential,engine);}
   const data={ownerId:req.user.id,config,credential,enabled:config.enabled,status:config.enabled?'WAITING':'DISABLED',lastError:null,leaseToken:null,leaseUntil:null,failureCount:0,lastSuccessAt:null,lastMetric:Prisma.DbNull,lastAttemptAt:null};
   const monitor=await tx.operationalMonitor.upsert({where:{instanceId:id},create:{kind:engine==='postgresql'?'POSTGRESQL':'DATABASE',instanceId:id,...data,version:1},update:{...data,kind:engine==='postgresql'?'POSTGRESQL':'DATABASE',version:{increment:1}}});
   await tx.audit.create({data:{actor:req.user.email,action:'DATABASE_MONITOR_CONFIG',resource:'database-instances',resourceId:id,detail:{address:config.address,port:config.port,database:config.database,username:config.username,tls:config.tls,enabled:config.enabled,version:monitor.version,passwordChanged:!!v.connection.password}}});return publicMonitor(monitor);
  });
 }
 @Post(':id/runtime-monitor/check')async check(@Req()req:SecurityRequest,@Param('id')id:string){allow(req,['ADMIN','ANALYST']);assertEvidence(req.user);await assertInstanceScope(this.db,req.user,id);const m=await this.db.operationalMonitor.findUnique({where:{instanceId:id}});if(!m)throw new BadRequestException('请先保存只读监控连接');const result=await this.service.poll(m.id,true);await this.db.audit.create({data:{actor:req.user.email,action:'DATABASE_MONITOR_CHECK',resource:'database-instances',resourceId:id,detail:result}});return{...await monitorView(this.db,await this.db.operationalMonitor.findUnique({where:{id:m.id}}),'POSTGRESQL'),engine:engineOf(m),checkResult:result};}
}
