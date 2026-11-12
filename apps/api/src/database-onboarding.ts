import {Body,Controller,Get,Post,Param,Query,Req,UseGuards,Inject,Injectable,OnModuleInit,OnModuleDestroy,ConflictException,ForbiddenException,UnauthorizedException,BadRequestException,Logger} from '@nestjs/common';
import {AssetRemoteJob,Prisma,User} from '@prisma/client';
import {z} from 'zod';
import {readFile,stat} from 'node:fs/promises';
import {createHash} from 'node:crypto';
import {isDeepStrictEqual} from 'node:util';
import {resolve} from 'node:path';
import {Db} from './db';
import {AUDIT_DB} from './audit-db';
import {AuthGuard,bearer} from './auth';
import {hashToken} from './security';
import {assertScope,assertEvidence,assertGlobal,dataScopeInput,assetScope} from './scope';
import {assertInstanceScope,assertDatabaseRuleEngine,instanceInput} from './database-instances';
import {databaseAuditSourceFormats} from './database-capabilities';
import {AssetRemoteService} from './asset-remote';
import {isLinuxAsset} from './asset-os';
import {runPasswordSsh,RemoteSshError} from './remote-ssh';
import {unseal} from './maintenance';
import {configuredPlatform} from './agent-platform';
import {parse} from './validation';
const absolutePath=z.string().startsWith('/').max(4096).refine(s=>!/[\x00-\x1f\x7f]/.test(s)&&!s.split('/').includes('..'));
const targetInput=z.object({deployment:z.enum(['HOST','DOCKER','FILE']),container:z.string().regex(/^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$/).optional(),port:z.number().int().min(1).max(65535),database:z.string().trim().min(1).max(128).regex(/^[^\x00-\x1f\x7f]+$/),sourcePath:absolutePath.optional(),format:z.enum(databaseAuditSourceFormats).optional()}).strict().superRefine((v,c)=>{if(v.deployment==='DOCKER'&&!v.container||v.deployment!=='DOCKER'&&v.container||v.deployment==='FILE'&&(!v.sourcePath||!v.format)||v.deployment!=='FILE'&&(v.sourcePath||v.format))c.addIssue({code:'custom',message:'目标部署方式与明确容器或日志来源不匹配'});});
export const onboardingInput=z.object({assetId:z.string().uuid(),action:z.enum(['CHECK','PREPARE','INSTALL','STOP']),target:targetInput,expectedUpdatedAt:z.string().datetime()}).strict();
const configInput=onboardingInput.extend({instanceId:z.string().uuid()});
const kinds=['DB_MONITOR_CHECK','DB_MONITOR_PREPARE','DB_MONITOR_INSTALL','DB_MONITOR_STOP'];
const resultInput=z.object({state:z.enum(['CHECKED','WAITING_RESTART','INSTALLED','STOPPED','BLOCKED']),detailCode:z.enum(['READY','COLLECTOR_OFF','PREPARED_RESTART','INSTALLED','STOPPED','ROOT_REQUIRED','POSTGRES_REQUIRED','DOCKER_REQUIRED','TARGET_MISMATCH','LOCAL_ADMIN_REQUIRED','AGENT_REQUIRED','AGENT_IDENTITY_MISMATCH','UNSUPPORTED_ENGINE','AUDIT_SOURCE_REQUIRED','SOURCE_UNREADABLE','SELF_AUDIT_ISOLATION_REQUIRED','TARGET_CHANGED','UNIT_NOT_OWNED','SYMLINK_REJECTED','RETENTION_NOT_READY','INSTALLATION_FAILED','COLLECTOR_NOT_RUNNING','CONFIGURATION_CHANGED','INVALID_REQUEST','INTERNAL_ERROR']),sourcePath:absolutePath.optional(),format:z.enum(databaseAuditSourceFormats).optional(),requiresRestart:z.boolean(),version:z.string().max(128).optional(),targetFingerprint:z.string().regex(/^[a-f0-9]{64}$/).optional(),databaseIdentity:z.string().regex(/^[a-f0-9]{64}$/).optional(),settings:z.object(Object.fromEntries(['logging_collector','log_destination','log_min_duration_statement','log_statement','log_error_verbosity','log_parameter_max_length','log_parameter_max_length_on_error','log_connections','log_disconnections','log_directory','log_rotation_age','log_rotation_size','log_timezone'].map(k=>[k,z.union([z.string().max(4096),z.boolean(),z.number()]).optional()]))).strict().optional()}).strict();
export const monitorHealthInput=z.object({instanceId:z.string().uuid(),sourcePath:absolutePath,status:z.enum(['READING','WAITING','BACKPRESSURE','ERROR']),version:z.string().regex(/^[A-Za-z0-9.+_-]{1,64}$/),queuedBatches:z.number().int().nonnegative(),acceptedEvents:z.number().int().nonnegative(),invalidRecords:z.number().int().nonnegative(),rotationGaps:z.number().int().nonnegative(),lastEventAt:z.string().datetime().optional(),detailCode:z.enum(['STARTING','VALIDATING','WAITING_LOG','READING','BACKPRESSURE','SOURCE_UNREADABLE','INVALID_RECORDS','ROTATION_GAP','DELIVERY_ERROR','AUTHORIZATION_REVOKED','DISK_ERROR','NETWORK_ERROR','EXPIRED'])}).strict();
type Target=z.infer<typeof targetInput>;
export function assertOnboardingTarget(instance:{engine:string;endpoints:unknown},target:Target){
 if(!instanceInput.shape.endpoints.parse(instance.endpoints).some(e=>e.port===target.port))throw new BadRequestException('端口不在实例登记入口中');
 if(target.deployment!=='FILE'&&instance.engine!=='postgresql')throw new BadRequestException('此引擎请使用已有审计文件接入');
 if(target.format)assertDatabaseRuleEngine(instance.engine,{service:target.format});
}
export function onboardingJobState(state:z.infer<typeof resultInput>['state']){return state==='WAITING_RESTART'?'WAITING_RESTART':state==='BLOCKED'?'FAILED':'SUCCEEDED';}
export function isPlatformDatabase(instance:{stableKey:string;endpoints:unknown},target:Target,monitor:unknown,databaseUrl=process.env.DATABASE_URL){
 if(/selfguard.*(?:system|postgres)|system.*selfguard/i.test(instance.stableKey))return true;
 try{const url=new URL(databaseUrl||''),database=decodeURIComponent(url.pathname.slice(1)),port=Number(url.port||5432);const m=z.object({address:z.string(),port:z.number(),database:z.string()}).safeParse(monitor);
 return (m.success&&m.data.address===url.hostname&&m.data.port===port&&m.data.database===database)||(target.database===database&&target.port===port&&(target.container==='self-guard-production-postgres-1'||instanceInput.shape.endpoints.parse(instance.endpoints).some(e=>e.address===url.hostname&&e.port===port)));
 }catch{return true;}
}
export function databaseIdentityMatches(identity:string|undefined,actual:{database:string;startedEpoch:string}|undefined){return !!identity&&!!actual&&identity===createHash('sha256').update(actual.database+'|'+actual.startedEpoch).digest('hex');}
function writer(user:User){if(user.disabled||user.role!=='ADMIN')throw new ForbiddenException('数据库接入需要管理员权限');assertGlobal(user);assertEvidence(user);}
function publicJob(row:AssetRemoteJob|null){if(!row)return null;const c=configInput.parse(row.config);return{id:row.id,status:row.status,action:c.action,detail:row.detail,updatedAt:row.updatedAt,...(row.result?{result:resultInput.parse(row.result)}:{})};}
@Injectable()
export class DatabaseOnboardingService implements OnModuleInit,OnModuleDestroy{
 private timer?:NodeJS.Timeout;private ticking=false;
 constructor(@Inject(Db)private db:Db,@Inject(AUDIT_DB)private auditDb:Db,@Inject(AssetRemoteService)private remote:AssetRemoteService){}
 onModuleInit(){this.timer=setInterval(()=>void this.tick(),2000);this.timer.unref();}
 onModuleDestroy(){if(this.timer)clearInterval(this.timer);}
 async instance(user:User,id:string){assertEvidence(user);const row=await assertInstanceScope(this.db,{...user,dataScope:dataScopeInput.parse(user.dataScope||{})},id);if(row.archivedAt)throw new ForbiddenException('实例已归档');return row;}
 async latest(user:User,id:string){const instance=await this.instance(user,id),hosts=await this.db.asset.findMany({where:{AND:[assetScope({...user,dataScope:dataScopeInput.parse(user.dataScope||{})}),{id:{in:instance.hostIds},archivedAt:null}]}}),ids=hosts.map(h=>h.id);
 const [access,job,health]=await Promise.all([this.db.assetRemoteAccess.findMany({where:{assetId:{in:ids}}}),this.db.assetRemoteJob.findFirst({where:{assetId:{in:ids},kind:{in:kinds},config:{path:['instanceId'],equals:id}},orderBy:[{createdAt:'desc'},{id:'desc'}]}),this.db.setting.findMany({where:{key:{in:ids.map(a=>'database-monitor:'+id+':'+a)}},orderBy:{updatedAt:'desc'}})]);
 const sources=instanceInput.shape.auditSources.parse(instance.auditSources),valid=health.find(h=>{const v=monitorHealthInput.safeParse(h.value);return v.success&&sources.some(s=>s.path===v.data.sourcePath&&h.key==='database-monitor:'+id+':'+s.assetId);});
 return{instanceUpdatedAt:instance.updatedAt,hosts:hosts.filter(isLinuxAsset).map(h=>({id:h.id,name:h.hostname,ip:h.ip,sshConfigured:access.some(a=>a.assetId===h.id&&a.address===h.ip),agentReady:!!h.tokenHash})),job:publicJob(job),collector:valid?{...monitorHealthInput.parse(valid.value),updatedAt:valid.updatedAt,stale:Date.now()-valid.updatedAt.getTime()>180000}:null,canManage:user.role==='ADMIN'};
 }
 async create(user:User,id:string,body:unknown){writer(user);const input=parse(onboardingInput,body),instance=await this.instance(user,id);assertOnboardingTarget(instance,input.target);
 if(!instance.hostIds.includes(input.assetId)||instance.updatedAt.toISOString()!==input.expectedUpdatedAt)throw new ConflictException('实例或主机范围已变化');
 const {access,asset}=await this.remote.connection(user,input.assetId);if(!asset.tokenHash)throw new ConflictException('请先接入基础 Agent');
 return this.db.$transaction(async tx=>{await tx.$queryRaw`SELECT pg_advisory_xact_lock(hashtext(${'asset-remote:'+asset.id}))::text`;
 if(await tx.assetRemoteJob.count({where:{assetId:asset.id,status:{in:['QUEUED','RUNNING']}}}))throw new ConflictException('主机已有操作正在执行');
 const current=await tx.databaseInstance.findUniqueOrThrow({where:{id}});if(current.updatedAt.getTime()!==instance.updatedAt.getTime())throw new ConflictException('实例已变化');
 const row=await tx.assetRemoteJob.create({data:{assetId:asset.id,ownerId:user.id,address:access.address,accessUpdatedAt:access.updatedAt,kind:'DB_MONITOR_'+input.action,config:{...input,instanceId:id},detail:'等待受控数据库接入操作'}});
 await tx.audit.create({data:{actor:user.email,action:'DATABASE_ONBOARDING_CREATE',resource:'database-instances',resourceId:id,detail:{jobId:row.id,action:input.action,assetId:asset.id}}});return {...publicJob(row),instanceUpdatedAt:current.updatedAt};});
 }
 async tick(){if(this.ticking)return;this.ticking=true;try{const jobs=await this.db.$transaction(async tx=>{await tx.$queryRaw`SELECT pg_advisory_xact_lock(hashtext('asset-remote-worker'))::text`;
 await tx.assetRemoteJob.updateMany({where:{kind:{in:kinds},status:'RUNNING',leaseUntil:{lt:new Date()}},data:{status:'UNKNOWN',detail:'执行结果未确认，请检查实际状态；未自动重试',leaseUntil:null}});
 const running=await tx.assetRemoteJob.count({where:{status:'RUNNING'}}),rows=await tx.assetRemoteJob.findMany({where:{kind:{in:kinds},status:'QUEUED'},orderBy:{createdAt:'asc'},take:Math.max(0,2-running)});
 for(const row of rows)await tx.assetRemoteJob.update({where:{id:row.id},data:{status:'RUNNING',leaseUntil:new Date(Date.now()+360000),detail:'正在检查授权与目标环境'}});return rows;});for(const row of jobs)void this.execute(row).catch(()=>Logger.warn('Database onboarding result unavailable','DatabaseOnboarding'));}catch{Logger.warn('Database onboarding scheduler unavailable','DatabaseOnboarding');}finally{this.ticking=false;}}
 async execute(job:AssetRemoteJob){let status='FAILED',detail='授权、实例配置或管理连接已变化',result:z.infer<typeof resultInput>|undefined,mutated=false;
 try{const c=configInput.parse(job.config),user=await this.db.user.findUniqueOrThrow({where:{id:job.ownerId}});writer(user);const instance=await this.instance(user,c.instanceId);assertOnboardingTarget(instance,c.target);
 if(!instance.hostIds.includes(job.assetId)||c.assetId!==job.assetId||instance.updatedAt.toISOString()!==c.expectedUpdatedAt)throw new ConflictException();
 const {access,asset}=await this.remote.connection(user,job.assetId);if(!asset.tokenHash||access.address!==job.address||access.updatedAt.getTime()!==job.accessUpdatedAt.getTime())throw new ConflictException();
 const monitor=await this.db.operationalMonitor.findUnique({where:{instanceId:instance.id}});let self=isPlatformDatabase(instance,c.target,monitor?.config);
 const source=await readFile(resolve(__dirname,'../scripts/database-onboarding.py'),'utf8'),command="python3 -c '"+source.replace(/'/g,"'\\''")+"'";
 const base={instanceId:instance.id,assetId:asset.id,engine:instance.engine,target:c.target,selfAuditSafe:!self||this.auditDb!==this.db};
 const invoke=async(action:string,extra:Record<string,unknown>={})=>resultInput.parse(JSON.parse(await runPasswordSsh(access,unseal(access.credential),command,JSON.stringify({...base,action,...extra})+'\n',action==='INSTALL'?240000:60000)));
 if(c.action==='STOP'){mutated=true;result=await invoke('STOP');}
 else{result=await invoke('CHECK');const identities=await this.db.$queryRaw<{database:string;startedEpoch:string}[]>`SELECT current_database() AS database, extract(epoch from pg_postmaster_start_time())::text AS "startedEpoch"`;if(!identities[0])throw new Error('Database identity unavailable');self=self||databaseIdentityMatches(result.databaseIdentity,identities[0]);base.selfAuditSafe=!self||this.auditDb!==this.db;}
 if(c.action==='INSTALL'||c.action==='PREPARE'){
 const checked=await this.db.assetRemoteJob.findFirst({where:{assetId:job.assetId,kind:'DB_MONITOR_CHECK',status:'SUCCEEDED',AND:[{config:{path:['instanceId'],equals:instance.id}},{config:{path:['target'],equals:c.target}}]},orderBy:{createdAt:'desc'}});
 const prior=checked&&configInput.parse(checked.config),proof=checked&&resultInput.parse(checked.result);
 if(!prior||!proof||prior.expectedUpdatedAt!==c.expectedUpdatedAt||!isDeepStrictEqual(prior.target,c.target)||!proof.targetFingerprint||proof.targetFingerprint!==result.targetFingerprint)throw new ConflictException('需要重新检查目标');
 }
 if(c.action!=='CHECK'&&c.action!=='STOP'&&result.state!=='BLOCKED'){
 if(self&&this.auditDb===this.db)result={state:'BLOCKED',detailCode:'SELF_AUDIT_ISOLATION_REQUIRED',requiresRestart:false};
 else{const owner=await this.db.user.findUniqueOrThrow({where:{id:user.id}});writer(owner);const fresh=await this.instance(owner,instance.id),identity=await this.remote.connection(owner,asset.id);if(fresh.updatedAt.toISOString()!==c.expectedUpdatedAt||identity.asset.tokenHash!==asset.tokenHash||identity.access.updatedAt.getTime()!==access.updatedAt.getTime())throw new ConflictException();const extra:Record<string,unknown>={...(['INSTALL','PREPARE'].includes(c.action)?{expectedTargetFingerprint:result.targetFingerprint}:{})};if(c.action==='INSTALL'){const machine=(await runPasswordSsh(access,unseal(access.credential),'uname -m')).trim();const arch=machine==='x86_64'?'amd64':machine==='aarch64'||machine==='arm64'?'arm64':null;if(!arch)throw new BadRequestException('Unsupported architecture');const path=process.env.DATABASE_PROBE_BINARY||resolve(process.env.PROBE_ARTIFACT_DIR||'/opt/selfguard-probes','selfguard-database-probe-linux-'+arch);if((await stat(path)).size>64*1024*1024)throw new BadRequestException();const binary=await readFile(path);if(binary.length>64*1024*1024)throw new BadRequestException();extra.artifact={base64:binary.toString('base64'),sha256:createHash('sha256').update(binary).digest('hex')};extra.platform=await configuredPlatform(this.db);}mutated=true;result=await invoke(c.action,extra);}
 }
 if(c.action==='INSTALL'&&result.state==='INSTALLED'){
 if(!result.sourcePath||!result.format)throw new Error();assertDatabaseRuleEngine(instance.engine,{service:result.format});const bound={assetId:asset.id,path:result.sourcePath,format:result.format};
 await this.db.$transaction(async tx=>{await tx.$queryRaw`SELECT id FROM "Asset" WHERE id=${asset.id} FOR UPDATE`;const a=await tx.asset.findUniqueOrThrow({where:{id:asset.id}}),u=await tx.user.findUniqueOrThrow({where:{id:user.id}});writer(u);await assertScope(tx,u,'assets',asset.id);if(a.archivedAt||a.tokenHash!==asset.tokenHash)throw new ConflictException();const sources=instanceInput.shape.auditSources.parse(instance.auditSources);if(sources.some(s=>s.assetId===bound.assetId&&s.path===bound.path&&s.format!==bound.format))throw new ConflictException();if(!sources.some(s=>isDeepStrictEqual(s,bound)))sources.push(bound);if(sources.length>20)throw new ConflictException();const changed=await tx.databaseInstance.updateMany({where:{id:instance.id,updatedAt:instance.updatedAt,archivedAt:null},data:{auditSources:sources}});if(!changed.count)throw new ConflictException();});
 }
 if(result.state!=='BLOCKED'&&result.state!=='WAITING_RESTART'&&result.state!==({CHECK:'CHECKED',INSTALL:'INSTALLED',PREPARE:'CHECKED',STOP:'STOPPED'} as const)[c.action])throw new Error('Unexpected operation result');
 status=onboardingJobState(result.state);detail=result.detailCode;
 }catch(error){status=mutated||error instanceof RemoteSshError&&error.uncertain?'UNKNOWN':'FAILED';detail=status==='UNKNOWN'?'远程操作结果或来源绑定未确认；未自动重试':'检查失败，请核对授权、目标身份、管理连接与实例版本';result=undefined;}
 await this.db.assetRemoteJob.updateMany({where:{id:job.id,status:'RUNNING'},data:{status,detail,leaseUntil:null,...(result?{result:result as Prisma.InputJsonValue}:{})}});
 }
}
@Controller('database-instances') @UseGuards(AuthGuard)
export class DatabaseOnboardingController{
 constructor(@Inject(DatabaseOnboardingService)private service:DatabaseOnboardingService){}
 @Get(':id/onboarding')get(@Req()req:{user:User},@Param('id')id:string){return this.service.latest(req.user,id);}
 @Post(':id/onboarding')post(@Req()req:{user:User},@Param('id')id:string,@Body()body:unknown){return this.service.create(req.user,id,body);}
}
@Controller('agent')
export class AgentDatabaseMonitorController{
 constructor(@Inject(AUDIT_DB)private db:Db){}
 private async authorized<T>(req:{headers:{authorization?:string}},selection:{instanceId:string;sourcePath:string},run:(tx:Prisma.TransactionClient,source:{assetId:string;path:string;format:string},engine:string)=>Promise<T>){
 const token=bearer(req);if(!token)throw new UnauthorizedException();const tokenHash=hashToken(token);
 return this.db.$transaction(async tx=>{const asset=await tx.asset.findUnique({where:{tokenHash}});if(!asset)throw new UnauthorizedException();await tx.$queryRaw`SELECT id FROM "Asset" WHERE id=${asset.id} FOR UPDATE`;
 const current=await tx.asset.findUniqueOrThrow({where:{id:asset.id}});if(current.archivedAt||current.tokenHash!==tokenHash)throw new UnauthorizedException();
 await tx.$queryRaw`SELECT id FROM "DatabaseInstance" WHERE id=${selection.instanceId} FOR SHARE`;
 const instance=await tx.databaseInstance.findUnique({where:{id:selection.instanceId}}),source=instance&&instanceInput.shape.auditSources.parse(instance.auditSources).find(s=>s.assetId===asset.id&&s.path===selection.sourcePath);
 if(!instance||instance.archivedAt||!instance.hostIds.includes(asset.id)||!source)throw new ForbiddenException('采集来源已撤销');return run(tx,source,instance.engine);});
 }
 @Get('database-monitor')get(@Req()req:{headers:{authorization?:string}},@Query()query:unknown){const selection=parse(z.object({instanceId:z.string().uuid(),sourcePath:absolutePath}).strict(),query);return this.authorized(req,selection,async(_tx,source,engine)=>({...selection,assetId:source.assetId,format:source.format,engine,enabled:true}));}
 @Post('database-monitor/status')status(@Req()req:{headers:{authorization?:string}},@Body()body:unknown){const health=parse(monitorHealthInput,body);return this.authorized(req,health,async(tx,source)=>{const key='database-monitor:'+health.instanceId+':'+source.assetId;await tx.setting.upsert({where:{key},create:{key,value:health},update:{value:health}});return{accepted:true};});}
}
