import {Body,Controller,Get,Post,Query,Req,UseGuards,Inject,Injectable,OnModuleInit,OnModuleDestroy,BadRequestException,ConflictException,ForbiddenException,Logger} from '@nestjs/common';
import {AccessSource,AssetRemoteJob,NetworkSensor,User} from '@prisma/client';
import {z} from 'zod';
import {Db} from './db';
import {AuthGuard} from './auth';
import {assertEvidence,assertGlobal,assertScope,dataScopeInput} from './scope';
import {assertInstanceScope} from './database-instances';
import {AssetRemoteService} from './asset-remote';
import {AccessObservationService,accessCollectionState} from './access-observation';
import {issueSensorCredential} from './network-sensors';
import {networkHealthInput} from './network-sensor-contract';
import {configuredPlatform} from './agent-platform';
import {unseal} from './maintenance';
import {runPasswordSsh,RemoteSshError} from './remote-ssh';
import {probeKind,probeArchitectureCommand,bundledProbe,probeTransfer,accessProbeCommand} from './probe-artifacts';
import {networkProbeCommand} from './network-probe-deploy';
import {parse} from './validation';
export const probeDeploymentQuery=z.object({kind:probeKind,sourceId:z.string().uuid()}).strict();
export const probeDeploymentInput=probeDeploymentQuery.extend({action:z.enum(['CHECK','INSTALL','STOP']),interface:z.string().regex(/^[A-Za-z0-9_.:-]{1,15}$/).optional()}).strict().superRefine((v,c)=>{if(v.kind==='NETWORK'&&v.action==='INSTALL'&&!v.interface)c.addIssue({code:'custom',message:'网络探针安装需要明确网卡'});if(v.kind==='ACCESS'&&v.interface)c.addIssue({code:'custom',message:'访问探针沿用观察源批准的网卡'});});
// Parse the persisted public scope independently; strict HTTP input must not accept version overrides.
const persistedConfig=z.object({kind:probeKind,sourceId:z.string().uuid(),action:z.enum(['CHECK','INSTALL','STOP']),interface:z.string().regex(/^[A-Za-z0-9_.:-]{1,15}$/).optional(),version:z.number().int()}).strict();
const kinds=['PROBE_CHECK','PROBE_INSTALL','PROBE_STOP'];
type Selection=z.infer<typeof probeDeploymentQuery>;
type Source={kind:'ACCESS';source:AccessSource}|{kind:'NETWORK';source:NetworkSensor};
type Readiness={state:'READY'|'WAITING'|'STALE'|'DISABLED'|'UNCONFIGURED'|'ERROR';message:string};
type ReadinessSource={kind:'ACCESS';source:Pick<AccessSource,'enabled'|'tokenHash'|'issuedAssetTokenHash'|'version'|'health'|'lastReportAt'>}|{kind:'NETWORK';source:Pick<NetworkSensor,'enabled'|'tokenHash'|'lastReportedAt'|'lastMode'|'health'|'lastStatsAt'|'ruleFile'|'expectedRuleSha256'|'stats'>};
export function probeReadiness(value:ReadinessSource,assetToken:string|null,now=Date.now()):Readiness{
 const s=value.source;
 if(!s.enabled)return {state:'DISABLED',message:'来源已停用'};
 if(!s.tokenHash||!assetToken)return {state:'UNCONFIGURED',message:'来源或主机身份尚未配置'};
 if(value.kind==='ACCESS'){
  const source=value.source,state=accessCollectionState({...source,credentialValid:source.issuedAssetTokenHash===assetToken},now).state;
  return state==='RUNNING'?{state:'READY',message:'已收到当前配置的运行心跳；实际访问记录取决于业务流量'}:state==='STALE'?{state:'STALE',message:'探针心跳已过期'}:state==='AWAITING_PROBE'?{state:'WAITING',message:'等待真实探针心跳'}:{state:'ERROR',message:'探针尚未就绪：'+state};
 }
 const source=value.source,h=networkHealthInput.safeParse(source.health);
 if(!source.lastReportedAt||source.lastMode!=='LIVE')return {state:'WAITING',message:'等待实时读取心跳及引擎统计'};
 if(now-source.lastReportedAt.getTime()>180000)return {state:'STALE',message:'实时读取心跳已过期'};
 if(!h.success||h.data.status==='ERROR'||source.expectedRuleSha256&&h.data.rulesSha256!==source.expectedRuleSha256)return {state:'ERROR',message:'探针读取健康异常'};
 if(h.data.status!=='READING'||!source.lastStatsAt||now-source.lastStatsAt.getTime()>180000)return {state:'WAITING',message:'等待实时引擎统计；服务启动不代表引擎已验收'};
 const rules=z.object({rulesLoaded:z.number().int().nonnegative(),rulesFailed:z.number().int().nonnegative()}).safeParse(source.stats);
 if(source.ruleFile&&(!rules.success||rules.data.rulesLoaded===0||rules.data.rulesFailed>0))return {state:'ERROR',message:'检测规则加载尚未确认成功，请检查实时引擎统计'};
 return {state:'READY',message:source.ruleFile?'实时读取与引擎统计正常；协议事件取决于业务流量':'实时读取与引擎统计正常；未配置检测规则，仅确认协议采集'};
}
export function accessInstallationConfig(source:Pick<AccessSource,'id'|'assetId'|'maxQueueBytes'|'mode'|'interface'|'address'|'port'|'profile'>,token:string,platform:{server:string;caCertificate?:string}){
 return {server:platform.server,sourceId:source.id,token,stateDir:'/var/lib/selfguard/access-probe/'+source.id,maxQueueBytes:source.maxQueueBytes,allowHTTP:false,...(platform.caCertificate?{caCertificate:platform.caCertificate}:{}),installation:{assetId:source.assetId,mode:source.mode,interface:source.interface,address:source.address,port:source.port,...(source.mode==='PLAINTEXT_EVENTS'?{profile:source.profile}:{})}};
}
const networkResult=z.object({commandCompleted:z.boolean().optional(),error:z.string().optional(),enginePresent:z.boolean().optional(),engineRunning:z.boolean().optional(),bridgeStatus:z.string().optional()});
export function networkCommandResult(output:string,action:'CHECK'|'INSTALL'|'STOP'){
 const result=networkResult.parse(JSON.parse(output));
 if(result.commandCompleted===false){const code=result.error||'UNKNOWN';const explanations:Record<string,string>={DOCKER_REQUIRED:'目标主机需要 Docker',LOGROTATE_REQUIRED:'目标主机需要 logrotate',SYSTEMD_REQUIRED:'目标主机需要 systemd',ROOT_REQUIRED:'需要 root 管理连接',INTERFACE_NOT_FOUND:'所选网卡不存在',ModuleNotFoundError:'目标主机需要 Python3 PyYAML',KeyError:'请检查基础 Agent 专用账户与配置',RULE_DIGEST_MISMATCH:'批准规则文件摘要不匹配',CONFIG_BINDING_INVALID:'来源配置与目标主机不匹配',UNIT_NOT_OWNED:'发现非本来源管理的同名服务',CONTAINER_NOT_OWNED:'发现非本来源管理的同名容器',SYMLINK_REJECTED:'安装目录包含不允许的符号链接',VENDOR_CONFIG_INVALID:'引擎镜像配置无效',FileNotFoundError:'目标主机缺少必需文件',PermissionError:'目标主机文件权限不满足要求'};
  return {status:code==='TimeoutExpired'?'UNKNOWN':'FAILED',detail:explanations[code]||'引擎操作未完成，请检查目标主机依赖、容器运行环境和服务状态'};
 }
 if(action==='CHECK'){if(result.engineRunning===undefined||result.bridgeStatus===undefined)throw new Error('invalid result');return {status:'SUCCEEDED',detail:result.engineRunning&&result.bridgeStatus==='active'?'引擎与读取服务运行中，采集就绪仍以实时心跳和统计为准':'远程检查完成，采集服务尚未全部运行'};}
 if(result.commandCompleted!==true)throw new Error('invalid result');return null;
}
function publicJob(job:AssetRemoteJob|null){if(!job)return null;const config=persistedConfig.parse(job.config);return {id:job.id,status:job.status,action:config.action,detail:job.detail,createdAt:job.createdAt,updatedAt:job.updatedAt};}
export function assertProbeWriter(user:Pick<User,'role'|'disabled'|'dataScope'>){if(user.disabled||user.role!=='ADMIN')throw new ForbiddenException('探针远程操作需要有效管理员权限');assertGlobal(user);assertEvidence(user);}
@Injectable()
export class ProbeDeploymentsService implements OnModuleInit,OnModuleDestroy{
 private timer?:NodeJS.Timeout;private ticking=false;
 constructor(@Inject(Db)private db:Db,@Inject(AssetRemoteService)private remote:AssetRemoteService,@Inject(AccessObservationService)private access:AccessObservationService){}
 onModuleInit(){this.timer=setInterval(()=>void this.tick(),2000);this.timer.unref();}
 onModuleDestroy(){if(this.timer)clearInterval(this.timer);}
 async source(user:User,selection:Selection):Promise<Source>{
  if(user.disabled)throw new ForbiddenException();assertGlobal(user);assertEvidence(user);
  const value:Source=selection.kind==='ACCESS'?{kind:'ACCESS',source:await this.db.accessSource.findUniqueOrThrow({where:{id:selection.sourceId}})}:{kind:'NETWORK',source:await this.db.networkSensor.findUniqueOrThrow({where:{id:selection.sourceId}})};
  await assertScope(this.db,user,'assets',value.source.assetId);
  if(value.kind==='ACCESS'&&value.source.instanceId){const instance=await assertInstanceScope(this.db,{...user,dataScope:dataScopeInput.parse(user.dataScope||{})},value.source.instanceId);if(instance.archivedAt||!instance.hostIds.includes(value.source.assetId))throw new ForbiddenException('实例授权已变化');}
  return value;
 }
 async latest(user:User,query:unknown){const selection=parse(probeDeploymentQuery,query),value=await this.source(user,selection),asset=await this.db.asset.findUniqueOrThrow({where:{id:value.source.assetId}});
  const job=await this.db.assetRemoteJob.findFirst({where:{assetId:asset.id,kind:{in:kinds},AND:[{config:{path:['sourceId'],equals:selection.sourceId}},{config:{path:['kind'],equals:selection.kind}}]},orderBy:{createdAt:'desc'}});
  return {job:publicJob(job),readiness:probeReadiness(value,asset.archivedAt?null:asset.tokenHash)};
 }
 async create(user:User,body:unknown){assertProbeWriter(user);const input=parse(probeDeploymentInput,body),value=await this.source(user,input),{access}=await this.remote.connection(user,value.source.assetId);
  if(input.action==='INSTALL'&&!value.source.enabled)throw new ConflictException('请先启用来源');
  return this.db.$transaction(async tx=>{await tx.$queryRaw`SELECT pg_advisory_xact_lock(hashtext(${'asset-remote:'+value.source.assetId}))::text`;
   if(await tx.assetRemoteJob.count({where:{assetId:value.source.assetId,status:{in:['QUEUED','RUNNING']}}}))throw new ConflictException('此主机已有远程操作，请等待完成');
   const row=await tx.assetRemoteJob.create({data:{assetId:value.source.assetId,ownerId:user.id,address:access.address,accessUpdatedAt:access.updatedAt,kind:'PROBE_'+input.action,config:{...input,version:value.source.version},detail:'已排队，等待通过已验证的管理连接执行'}});
   await tx.audit.create({data:{actor:user.email,action:'PROBE_DEPLOYMENT_CREATE',resource:'assets',resourceId:row.assetId,detail:{jobId:row.id,sourceId:input.sourceId,kind:input.kind,action:input.action}}});return publicJob(row);
  });
 }
 async tick(){if(this.ticking)return;this.ticking=true;try{
  const jobs=await this.db.$transaction(async tx=>{await tx.$queryRaw`SELECT pg_advisory_xact_lock(hashtext('asset-remote-worker'))::text`;
   await tx.assetRemoteJob.updateMany({where:{kind:{in:kinds},status:'RUNNING',leaseUntil:{lt:new Date()}},data:{status:'UNKNOWN',detail:'执行确认超时，请检查实际服务状态；未自动重试',leaseUntil:null}});
   const running=await tx.assetRemoteJob.count({where:{status:'RUNNING'}}),jobs=await tx.assetRemoteJob.findMany({where:{kind:{in:kinds},status:'QUEUED'},orderBy:{createdAt:'asc'},take:Math.max(0,2-running)});
   for(const row of jobs)await tx.assetRemoteJob.update({where:{id:row.id},data:{status:'RUNNING',detail:'正在执行探针远程操作',leaseUntil:new Date(Date.now()+360000)}});return jobs;
  });for(const job of jobs)void this.execute(job).catch(()=>Logger.warn('Probe deployment result unavailable','ProbeDeployments'));
 }catch{Logger.warn('Probe deployment scheduler unavailable','ProbeDeployments');}finally{this.ticking=false;}}
 async execute(job:AssetRemoteJob){let status='FAILED',detail='执行前授权、来源配置或主机连接已变化，请刷新后重试';
  try{const config=persistedConfig.parse(job.config),user=await this.db.user.findUniqueOrThrow({where:{id:job.ownerId}});assertProbeWriter(user);
   let value=await this.source(user,config);if(value.source.assetId!==job.assetId)throw new ConflictException();
   const {asset,access}=await this.remote.connection(user,job.assetId);if(access.address!==job.address||access.updatedAt.getTime()!==job.accessUpdatedAt.getTime())throw new ConflictException();
   if(config.action==='INSTALL'&&(!value.source.enabled||value.source.version!==config.version||!asset.tokenHash))throw new ConflictException();
   const password=unseal(access.credential),ssh=(command:string,input='',timeout=30000)=>runPasswordSsh(access,password,command,input,timeout);
   if(config.action==='INSTALL'){
    if(value.kind==='NETWORK')networkProbeCommand(config.sourceId,'INSTALL',{interface:config.interface,image:process.env.NETWORK_PROBE_IMAGE,evePath:'/var/lib/selfguard-network/'+config.sourceId+'/eve/eve.json',ruleFile:value.source.ruleFile||undefined,expectedRuleSha256:value.source.expectedRuleSha256||undefined});
    const arch=(await ssh(probeArchitectureCommand)).trim(),artifact=await bundledProbe(config.kind,arch);let configuration:unknown;
    if(value.kind==='ACCESS'){
     const platform=z.object({server:z.string().url(),caCertificate:z.string().optional()}).parse(await configuredPlatform(this.db));
     const credential=await this.access.issueCredential({...user,dataScope:dataScopeInput.parse(user.dataScope||{})},value.source.id);const reset=await this.db.accessSource.updateMany({where:{id:value.source.id,version:config.version,enabled:true},data:{lastReportAt:null,health:{}}});if(!reset.count)throw new ConflictException();configuration=accessInstallationConfig(value.source,credential.token,platform);
    }else{
     const evePath='/var/lib/selfguard-network/'+value.source.id+'/eve/eve.json';
     // An explicit installation authorizes only this managed output path; capture scope remains unchanged.
     const changed=await this.db.networkSensor.updateMany({where:{id:value.source.id,version:config.version,enabled:true},data:{evePath,version:{increment:1},tokenHash:null,lastReportedAt:null,lastStatsAt:null,lastMode:null}});if(!changed.count)throw new ConflictException();
     configuration=await issueSensorCredential(this.db,user.id,value.source.id);value={kind:'NETWORK',source:await this.db.networkSensor.findUniqueOrThrow({where:{id:value.source.id}})};
    }
    const transfer=probeTransfer(config.kind,config.sourceId,artifact,configuration);await ssh(transfer.command,transfer.input,60000);
   }
   if(config.action==='INSTALL'){const current=await this.source(user,config);if(!current.source.enabled||current.source.version!==value.source.version)throw new ConflictException();}
   const command=value.kind==='ACCESS'?accessProbeCommand(config.sourceId,config.action):networkProbeCommand(config.sourceId,config.action,{interface:config.interface,image:process.env.NETWORK_PROBE_IMAGE,evePath:value.source.evePath,ruleFile:value.source.ruleFile||undefined,expectedRuleSha256:value.source.expectedRuleSha256||undefined});
   const output=await ssh(command,'',240000);status='SUCCEEDED';detail=config.action==='STOP'?'停止命令已完成；请核对实际采集状态':config.action==='CHECK'?'远程检查命令已完成；采集就绪以来源实时心跳为准':'安装命令已完成，正在等待真实采集心跳及引擎验收';
   if(value.kind==='NETWORK'){const result=networkCommandResult(output,config.action);if(result){status=result.status;detail=result.detail;}}else if(!output.includes('PROBE_COMMAND_OK'))throw new RemoteSshError('探针命令未返回完成标识，请核对实际状态',true);
  }catch(error){if(status==='SUCCEEDED'){status='UNKNOWN';detail='命令返回格式未确认，请检查实际服务状态';}if(error instanceof RemoteSshError){status=error.uncertain?'UNKNOWN':'FAILED';detail=error.message;}else if(error instanceof BadRequestException||error instanceof ConflictException){detail='来源配置或运行条件不满足，请核对启用状态、版本、平台入口与管理连接';}}
  await this.db.assetRemoteJob.updateMany({where:{id:job.id,status:'RUNNING'},data:{status,detail,leaseUntil:null}});
  await this.db.audit.create({data:{actor:'probe-worker',action:'PROBE_DEPLOYMENT_'+status,resource:'assets',resourceId:job.assetId,detail:{jobId:job.id}}});
 }
}
@Controller('probe-deployments') @UseGuards(AuthGuard)
export class ProbeDeploymentsController{
 constructor(@Inject(ProbeDeploymentsService)private service:ProbeDeploymentsService){}
 @Get()get(@Req()req:{user:User},@Query()query:unknown){return this.service.latest(req.user,query);}
 @Post()post(@Req()req:{user:User},@Body()body:unknown){return this.service.create(req.user,body);}
}
