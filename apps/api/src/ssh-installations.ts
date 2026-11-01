import {platformBaseURL,validPlatformURL} from './platform-path';
import {platformInstallationBody} from './agent-platform';
import {runPasswordSsh,RemoteSshError} from './remote-ssh';
import {installationDiagnostic,installationTransportData} from './ssh-install-progress';
import {Body,Controller,Get,Post,Param,Query,Req,UseGuards,Inject,Injectable,OnModuleInit,OnModuleDestroy,BadRequestException,ConflictException,NotFoundException,ForbiddenException,Logger} from '@nestjs/common';
import {z} from 'zod';import {isIP} from 'node:net';import {spawn} from 'node:child_process';import {mkdtemp,writeFile,rm} from 'node:fs/promises';import {tmpdir} from 'node:os';import {join} from 'node:path';
import {Db} from './db';import {AuthGuard,allow} from './auth';import {parse,pageInput} from './validation';import {assertScope,restricted} from './scope';import {seal,unseal} from './maintenance';import {InstallationService,installationProfileInput,validateInstallationCompatibility} from './installations';import {componentPageInput,verifyArtifactManifest} from './construction-contracts';
const hostKey=z.string().max(8192).regex(/^(ssh-ed25519|ecdsa-sha2-nistp(?:256|384|521)|ssh-rsa) [A-Za-z0-9+/]+={0,2}$/);
export const sshDeploymentInput=installationProfileInput.safeExtend({name:z.string().trim().min(1).max(200),username:z.string().regex(/^[a-z_][a-z0-9_-]{0,31}$/),port:z.number().int().min(1).max(65535).default(22),authMode:z.enum(['PRIVATE_KEY','ASSET_PASSWORD']).default('PRIVATE_KEY'),privateKey:z.string().min(100).max(32768).refine(s=>/^-----BEGIN (OPENSSH |RSA |EC )?PRIVATE KEY-----\r?\n/.test(s),'需要 SSH 私钥文件内容').optional(),targets:z.array(z.object({assetId:z.string().uuid(),hostKey}).strict()).min(1).max(1000),concurrency:z.number().int().min(1).max(20).default(5),stopOnFailure:z.boolean().default(true)}).refine(v=>v.authMode==='ASSET_PASSWORD'||!!v.privateKey,'私钥认证需要部署私钥');
function shellQuote(value:string){return "'"+value.replace(/'/g,"'\\''")+"'";}
export function sshArguments(address:string,port:number,username:string,keyFile:string,knownHosts:string,command:string){
 if(!isIP(address)||!Number.isInteger(port)||port<1||port>65535||!/^[a-z_][a-z0-9_-]{0,31}$/.test(username))throw new BadRequestException('SSH 目标、端口或用户无效');
 return ['-F','/dev/null','-o','BatchMode=yes','-o','IdentitiesOnly=yes','-o','StrictHostKeyChecking=yes','-o','GlobalKnownHostsFile=/dev/null','-o','VerifyHostKeyDNS=no','-o','UpdateHostKeys=no','-o','PasswordAuthentication=no','-o','KbdInteractiveAuthentication=no','-o','PermitLocalCommand=no','-o','ClearAllForwardings=yes','-o','ConnectTimeout=15','-o','ServerAliveInterval=15','-o','ServerAliveCountMax=2','-o','UserKnownHostsFile='+knownHosts,'-i',keyFile,'-p',String(port),'--',username+'@'+address,command];
}
export function remoteInstallCommand(server:string,id:string,digest:string,root:string,caCertificate='',bootstrap:{proxyUrl?:string;stateDir?:string;proxyMode?:string}={}){
 const u=new URL(server);if(!validPlatformURL(server)||!/^[a-f0-9-]{36}$/.test(id)||!/^[a-f0-9]{64}$/.test(digest)||!/^[A-Za-z0-9+/=]+$/.test(root))throw new BadRequestException('远程安装参数无效');
 const proxyMode=bootstrap.proxyMode||(bootstrap.proxyUrl?'EXPLICIT':'ENVIRONMENT');if(!['DIRECT','EXPLICIT','ENVIRONMENT'].includes(proxyMode)||(proxyMode==='EXPLICIT')!==!!bootstrap.proxyUrl)throw new BadRequestException('代理方式与地址不一致');
 const script=`set -euo pipefail
umask 077
stage=PREPARE
trap 'code=$?; printf "SELFGUARD_INSTALL_FAILED:%s:%s\\n" "$stage" "$code" >&2; exit "$code"' ERR
read -r ticket
[[ "$ticket" =~ ^[A-Za-z0-9_-]{43}$ ]] || exit 1
file=$(mktemp)
ca_file=''
curl_ca=()
install_env=(/usr/bin/env ${shellQuote("AGENT_PROXY_MODE="+proxyMode)})
curl_proxy=()
${proxyMode==='DIRECT'?`curl_proxy=(--noproxy '*' --proxy '')`:''}
${bootstrap.stateDir?`install_env+=( ${shellQuote("AGENT_INSTALL_STATE_DIR="+bootstrap.stateDir)} )`:""}
${bootstrap.proxyUrl?`curl_proxy=(--noproxy '' --proxy ${shellQuote(bootstrap.proxyUrl)})
install_env+=( ${shellQuote("AGENT_PROXY_URL="+bootstrap.proxyUrl)} )`:""}
trap 'rm -f "$file" "${'$'}{ca_file}"; unset ticket' EXIT
${caCertificate?`ca_file=$(mktemp)
printf '%s' ${shellQuote(Buffer.from(caCertificate).toString('base64'))} | base64 -d > "$ca_file"
curl_ca=(--cacert "$ca_file")
install_env+=("AGENT_CA_FILE=$ca_file")`:''}
stage=PLATFORM
ready_file=$(mktemp)
trap 'rm -f "$file" "$ca_file" "$ready_file"; unset ticket' EXIT
curl "${'$'}{curl_ca[@]}" "${'$'}{curl_proxy[@]}" --connect-timeout 10 --max-time 15 --fail --silent --show-error --proto ${shellQuote('='+u.protocol.slice(0,-1))} --tlsv1.2 ${shellQuote(platformBaseURL(server)+'/api/health/ready')} -o "$ready_file"
grep -Eq '"ready"[[:space:]]*:[[:space:]]*true' "$ready_file"
stage=DOWNLOAD
printf 'header = "Authorization: Bearer %s"\\n' "$ticket" | curl --config - "${'$'}{curl_ca[@]}" "${'$'}{curl_proxy[@]}" --connect-timeout 15 --max-time 300 --fail --silent --show-error --proto ${shellQuote('='+u.protocol.slice(0,-1))} --tlsv1.2 ${shellQuote(platformBaseURL(server)+'/api/agent/install/'+id+'/artifact')} -o "$file"
stage=VERIFY
printf '%s  %s\\n' ${shellQuote(digest)} "$file" | sha256sum -c -
chmod 700 "$file"
stage=INSTALL
if [[ $(id -u) == 0 ]]; then printf '%s\\n' "$ticket" | "${'$'}{install_env[@]}" "$file" --install ${shellQuote(platformBaseURL(server))} ${shellQuote(id)} ${shellQuote(root)}; else printf '%s\\n' "$ticket" | sudo -n "${'$'}{install_env[@]}" "$file" --install ${shellQuote(platformBaseURL(server))} ${shellQuote(id)} ${shellQuote(root)}; fi`;
 return 'bash -c '+shellQuote(script);
}
export function sshFailureReason(diagnostic:string){const installation=installationDiagnostic(diagnostic);if(installation)return installation.detail;if(/Host key verification failed|REMOTE HOST IDENTIFICATION HAS CHANGED/.test(diagnostic))return 'SSH 主机密钥不匹配或未被信任，未继续安装';if(/Permission denied/.test(diagnostic))return 'SSH 凭据或目标用户权限无效';if(/sudo:.*(password|terminal|tty)/i.test(diagnostic))return '目标用户缺少免交互 sudo 安装权限';if(/Connection timed out|Connection refused|No route to host/.test(diagnostic))return '目标 SSH 连接不可用或超时';if(/Could not resolve hostname/.test(diagnostic))return '目标地址无法解析';if(/invalid format|error in libcrypto/.test(diagnostic))return 'SSH 私钥格式或解锁方式不支持';return '预检或安装失败；请在目标主机查看受保护诊断';}
function safeBatch(row:any){const{credential,...safe}=row;return safe;}
@Injectable()
export class SshInstallationService implements OnModuleInit,OnModuleDestroy{
 private timer?:NodeJS.Timeout;private ticking=false;private running=new Set<string>();
 constructor(@Inject(Db) private db:Db,@Inject(InstallationService)private installations:InstallationService){}
 onModuleInit(){this.timer=setInterval(()=>void this.tick(),5000);this.timer.unref();}
 onModuleDestroy(){if(this.timer)clearInterval(this.timer);}
 async list(user:any,q:any){const v=parse(componentPageInput,q),where:any=user.role==='ADMIN'?{}:{ownerId:user.id};
 if(restricted(user)){const businesses=user.dataScope.businesses||[],assetIds=user.dataScope.assetIds||[];const allowed=await this.db.$queryRaw<Array<{id:string}>>`SELECT b.id FROM "AgentInstallBatch" b WHERE b."ownerId"=${user.id} AND NOT EXISTS (SELECT 1 FROM "AgentInstallTarget" t LEFT JOIN "Asset" a ON a.id=t."assetId" WHERE t."batchId"=b.id AND (a.id IS NULL OR NOT (a.id=ANY(${assetIds}::text[]) OR COALESCE(a.business=ANY(${businesses}::text[]),FALSE))))`;where.id={in:allowed.map(b=>b.id)};}
 const[rows,total]=await Promise.all([this.db.agentInstallBatch.findMany({where,include:{targets:{orderBy:{ordinal:'asc'}}},take:v.pageSize,skip:(v.page-1)*v.pageSize,orderBy:[{createdAt:'desc'},{id:'asc'}]}),this.db.agentInstallBatch.count({where})]);return {items:rows.map(safeBatch),total};}
 async create(user:any,body:unknown){if(!['ADMIN','OPERATOR'].includes(user.role))throw new ForbiddenException();const v=parse(sshDeploymentInput,body);if(new Set(v.targets.map(t=>t.assetId)).size!==v.targets.length)throw new BadRequestException('目标不能重复');
  const release=await this.db.agentRelease.findUniqueOrThrow({where:{id:v.releaseId}});if(release.status!=='PUBLISHED'||release.revokedAt)throw new ConflictException('请使用已发布版本');verifyArtifactManifest(release,process.env.AGENT_UPGRADE_PUBLIC_KEY||'');validateInstallationCompatibility(v,release.version);
  const targets:Array<{assetId:string;hostKey:string;address:string;ordinal:number}>=[];for(const [ordinal,target]of v.targets.entries()){await assertScope(this.db,user,'assets',target.assetId);const asset=await this.db.asset.findUniqueOrThrow({where:{id:target.assetId}});if(asset.archivedAt||!asset.ip||!isIP(asset.ip)||v.business&&asset.business!==v.business)throw new BadRequestException('目标必须是授权、未归档且配置了明确 IP 的资产');targets.push({...target,address:asset.ip,ordinal});}
  if(v.authMode==='ASSET_PASSWORD')for(const target of targets){const access=await this.db.assetRemoteAccess.findUnique({where:{assetId:target.assetId}});if(!access||access.address!==target.address||access.hostKey!==target.hostKey||access.port!==v.port||v.username!=='root')throw new BadRequestException('请先配置目标当前 IP 的 root 管理连接');}
  const {name,username,privateKey,targets:ignored,concurrency,stopOnFailure,port,...profile}=v;delete profile.targetAssetId;
  return this.db.$transaction(async tx=>{const row=await tx.agentInstallBatch.create({data:{name,ownerId:user.id,releaseId:v.releaseId,profile:profile as any,username,port,credential:seal(privateKey||'ASSET_MANAGED_PASSWORD'),concurrency,stopOnFailure,targets:{create:targets}},include:{targets:true}});await tx.audit.create({data:{actor:user.email,action:'CREATE',resource:'agent-install-batches',resourceId:row.id,detail:{assetIds:targets.map(t=>t.assetId),concurrency}}});return safeBatch(row);});
 }
 private async owned(tx:any,user:any,id:string){const row=await tx.agentInstallBatch.findUnique({where:{id},include:{targets:true}});if(!row||user.role!=='ADMIN'&&row.ownerId!==user.id)throw new NotFoundException();return row;}
 async state(user:any,id:string,action:'start'|'cancel'|'retry',body:unknown={}){if(!['ADMIN','OPERATOR'].includes(user.role))throw new ForbiddenException();return this.db.$transaction(async tx=>{
  await tx.$queryRaw`SELECT pg_advisory_xact_lock(hashtext('selfguard-ssh-install'))::text`;const row=await this.owned(tx,user,id);
  if(action==='start'){const v=parse(z.object({assetIds:z.array(z.string().uuid()).min(1).max(1000)}).strict(),body);if(!['DRAFT','PAUSED'].includes(row.status)||JSON.stringify([...v.assetIds].sort())!==JSON.stringify(row.targets.map((t:any)=>t.assetId).sort()))throw new ConflictException('需明确确认原批次目标，且批次处于草稿或暂停状态');for(const target of row.targets)await assertScope(tx,user,'assets',target.assetId);await tx.agentInstallBatch.update({where:{id},data:{status:'RUNNING'}});
  }else if(action==='cancel'){if(!['DRAFT','RUNNING','PAUSED','CANCELLING'].includes(row.status))throw new ConflictException('批次已结束');await tx.agentInstallTarget.updateMany({where:{batchId:id,status:'WAITING'},data:{status:'CANCELLED',detail:'取消后续目标，未进行卸载'}});await tx.agentInstallBatch.update({where:{id},data:{status:row.targets.some((t:any)=>t.status==='RUNNING')?'CANCELLING':'CANCELLED'}});
  }else{const v=parse(z.object({targetId:z.string().uuid()}).strict(),body),target=row.targets.find((t:any)=>t.id===v.targetId);if(!target||!['FAILED','PARTIAL','UNKNOWN'].includes(target.status)||!['PAUSED','COMPLETED'].includes(row.status))throw new ConflictException('只能重试已结束或暂停批次中的失败目标');await assertScope(tx,user,'assets',target.assetId);await tx.agentInstallTarget.update({where:{id:target.id},data:{status:'WAITING',leaseUntil:null,detail:'等待重新领取目标授权'}});await tx.agentInstallBatch.update({where:{id},data:{status:'PAUSED'}});}
  await tx.audit.create({data:{actor:user.email,action:action.toUpperCase(),resource:'agent-install-batches',resourceId:id}});return {ok:true};
 });}
 async tick(){if(this.ticking)return;this.ticking=true;try{
  const work=await this.db.$transaction(async tx=>{await tx.$queryRaw`SELECT pg_advisory_xact_lock(hashtext('selfguard-ssh-install'))::text`;
   const corrected=await tx.$queryRaw<Array<{id:string;status:string;targetId:string}>>`UPDATE "AgentInstallation" i SET status=CASE WHEN t.status='FAILED' AND i."assetId" IS NOT NULL THEN 'UNKNOWN' ELSE t.status END,detail=t.detail,"updatedAt"=NOW() FROM "AgentInstallTarget" t WHERE t."installationId"=i.id AND t.status IN ('FAILED','UNKNOWN','PARTIAL') AND i.status IN ('WAITING','PREFLIGHT','INSTALLING','REGISTERED','SERVICE_STARTING') RETURNING i.id,i.status,t.id AS "targetId"`;if(corrected.length)await tx.audit.createMany({data:corrected.map(row=>({actor:'installer-worker',action:'SYNC_REMOTE_INSTALL_STATE',resource:'agent-installations',resourceId:row.id,detail:{status:row.status,targetId:row.targetId}}))});
   const reconciled=await tx.$queryRaw<Array<{id:string;batchId:string;installationId:string}>>`WITH ready AS (SELECT t.id FROM "AgentInstallTarget" t JOIN "AgentInstallation" i ON i.id=t."installationId" WHERE t.status IN ('UNKNOWN','PARTIAL','FAILED') AND i.status='SUCCEEDED' ORDER BY t."updatedAt",t.id LIMIT 100 FOR UPDATE OF t SKIP LOCKED) UPDATE "AgentInstallTarget" t SET status='SUCCEEDED',detail='已按后续安装验收记录核对为接入已验证',"leaseUntil"=NULL,"updatedAt"=NOW() FROM ready WHERE t.id=ready.id RETURNING t.id,t."batchId",t."installationId"`;
   if(reconciled.length)await tx.audit.createMany({data:reconciled.map(t=>({actor:'installer-worker',action:'RECONCILE_VERIFIED',resource:'agent-install-targets',resourceId:t.id,detail:{batchId:t.batchId,installationId:t.installationId}}))});

   const expired=await tx.agentInstallTarget.findMany({where:{status:'RUNNING',leaseUntil:{lt:new Date()}},take:100});for(const t of expired){const installation=t.installationId?await tx.agentInstallation.findUnique({where:{id:t.installationId}}):null;await tx.agentInstallTarget.update({where:{id:t.id},data:{status:installation?.status==='SUCCEEDED'?'SUCCEEDED':'UNKNOWN',detail:'工作节点租约中断，按安装验收记录核对；未自动重新执行'}});}
   const batches=await tx.agentInstallBatch.findMany({where:{status:{in:['RUNNING','CANCELLING']}},include:{targets:{orderBy:{ordinal:'asc'}}},orderBy:{createdAt:'asc'},take:100});let slots=20-await tx.agentInstallTarget.count({where:{status:'RUNNING'}});const selected=[];
   for(const b of batches){const active=b.targets.filter(t=>t.status==='RUNNING').length,pending=b.targets.filter(t=>t.status==='WAITING');if(b.status==='CANCELLING'){if(!active)await tx.agentInstallBatch.update({where:{id:b.id},data:{status:'CANCELLED'}});continue;}if(b.stopOnFailure&&b.targets.some(t=>['FAILED','PARTIAL','UNKNOWN'].includes(t.status))){await tx.agentInstallBatch.update({where:{id:b.id},data:{status:'PAUSED'}});continue;}if(!active&&!pending.length){await tx.agentInstallBatch.update({where:{id:b.id},data:{status:'COMPLETED'}});continue;}
    for(const t of pending.slice(0,Math.max(0,Math.min(slots,b.concurrency-active)))){const claimed=await tx.agentInstallTarget.update({where:{id:t.id},data:{status:'RUNNING',leaseUntil:new Date(Date.now()+15*60000),attempts:{increment:1},detail:'正在预检与受控安装'}});selected.push({batch:b,target:claimed});slots--;}
   }return selected;
  });for(const task of work){this.running.add(task.target.id);void this.execute(task.batch,task.target).catch(()=>Logger.warn('SSH installation failed; target state recorded','SshInstallation')).finally(()=>this.running.delete(task.target.id));}
 }catch{Logger.warn('SSH install scheduling unavailable; leases preserve incomplete state','SshInstallation');}finally{this.ticking=false;}}
 private async execute(batch:any,target:any){let directory:string|undefined,installationId:string|undefined;let status='FAILED',detail='预检或安装失败；未持久化远程原始输出以避免秘密泄露';
  try{const owner=await this.db.user.findUniqueOrThrow({where:{id:batch.ownerId}});if(owner.disabled||!['ADMIN','OPERATOR'].includes(owner.role))throw new ForbiddenException();await assertScope(this.db,owner,'assets',target.assetId);const asset=await this.db.asset.findUniqueOrThrow({where:{id:target.assetId}});if(asset.archivedAt||asset.ip!==target.address)throw new ConflictException('资产地址或授权已变化');const profile=batch.profile as any;
   const task=await this.installations.createInstallation(owner,{...Object.fromEntries(Object.entries(profile).filter(([key])=>key!=='authMode')),targetAssetId:asset.id,business:asset.business||undefined});installationId=task.id;await this.db.agentInstallation.updateMany({where:{id:task.id,status:'WAITING'},data:{status:'PREFLIGHT',detail:'平台正在通过 SSH 检查主机和平台 API 连通性，随后下载并安装固定版本'}});await this.db.agentInstallTarget.updateMany({where:{id:target.id,status:'RUNNING',attempts:target.attempts},data:{installationId}});
   const release=await this.db.agentRelease.findUniqueOrThrow({where:{id:batch.releaseId}});
   if(profile.authMode==='ASSET_PASSWORD'){const access=await this.db.assetRemoteAccess.findUnique({where:{assetId:asset.id}});if(!access||access.address!==target.address||access.hostKey!==target.hostKey||access.port!==batch.port)throw new ConflictException('管理连接已变化，请重新核对安装目标');try{await runPasswordSsh(access,unseal(access.credential),remoteInstallCommand(profile.server,task.id,release.sha256,process.env.AGENT_UPGRADE_PUBLIC_KEY||'',profile.caCertificate||'',task.profile),task.ticket+'\n',10*60000);}catch(e){detail=e instanceof RemoteSshError?e.message:detail;if(e instanceof RemoteSshError&&e.uncertain)status='UNKNOWN';throw e;}}else{directory=await mkdtemp(join(tmpdir(),'selfguard-ssh-'));const keyFile=join(directory,'key'),knownHosts=join(directory,'known_hosts');await writeFile(keyFile,unseal(batch.credential),{mode:0o600});await writeFile(knownHosts,(batch.port===22?target.address:'['+target.address+']:'+batch.port)+' '+target.hostKey+'\n',{mode:0o600});
   const args=sshArguments(target.address,batch.port,batch.username,keyFile,knownHosts,remoteInstallCommand(profile.server,task.id,release.sha256,process.env.AGENT_UPGRADE_PUBLIC_KEY||'',profile.caCertificate||'',task.profile));
   await new Promise<void>((resolve,reject)=>{const child=spawn(process.env.SSH_CLIENT_BINARY||'/usr/bin/ssh',args,{stdio:['pipe','ignore','pipe'],env:{PATH:'/usr/bin:/bin',LANG:'C',HOME:directory}});let diagnostic='';child.stderr?.on('data',part=>{if(diagnostic.length<16384)diagnostic+=part.toString().slice(0,16384-diagnostic.length);});const timeout=setTimeout(()=>{child.kill('SIGKILL');status='UNKNOWN';detail='远程连接超时，实际修改状态需要核对';reject(new Error('remote completion unknown'));},10*60000);child.once('error',e=>{clearTimeout(timeout);reject(e);});child.once('close',code=>{clearTimeout(timeout);if(code===0)resolve();else{detail=sshFailureReason(diagnostic);if(installationDiagnostic(diagnostic)?.uncertain)status='UNKNOWN';reject(new Error('SSH execution failed'));}});child.stdin.on('error',()=>{});child.stdin.end(task.ticket+'\n');});}
   const result=await this.db.agentInstallation.findUniqueOrThrow({where:{id:task.id}});status=result.status==='SUCCEEDED'?'SUCCEEDED':'PARTIAL';detail=status==='SUCCEEDED'?'目标版本服务与平台接入已验收':'远程命令结束，但平台验收尚未完成';
  }catch{if(installationId){const result=await this.db.agentInstallation.findUnique({where:{id:installationId}});if(result?.status==='SUCCEEDED'){status='SUCCEEDED';detail='连接中断后通过安装记录核对为接入已验证';}else if(result?.assetId){status='UNKNOWN';detail='已开始安装，但连接或服务验收未确认；保留目标身份与恢复材料';}}}
  finally{if(directory)await rm(directory,{recursive:true,force:true});if(installationId)await this.db.$transaction(async tx=>{await tx.$queryRaw`SELECT pg_advisory_xact_lock(hashtext(${'installation:'+installationId}))::text`;const row=await tx.agentInstallation.findUnique({where:{id:installationId}});const data=row&&installationTransportData(row,status,detail);if(data)await tx.agentInstallation.update({where:{id:installationId},data});});await this.db.agentInstallTarget.updateMany({where:{id:target.id,status:'RUNNING',attempts:target.attempts},data:{status,detail,leaseUntil:null}});await this.db.audit.create({data:{actor:'installer-worker',action:status,resource:'agent-install-targets',resourceId:target.id,detail:{batchId:batch.id,installationId:installationId||null}}});}
 }
}
@Controller('agent-install-batches') @UseGuards(AuthGuard)
export class SshInstallationsController{
 constructor(@Inject(SshInstallationService)private svc:SshInstallationService,@Inject(Db)private db:Db){}
 @Get() list(@Req()req:any,@Query()q:any){return this.svc.list(req.user,q);}
 @Post() async create(@Req()req:any,@Body()body:unknown){allow(req,['ADMIN','OPERATOR']);return this.svc.create(req.user,await platformInstallationBody(this.db,body));}
 @Post(':id/:action') state(@Req()req:any,@Param('id')id:string,@Param('action')action:string,@Body()body:unknown){allow(req,['ADMIN','OPERATOR']);if(!['start','cancel','retry'].includes(action))throw new NotFoundException();return this.svc.state(req.user,id,action as any,body);}
}
