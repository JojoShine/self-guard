import {configuredPlatform} from './agent-platform';
import {authorizeTask} from './task-signing';
import {verifyExecutorResult} from './executor-proof';
import { Body, Controller, Get, Post, Param, Req, Res, Inject, UseGuards, BadRequestException, ConflictException, UnauthorizedException } from '@nestjs/common';
import { createPublicKey, verify } from 'node:crypto';
import { z } from 'zod';
import { Db } from './db';
import { Platform } from './platform';
import { AuthGuard, allow, bearer } from './auth';
import { hashToken } from './security';
import { parse } from './validation';
import {InstallationService,taskVerificationKey,activeInstallationWhere} from './installations';
import {verifyArtifactManifest} from './construction-contracts';import {verifyDownloadGrant} from './artifact-grants';

const release = z.object({manifestBytes:z.string().min(1).max(90000),signature:z.string().max(100),artifactUrl:z.string().url().max(2048)}).strict();
const manifest = z.object({version:z.string().regex(/^[0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9.-]+)?$/),sequence:z.number().int().positive().safe(),sha256:z.string().regex(/^[a-f0-9]{64}$/),size:z.number().int().min(1).max(64<<20),os:z.enum(['linux','darwin','windows']),architecture:z.enum(['amd64','arm64']),expiresAt:z.string().datetime()}).strict();
export function validateRelease(input:z.infer<typeof release>,publicKey:string,origins:string[]) {
 try {
  const u=new URL(input.artifactUrl);
  if(!['http:','https:'].includes(u.protocol)||u.username||u.password||u.hash||!origins.includes(u.origin))throw new Error('untrusted artifact origin');
  const key=Buffer.from(publicKey,'base64'),raw=Buffer.from(input.manifestBytes,'base64'),signature=Buffer.from(input.signature,'base64');
  if(key.length!==32||raw.length>65536||signature.length!==64||!verify(null,raw,createPublicKey({key:Buffer.concat([Buffer.from('302a300506032b6570032100','hex'),key]),format:'der',type:'spki'}),signature))throw new Error('invalid signature');
  const m=manifest.parse(JSON.parse(raw.toString('utf8')));
  if(Date.parse(m.expiresAt)<=Date.now())throw new Error('expired release');
  return m;
 }catch {throw new BadRequestException('发布签名、清单或可信下载来源无效');}
}
async function trustedRelease(input:z.infer<typeof release>,db:Db){const platform=await configuredPlatform(db);return validateRelease(input,process.env.AGENT_UPGRADE_PUBLIC_KEY||'',[...(process.env.AGENT_UPGRADE_ORIGINS||'').split(',').map(x=>x.trim()).filter(Boolean),...(platform?.server?[new URL(platform.server).origin]:[])]);}
async function lock(tx:any){await tx.$queryRaw`SELECT pg_advisory_xact_lock(hashtext('selfguard-agent-rollouts'))::text`;}
async function managedRelease(db:any,envelope:any){
 if(!envelope.managedReleaseId)return null;const row=await db.agentRelease.findUnique({where:{id:envelope.managedReleaseId}});
 if(!row||row.status!=='PUBLISHED'||row.revokedAt||row.manifestBytes!==envelope.manifestBytes||row.signature!==envelope.signature)throw new ConflictException('受管发行版本未发布、已撤回或签名绑定不一致');
 verifyArtifactManifest(row,process.env.AGENT_UPGRADE_PUBLIC_KEY||'');return row;
}

@Controller('rollouts')
@UseGuards(AuthGuard)
export class RolloutsController {
 constructor(@Inject(Db) private db:Db,@Inject(Platform) private p:Platform){}
 @Get() async list(@Req() req:any){allow(req,['ADMIN']);return this.db.agentRollout.findMany({include:{targets:true},orderBy:{createdAt:'desc'},take:100});}
 @Post() async create(@Req() req:any,@Body() body:unknown){
  allow(req,['ADMIN']);
  const v=parse(release.extend({managedReleaseId:z.string().uuid().optional(),targetIds:z.array(z.string().min(1).max(200)).min(1).max(1000),batchSize:z.number().int().min(1).max(100).default(1)}).strict(),body);
  const envelope={manifestBytes:v.manifestBytes,signature:v.signature,artifactUrl:v.artifactUrl,...(v.managedReleaseId?{managedReleaseId:v.managedReleaseId}:{})};const m=await trustedRelease(envelope,this.db);
  if(new Set(v.targetIds).size!==v.targetIds.length)throw new BadRequestException('目标不能重复');
  return this.db.$transaction(async tx=>{
   const assets=await tx.asset.findMany({where:{id:{in:v.targetIds},archivedAt:null}});
   if(assets.length!==v.targetIds.length||assets.some(a=>a.os!==m.os || (a.inventory as any)?.architecture!==m.architecture))throw new BadRequestException('目标不存在、已归档或操作系统/架构不匹配');
   if(v.managedReleaseId){await managedRelease(tx,envelope);for(const asset of assets)await assertScope(tx,req.user,'assets',asset.id);if(assets.some(a=>!a.executorPublicKey||(a.inventory as any)?.agentDiagnostics?.executorEnabled===false||(a.inventory as any)?.agentDiagnostics?.managedReleaseDownload!==true))throw new BadRequestException('请先通过新版安装器启用执行器与受管下载能力，再创建制品库升级计划');}
   const row=await tx.agentRollout.create({data:{version:m.version,envelope,artifactUrl:v.artifactUrl,batchSize:v.batchSize,targetIds:v.targetIds,targets:{create:v.targetIds.map((assetId,ordinal)=>({assetId,ordinal}))}}});
   await this.p.audit(tx,req.user.email,'CREATE','rollouts',row.id,{version:m.version,targetIds:v.targetIds});return row;
  });
 }
 @Post(':id/approve') async approve(@Req() req:any,@Param('id') id:string,@Body() body:unknown){
  allow(req,['ADMIN']);const v=parse(z.object({targetIds:z.array(z.string().min(1).max(200)).min(1).max(1000)}).strict(),body);
  return this.db.$transaction(async tx=>{await lock(tx);const row=await tx.agentRollout.findUniqueOrThrow({where:{id}});
   if(!['DRAFT','PAUSED'].includes(row.status))throw new ConflictException('发布不在待审批或暂停状态');
   if(JSON.stringify(row.targetIds)!==JSON.stringify(v.targetIds))throw new ConflictException('审批必须明确确认原始有序目标');
   await trustedRelease(row.envelope as any,this.db);
   await managedRelease(tx,row.envelope);
   if(row.status==='PAUSED'&&await tx.agentRolloutTarget.count({where:{rolloutId:id,OR:[{status:{in:['FAILED','UNKNOWN']}},{status:{in:['CLAIMED','STAGED']},claimedAt:{lt:new Date(Date.now()-10*60000)}}]}}))throw new ConflictException('先核对失败或未知目标；不会自动重新执行已有变更，请按明确结果创建新计划');
   if(await tx.agentRollout.count({where:{id:{not:id},status:{in:['RUNNING','PAUSED']}}}))throw new ConflictException('请先完成或取消现有发布');
   await this.p.audit(tx,req.user.email,'APPROVE','rollouts',id,{targetIds:v.targetIds});return tx.agentRollout.update({where:{id},data:{status:'RUNNING'}});
  });
 }
 @Post(':id/pause') async pause(@Req() req:any,@Param('id') id:string){return this.setState(req,id,'PAUSED');}
 @Post(':id/cancel') async cancel(@Req() req:any,@Param('id') id:string){return this.setState(req,id,'CANCELLED');}
 private async setState(req:any,id:string,status:string){allow(req,['ADMIN']);return this.db.$transaction(async tx=>{await lock(tx);const row=await tx.agentRollout.findUniqueOrThrow({where:{id}});if(!['RUNNING','PAUSED','DRAFT'].includes(row.status))throw new ConflictException('发布已结束');await this.p.audit(tx,req.user.email,status,'rollouts',id);return tx.agentRollout.update({where:{id},data:{status}});});}
}

@Controller('agent/rollout')
export class AgentRolloutController {
 constructor(@Inject(Db) private db:Db){}
 private async identity(req:any){const token=bearer(req);if(!token)throw new UnauthorizedException();const a=await this.db.asset.findUnique({where:{tokenHash:hashToken(token)}});if(!a||a.archivedAt)throw new UnauthorizedException();return a;}
 private async currentIdentity(tx:any,id:string,req:any){await tx.$queryRaw`SELECT id FROM "Asset" WHERE id=${id} FOR UPDATE`;const current=await tx.asset.findUnique({where:{id}});if(!current||current.archivedAt||current.tokenHash!==hashToken(bearer(req)||''))throw new UnauthorizedException('组件凭据已撤销或身份无效');return current;}
 @Get() async poll(@Req() req:any){const initial=await this.identity(req);return this.db.$transaction(async tx=>{
  await lock(tx);const a=await this.currentIdentity(tx,initial.id,req);if(await tx.agentInstallation.count({where:activeInstallationWhere(a.id)}))return {item:null};const rows=await tx.agentRollout.findMany({where:{status:'RUNNING'},include:{targets:{orderBy:{ordinal:'asc'}}}});
  for(const row of rows){
   const timed=row.targets.filter(t=>['CLAIMED','STAGED'].includes(t.status)&&t.claimedAt&&t.claimedAt.getTime()<Date.now()-10*60000);
   if(timed.length||row.targets.some(t=>t.status==='FAILED')){await tx.agentRollout.update({where:{id:row.id},data:{status:'PAUSED'}});return {item:null};}
   const unresolved=row.targets.filter(t=>t.status!=='RUNNING');if(!unresolved.length){await tx.agentRollout.update({where:{id:row.id},data:{status:'COMPLETED'}});continue;}
   // Canary first, then fixed consecutive batches; every member must restart and heartbeat before advancement.
   const first=unresolved[0].ordinal;const start=first===0?0:1+Math.floor((first-1)/row.batchSize)*row.batchSize;const end=start===0?1:start+row.batchSize;
   const target=row.targets.find(t=>t.assetId===a.id&&t.ordinal>=start&&t.ordinal<end&&t.status==='PENDING');if(!target)continue;
   let managed:any;try{await trustedRelease(row.envelope as any,this.db);managed=await managedRelease(tx,row.envelope);}catch{await tx.agentRollout.update({where:{id:row.id},data:{status:'PAUSED'}});return {item:null};}
   const envelope=row.envelope as any;const manifest=await trustedRelease(envelope,this.db);
   const artifactUrl=managed?envelope.artifactUrl.replace(/\/api\/agent-releases\/[^/]+\/download$/, '')+'/api/agent/rollout/'+target.id+'/artifact':envelope.artifactUrl;
   const downloadGrant=managed?authorizeTask({id:target.id,assetId:a.id,template:'DOWNLOAD_AGENT_RELEASE',parameters:{releaseId:managed.id,sha256:managed.sha256},expiresAt:manifest.expiresAt}):undefined;
   const authorization=authorizeTask({id:target.id,assetId:a.id,template:'UPGRADE',parameters:{artifactUrl,manifestBytes:envelope.manifestBytes,signature:envelope.signature,...(downloadGrant?{downloadGrant}:{})},expiresAt:manifest.expiresAt});
   if(managed&&!downloadGrant){await tx.agentRollout.update({where:{id:row.id},data:{status:'PAUSED'}});return {item:null};}
   if(a.executorPublicKey&&!authorization){await tx.agentRollout.update({where:{id:row.id},data:{status:'PAUSED'}});return {item:null};}
   await tx.agentRolloutTarget.update({where:{id:target.id},data:{status:'CLAIMED',claimedAt:new Date()}});
   await tx.audit.create({data:{actor:'agent:'+a.id,action:'CLAIM',resource:'rollouts',resourceId:row.id,detail:{targetId:target.id}}});
   return {item:{id:target.id,...row.envelope as any,artifactUrl,...(downloadGrant?{downloadGrant}:{}),authorization}};
  }return {item:null};
 });}
 async authorizedArtifact(id:string,header:string){
  if(typeof header!=='string'||!header.startsWith('SelfGuardDownload ')||header.length>36000)throw new UnauthorizedException('下载授权无效');let grant:unknown;
  try{const encoded=header.slice(18),bytes=Buffer.from(encoded,'base64');if(bytes.toString('base64')!==encoded)throw Error();grant=JSON.parse(bytes.toString('utf8'));}catch{throw new UnauthorizedException('下载授权无效');}
  return this.db.$transaction(async tx=>{await lock(tx);const target=await tx.agentRolloutTarget.findUnique({where:{id},include:{rollout:true}});if(!target||!['CLAIMED','STAGED'].includes(target.status)||target.rollout.status!=='RUNNING')throw new UnauthorizedException('下载任务已结束或暂停');const asset=await tx.asset.findUnique({where:{id:target.assetId}});if(!asset||asset.archivedAt||!asset.tokenHash)throw new UnauthorizedException('目标身份已失效');const release=await managedRelease(tx,target.rollout.envelope);if(!release||!verifyDownloadGrant(grant,{id,assetId:target.assetId,releaseId:release.id,sha256:release.sha256},taskVerificationKey()||''))throw new UnauthorizedException('下载授权无效');await tx.audit.create({data:{actor:'agent:'+asset.id,action:'DOWNLOAD_GRANTED_RELEASE',resource:'rollouts',resourceId:target.rolloutId,detail:{targetId:id,releaseId:release.id,sha256:release.sha256}}});return new InstallationService(tx as any).downloadRelease(release.id);},{timeout:30000});
 }
 @Get(':id/artifact') async artifact(@Req()req:any,@Param('id')id:string,@Res()res:any){const {bytes,release}=await this.authorizedArtifact(id,req.headers.authorization);res.setHeader('Content-Type','application/octet-stream');res.setHeader('Cache-Control','no-store');res.setHeader('X-Content-SHA256',release.sha256);res.send(bytes);}
 @Post(':id/result') async result(@Req() req:any,@Param('id') id:string,@Body() body:unknown){
  const initial=await this.identity(req);const v=parse(z.object({status:z.enum(['STAGED','RUNNING','FAILED']),version:z.string().max(128),executorResult:z.object({success:z.boolean(),evidence:z.string().max(16000),details:z.record(z.string(),z.unknown()).optional()}).strict().optional()}).strict(),body);
  return this.db.$transaction(async tx=>{await lock(tx);const a=await this.currentIdentity(tx,initial.id,req);const target=await tx.agentRolloutTarget.findUnique({where:{id},include:{rollout:true}});
   if(!target||target.assetId!==a.id)throw new UnauthorizedException();
   if(target.status===v.status)return {ok:true};
   if(!['CLAIMED','STAGED'].includes(target.status))throw new ConflictException('目标尚未领取或结果已完成');
   if(a.executorPublicKey&&v.status!=='FAILED'&&(!v.executorResult||!verifyExecutorResult(a.executorPublicKey,id,a.id,v.executorResult)||!v.executorResult.success||v.executorResult.details?.upgradeStaged!=='true'||v.executorResult.details?.upgradeVersion!==target.rollout.version||(v.status==='RUNNING'&&(v.executorResult.details?.executorVersion!==v.version||v.executorResult.details?.executorProcess===v.executorResult.details?.stageProcess)))){
    await tx.agentRolloutTarget.update({where:{id},data:{status:'UNKNOWN',reportedAt:new Date(),evidence:'privileged upgrade proof missing or invalid'}});await tx.agentRollout.update({where:{id:target.rolloutId},data:{status:'PAUSED'}});return {ok:false,proofRejected:true};
   }
   if(v.status==='RUNNING'){
    const fresh=await tx.asset.findUniqueOrThrow({where:{id:a.id}});const diagnostics=(fresh.inventory as any)?.agentDiagnostics;
    if(target.status!=='STAGED'||v.version!==target.rollout.version||diagnostics?.version!==v.version||!target.claimedAt||!fresh.lastSeen||fresh.lastSeen<target.claimedAt)throw new ConflictException('等待重启后的版本心跳验证');
   }
   await tx.agentRolloutTarget.update({where:{id},data:{status:v.status,reportedAt:new Date(),evidence:JSON.stringify(v)}});
   if(v.status==='FAILED')await tx.agentRollout.updateMany({where:{id:target.rolloutId,status:'RUNNING'},data:{status:'PAUSED'}});
   await tx.audit.create({data:{actor:'agent:'+a.id,action:v.status,resource:'rollouts',resourceId:target.rolloutId,detail:{targetId:id,version:v.version}}});
   if(v.status==='RUNNING'&&!(await tx.agentRolloutTarget.count({where:{rolloutId:target.rolloutId,status:{not:'RUNNING'}}})))await tx.agentRollout.updateMany({where:{id:target.rolloutId,status:'RUNNING'},data:{status:'COMPLETED'}});
   return {ok:true};
  });
 }
}

import { assertScope } from './scope';
@Controller('repair')
@UseGuards(AuthGuard)
export class RepairController {
 constructor(@Inject(Db) private db:Db,@Inject(Platform) private p:Platform){}
 @Post(':id/verify') async verify(@Req() req:any,@Param('id') id:string){return this.create(req,id,'VERIFY_READ');}
 @Post(':id/rollback') async rollback(@Req() req:any,@Param('id') id:string){return this.create(req,id,'ROLLBACK');}
 private async create(req:any,id:string,template:string){
  allow(req,template==='VERIFY_READ'?['ADMIN','ANALYST']:['ADMIN','OPERATOR']);
  await assertScope(this.db,req.user,'tasks',id);
  return this.db.$transaction(async tx=>{
   const original=await tx.task.findUniqueOrThrow({where:{id}});
   if(!['FILE_PERMISSION','CONFIG_VALUE','SERVICE_STATE','ROLLBACK'].includes(original.template)||!(original.result as any)?.success||!['VERIFYING','SUCCEEDED','FAILED','UNKNOWN'].includes(original.status))throw new ConflictException('仅可验证或回滚有成功执行记录的修复任务');
   if(template==='ROLLBACK'&&original.template==='ROLLBACK')throw new ConflictException('回滚任务不能再次回滚');
   const row=await tx.task.create({data:{title:(template==='VERIFY_READ'?'验证: ':'回滚: ')+original.title,assetId:original.assetId,findingId:original.findingId,template,parameters:{originalTaskId:id},rollbackOf:id,status:template==='VERIFY_READ'?'APPROVED':'PENDING',requestedBy:req.user.email,approvedBy:template==='VERIFY_READ'?req.user.email:null,expiresAt:new Date(Date.now()+30*60000)}});
   await this.p.audit(tx,req.user.email,template,'tasks',row.id,{originalTaskId:id});return row;
  });
 }
}
