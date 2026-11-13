import {isPublicReadOnlyUser} from './public-demo';
import {validPlatformURL} from './platform-path';
import {platformInstallationBody} from './agent-platform';
import {assertGlobal} from './scope';
import {hostWafBindingInput} from './host-waf';
import {Body,Controller,Get,Post,Param,Query,Req,Res,UseGuards,Inject,Injectable,BadRequestException,ConflictException,NotFoundException,UnauthorizedException,ForbiddenException} from '@nestjs/common';
import {createHash,createPublicKey,verify,X509Certificate} from 'node:crypto';
import {constants as fsConstants} from 'node:fs';
import {mkdir,open,link,unlink,lstat} from 'node:fs/promises';
import {resolve,join} from 'node:path';
import {z} from 'zod';
import {Db} from './db';import {AuthGuard,allow,bearer} from './auth';
import {hashToken,newToken,equalSecret} from './security';import {parse,text} from './validation';import {restricted,assertScope} from './scope';
import {componentPageInput,signedArtifactInput,verifyArtifactManifest,verifyPackageManifest} from './construction-contracts';

const digestInput=z.string().regex(/^[a-f0-9]{64}$/);
function artifactRoot(){return resolve(process.env.AGENT_ARTIFACT_DIR||'./storage/agent-artifacts');}
async function artifactPath(root:string,digest:string){
 parse(digestInput,digest);await mkdir(root,{recursive:true,mode:0o700});
 const info=await lstat(root);if(!info.isDirectory()||info.isSymbolicLink()||(info.mode&0o022))throw new BadRequestException('制品目录必须是受管且不可被其他用户写入的目录');
 return join(root,digest);
}
export async function readArtifact(root:string,digest:string,size:number){
 const path=await artifactPath(root,digest),f=await open(path,fsConstants.O_RDONLY|fsConstants.O_NOFOLLOW);
 try{const stat=await f.stat();if(!stat.isFile()||stat.size!==size||size>64<<20||stat.nlink!==1)throw new BadRequestException('制品文件不符合清单');
  const bytes=await f.readFile();if(createHash('sha256').update(bytes).digest('hex')!==digest)throw new BadRequestException('制品摘要不匹配');return bytes;
 }finally{await f.close();}
}
export async function storeArtifact(root:string,digest:string,size:number,bytes:Buffer){
 if(bytes.length!==size||size>64<<20||createHash('sha256').update(bytes).digest('hex')!==digest)throw new BadRequestException('上传内容与签名清单不一致');
 const path=await artifactPath(root,digest),tmp=path+'.'+newToken()+'.pending';
 const file=await open(tmp,'wx',0o600);
 try{await file.writeFile(bytes);await file.sync();}finally{await file.close();}
 try{await link(tmp,path);}catch(e:any){if(e.code!=='EEXIST')throw e;await readArtifact(root,digest,size);}finally{await unlink(tmp);}
}
const releaseInput=signedArtifactInput.extend({sourceDigest:digestInput,license:z.string().trim().min(1).max(200),sbom:z.object({bomFormat:z.literal('CycloneDX'),specVersion:z.string(),components:z.array(z.record(z.string(),z.unknown())).max(10000)}).passthrough(),channel:z.enum(['stable','canary']).default('stable')}).strict();
const collectionPath=z.string().max(1000).refine(p=>/^\/[A-Za-z0-9_./-]+$/.test(p)&&p!=='/'&&!p.split('/').some(part=>part==='.'||part==='..')&&!p.includes('//')&&!p.endsWith('/'),'需要明确的绝对路径');
export const installationProfileInput=z.object({
 hostWaf:hostWafBindingInput.omit({assetId:true}).extend({siteId:z.string().uuid()}).optional(),
 releaseId:z.string().uuid(),targetAssetId:z.string().uuid().optional(),server:z.string().url().max(2048).refine(validPlatformURL,'平台地址必须是 HTTP 或 HTTPS 部署入口'),
 business:z.string().trim().min(1).max(200).optional(),tags:z.array(z.string().trim().min(1).max(100)).max(30).default([]),
 stateDir:z.string().regex(/^\/var\/lib\/selfguard-agent(?:-[a-z0-9][a-z0-9-]{0,40})?$/).default('/var/lib/selfguard-agent'),
 proxyMode:z.enum(['DIRECT','EXPLICIT','ENVIRONMENT']).optional(),
 proxyUrl:z.string().max(2048).refine(value=>{try{const u=new URL(value);return ['http:','https:'].includes(u.protocol)&&!!u.hostname&&!u.username&&!u.password&&!u.search&&!u.hash&&u.pathname==='/';}catch{return false;}},'代理需要不含凭据和路径的 HTTP(S) 地址').optional(),
 collectionRoot:collectionPath.optional(),applicationInputs:z.array(z.object({format:z.enum(['NPM_INSTALLED_TREE','PYTHON_SITE_PACKAGES','MAVEN_JAR','GO_BINARY','NPM_LOCK_FILE','CYCLONEDX_1_6']),path:collectionPath}).strict()).max(100).default([]),fimPaths:z.array(collectionPath).max(100).default([]),logPaths:z.array(collectionPath).max(100).default([]),logIncludeMessage:z.boolean().default(false),
 maxCPUs:z.number().int().min(1).max(8).default(1),maxMemoryBytes:z.number().int().min(64*1048576).max(1073741824).default(128*1048576),maxQueueBytes:z.number().int().min(1048576).max(512*1048576).default(32*1048576),bytesPerSecond:z.number().int().min(1024).max(10*1048576).default(128*1024),cpuQuotaPercent:z.number().int().min(1).max(100).default(20),
 executorEnabled:z.boolean().default(false),allowedRoot:z.string().max(1000).optional(),allowedServices:z.array(z.string().regex(/^[A-Za-z0-9@_.-]+$/)).max(100).default([]),
 caCertificate:z.string().max(32000).refine(value=>{if(!value)return true;try{const certificates=value.match(/-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/g);return !!certificates?.length&&value.replace(/-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/g,'').trim()===''&&certificates.every(pem=>new X509Certificate(pem).ca);}catch{return false;}},'需要有效的 PEM CA 证书，不得填写私钥或终端证书').optional(),
}).strict().refine(v=>!v.proxyMode||(v.proxyMode==='EXPLICIT')===!!v.proxyUrl,'指定代理需要地址；直连或环境模式不能同时填写地址').refine(v=>[...v.fimPaths,...v.logPaths,...v.applicationInputs.map(input=>input.path)].every(p=>v.collectionRoot&&p.startsWith(v.collectionRoot+'/')),'采集文件必须位于明确授权的采集目录内').refine(v=>new Set(v.applicationInputs.map(i=>i.format+'|'+i.path)).size===v.applicationInputs.length,'应用采集输入不能重复').refine(v=>!v.executorEnabled||!!v.allowedRoot&&/^\/[A-Za-z0-9_./-]+$/.test(v.allowedRoot)&&v.allowedRoot!=='/'&&!v.allowedRoot.split('/').includes('..'),'执行器需要明确的非根允许目录');
export function validateInstallationCompatibility(v:z.infer<typeof installationProfileInput>,version:string){
 const [major,minor,patch]=version.split('.').map(Number);if(new URL(v.server).pathname.replace(/\/$/,'')&&!(major>0||minor>4||minor===4&&patch>=11))throw new BadRequestException('子路径平台接入需要 Agent 0.4.11 或更高版本');if(v.server.startsWith('http:')&&!(major>0||minor>4||minor===4&&patch>=10))throw new BadRequestException('HTTP 平台接入需要 Agent 0.4.10 或更高版本，请选择支持的固定发行版本');if(v.hostWaf&&!(major>0||minor>4||minor===4&&patch>=9))throw new BadRequestException('同机 Web 接入需要 Agent 0.4.9 或更高版本');if(v.applicationInputs.length&&!(major>0||minor>=4))throw new BadRequestException('应用依赖采集需要 Agent 0.4.0 或更高版本，旧版本不能忽略此配置');if(v.proxyMode&&!(major>0||minor>3||minor===3&&patch>=9))throw new BadRequestException('明确代理方式需要 Agent 0.3.9 或更高版本');const custom=!!(v.proxyUrl||v.collectionRoot||v.fimPaths.length||v.logPaths.length||v.logIncludeMessage||v.stateDir!=='/var/lib/selfguard-agent'||v.maxCPUs!==1||v.maxMemoryBytes!==128*1048576||v.maxQueueBytes!==32*1048576||v.bytesPerSecond!==128*1024||v.cpuQuotaPercent!==20);
 if(custom&&!(major>0||minor>=3))throw new BadRequestException('采集范围、代理、自定义状态目录和资源预算需要 Agent 0.3.0 或更高版本；旧版本不会被静默当成已支持');
}
export function activeInstallationWhere(assetId:string){return {assetId,status:{in:['PREFLIGHT','INSTALLING','REGISTERED','SERVICE_STARTING','RECOVERING','PARTIAL','UNKNOWN']},leaseUntil:{gt:new Date()}};}
const claimInput=z.object({identity:text,credential:z.string().min(32).max(128),hostname:text,architecture:z.enum(['amd64','arm64'])}).strict();
const reportInput=z.object({status:z.enum(['PREFLIGHT','INSTALLING','REGISTERED','SERVICE_STARTING','PARTIAL','FAILED','SUCCEEDED']),version:z.string().max(128),detail:z.string().max(2000).default('')}).strict();
async function lock(tx:any,id:string){await tx.$queryRaw`SELECT pg_advisory_xact_lock(hashtext(${`installation:${id}`}))::text`;}
function publicInstallation(row:any){const{ticketHash,credentialHash,challenge,...safe}=row;return safe;}
export function taskVerificationKey(){
 const encoded=process.env.TASK_SIGNING_PRIVATE_KEY;if(!encoded)return undefined;const {createPrivateKey}=require('node:crypto');try{const key=createPrivateKey({key:Buffer.from(encoded,'base64'),format:'der',type:'pkcs8'});if(key.asymmetricKeyType!=='ed25519')throw Error();return createPublicKey(key).export({format:'der',type:'spki'}).subarray(-32).toString('base64');}catch{throw new BadRequestException('任务验签公钥配置无效');}
}
function currentRelease(row:any){if(!row||row.status!=='PUBLISHED'||row.revokedAt)throw new ConflictException('发行版本尚未发布或已撤回');return verifyArtifactManifest(row,process.env.AGENT_UPGRADE_PUBLIC_KEY||'');}
async function uploadedBytes(req:any){if(!req.is('application/octet-stream'))throw new BadRequestException('请上传二进制文件');const chunks:Buffer[]=[];let size=0;for await(const part of req){size+=part.length;if(size>64<<20)throw new BadRequestException('制品超过64 MiB');chunks.push(part);}return Buffer.concat(chunks);}
function assertBusiness(user:any,business?:string,targetAssetId?:string){if(restricted(user)&&!(targetAssetId&&user.dataScope.assetIds?.includes(targetAssetId))&&(!business||!user.dataScope.businesses?.includes(business)))throw new ForbiddenException('安装归属不在当前业务授权范围');}

@Injectable()
export class InstallationService{
 constructor(@Inject(Db) private db:Db){}
 async installationOptions(user:any){
  if(!['ADMIN','ANALYST','OPERATOR'].includes(user.role))throw new ForbiddenException();
  const scoped=restricted(user),businesses=await this.db.businessGroup.findMany({where:scoped?{name:{in:user.dataScope.businesses||[]}}:{},select:{name:true},orderBy:{name:'asc'}});
  return {businesses,requiresBusiness:scoped};
 }
 async listReleases(q:any){const v=parse(componentPageInput,q),where={...(v.q?{version:{contains:v.q}}:{})};const[items,total]=await Promise.all([this.db.agentRelease.findMany({where,include:{packages:{orderBy:{format:'asc'}}},orderBy:[{createdAt:'desc'},{id:'asc'}],skip:(v.page-1)*v.pageSize,take:v.pageSize}),this.db.agentRelease.count({where})]);return {items,total,trustRoot:process.env.AGENT_UPGRADE_PUBLIC_KEY||null};}
 async createRelease(user:any,body:unknown){if(user.role!=='ADMIN')throw new ForbiddenException();const v=parse(releaseInput,body),m=verifyArtifactManifest(v,process.env.AGENT_UPGRADE_PUBLIC_KEY||'');
  if(m.sequence>2147483647)throw new BadRequestException('发布序列超出数据库范围');
  return this.db.$transaction(async tx=>{const row=await tx.agentRelease.create({data:{version:m.version,sequence:m.sequence,architecture:m.architecture,sha256:m.sha256,size:m.size,...v,expiresAt:new Date(m.expiresAt),author:user.email} as any});await tx.audit.create({data:{actor:user.email,action:'CREATE',resource:'agent-releases',resourceId:row.id,detail:{version:m.version,architecture:m.architecture}}});return row;});
 }
 async uploadRelease(user:any,id:string,bytes:Buffer){if(user.role!=='ADMIN')throw new ForbiddenException();return this.db.$transaction(async tx=>{await lock(tx,'release:'+id);const row=await tx.agentRelease.findUniqueOrThrow({where:{id}});if(row.status!=='DRAFT')throw new ConflictException('已发布制品不可覆盖');verifyArtifactManifest(row,process.env.AGENT_UPGRADE_PUBLIC_KEY||'');await storeArtifact(artifactRoot(),row.sha256,row.size,bytes);await tx.audit.create({data:{actor:user.email,action:'UPLOAD_VERIFIED',resource:'agent-releases',resourceId:id,detail:{sha256:row.sha256,size:row.size}}});return {ok:true};},{timeout:30000});}
 async publishRelease(user:any,id:string){if(user.role!=='ADMIN')throw new ForbiddenException();return this.db.$transaction(async tx=>{await lock(tx,'release:'+id);const row=await tx.agentRelease.findUniqueOrThrow({where:{id}});if(row.status!=='DRAFT')throw new ConflictException('仅草稿可以发布');verifyArtifactManifest(row,process.env.AGENT_UPGRADE_PUBLIC_KEY||'');await readArtifact(artifactRoot(),row.sha256,row.size);await tx.audit.create({data:{actor:user.email,action:'PUBLISH',resource:'agent-releases',resourceId:id}});return tx.agentRelease.update({where:{id},data:{status:'PUBLISHED',publishedAt:new Date()}});},{timeout:30000});}
 async downloadRelease(id:string){const row=await this.db.agentRelease.findUnique({where:{id}});currentRelease(row);return {bytes:await readArtifact(artifactRoot(),row!.sha256,row!.size),release:row!};}
 async createPackage(user:any,releaseId:string,body:unknown){if(user.role!=='ADMIN')throw new ForbiddenException();const envelope=parse(signedArtifactInput,body);return this.db.$transaction(async tx=>{await lock(tx,'release:'+releaseId);const release=await tx.agentRelease.findUniqueOrThrow({where:{id:releaseId}});currentRelease(release);const manifest=verifyPackageManifest(envelope,process.env.AGENT_UPGRADE_PUBLIC_KEY||'',release);const row=await tx.agentReleasePackage.create({data:{releaseId,format:manifest.format,sha256:manifest.sha256,size:manifest.size,expiresAt:new Date(manifest.expiresAt),...envelope,author:user.email}});await tx.audit.create({data:{actor:user.email,action:'REGISTER_PACKAGE',resource:'agent-release-packages',resourceId:row.id,detail:{releaseId,format:manifest.format,sha256:manifest.sha256}}});return row;});}
 private async lockedPackage(tx:any,id:string){const found=await tx.agentReleasePackage.findUniqueOrThrow({where:{id}});await lock(tx,'release:'+found.releaseId);await lock(tx,'package:'+id);const row=await tx.agentReleasePackage.findUniqueOrThrow({where:{id},include:{release:true}});currentRelease(row.release);verifyPackageManifest(row,process.env.AGENT_UPGRADE_PUBLIC_KEY||'',row.release);return row;}
 async uploadPackage(user:any,id:string,bytes:Buffer){if(user.role!=='ADMIN')throw new ForbiddenException();return this.db.$transaction(async tx=>{const row=await this.lockedPackage(tx,id);if(row.status!=='DRAFT')throw new ConflictException('已发布安装包不可覆盖');await storeArtifact(artifactRoot(),row.sha256,row.size,bytes);await tx.audit.create({data:{actor:user.email,action:'UPLOAD_VERIFIED',resource:'agent-release-packages',resourceId:id,detail:{sha256:row.sha256,size:row.size}}});return {ok:true};},{timeout:30000});}
 async publishPackage(user:any,id:string){if(user.role!=='ADMIN')throw new ForbiddenException();return this.db.$transaction(async tx=>{const row=await this.lockedPackage(tx,id);if(row.status!=='DRAFT')throw new ConflictException('仅草稿安装包可以发布');await readArtifact(artifactRoot(),row.sha256,row.size);await tx.audit.create({data:{actor:user.email,action:'PUBLISH',resource:'agent-release-packages',resourceId:id}});return tx.agentReleasePackage.update({where:{id},data:{status:'PUBLISHED',publishedAt:new Date()}});},{timeout:30000});}
 async downloadPackage(id:string){const row=await this.db.agentReleasePackage.findUniqueOrThrow({where:{id},include:{release:true}});currentRelease(row.release);if(row.status!=='PUBLISHED')throw new ConflictException('安装包尚未发布');verifyPackageManifest(row,process.env.AGENT_UPGRADE_PUBLIC_KEY||'',row.release);return {bytes:await readArtifact(artifactRoot(),row.sha256,row.size),package:row};}
 async revokeRelease(user:any,id:string){if(user.role!=='ADMIN')throw new ForbiddenException();return this.db.$transaction(async tx=>{await lock(tx,'release:'+id);const row=await tx.agentRelease.update({where:{id},data:{status:'REVOKED',revokedAt:new Date()}});await tx.audit.create({data:{actor:user.email,action:'REVOKE',resource:'agent-releases',resourceId:id}});return row;});}
 async listInstallations(user:any,q:any){const v=parse(componentPageInput,q),where:any={...(user.role==='ADMIN'||isPublicReadOnlyUser(user)?{}:{ownerId:user.id}),...(v.q?{OR:[{id:{contains:v.q}},{detail:{contains:v.q}}]}:{})};
  if(restricted(user)){const businesses=user.dataScope.businesses||[],assetIds=user.dataScope.assetIds||[];const allowed=await this.db.$queryRaw<Array<{id:string}>>`SELECT i.id FROM "AgentInstallation" i LEFT JOIN "Asset" a ON a.id=COALESCE(i."assetId",i.profile->>'targetAssetId') WHERE i."ownerId"=${user.id} AND ((a.id IS NOT NULL AND (a.id=ANY(${assetIds}::text[]) OR COALESCE(a.business=ANY(${businesses}::text[]),FALSE))) OR (i."assetId" IS NULL AND i.profile->>'targetAssetId' IS NULL AND COALESCE(i.profile->>'business'=ANY(${businesses}::text[]),FALSE)))`;where.id={in:allowed.map(a=>a.id)};}
  const[rows,total]=await Promise.all([this.db.agentInstallation.findMany({where,include:{release:true},orderBy:[{createdAt:'desc'},{id:'asc'}],take:v.pageSize,skip:(v.page-1)*v.pageSize}),this.db.agentInstallation.count({where})]);return {items:rows.map(publicInstallation),total};}
 async createInstallation(user:any,body:unknown){if(!['ADMIN','ANALYST','OPERATOR'].includes(user.role))throw new ForbiddenException();const v=parse(installationProfileInput,body);if(v.hostWaf){if(user.role!=='ADMIN')throw new ForbiddenException('同机 Web 接入需要管理员授权');assertGlobal(user);if(!process.env.HOST_WAF_IMAGE)throw new BadRequestException('先配置并交付固定摘要的 WAF 镜像');await this.db.site.findUniqueOrThrow({where:{id:v.hostWaf.siteId}});}if(v.targetAssetId){await assertScope(this.db,user,'assets',v.targetAssetId);const target=await this.db.asset.findUniqueOrThrow({where:{id:v.targetAssetId}});if(target.archivedAt||v.business&&v.business!==target.business)throw new ConflictException('目标已归档或业务归属不一致');v.business=target.business||undefined;}assertBusiness(user,v.business,v.targetAssetId);if(v.executorEnabled&&!taskVerificationKey())throw new BadRequestException('请先配置任务签名根，再启用执行器');const ticket=newToken();
  return this.db.$transaction(async tx=>{await lock(tx,'release:'+v.releaseId);const release=await tx.agentRelease.findUnique({where:{id:v.releaseId}});currentRelease(release);validateInstallationCompatibility(v,release!.version);const[major,minor,patch]=release!.version.split('.').map(Number);if(major>0||minor>3||minor===3&&patch>=9)v.proxyMode??=v.proxyUrl?'EXPLICIT':'DIRECT';
   const row=await tx.agentInstallation.create({data:{releaseId:v.releaseId,ownerId:user.id,profile:v as any,ticketHash:hashToken(ticket),expiresAt:new Date(Date.now()+15*60000),challenge:newToken()}});await tx.audit.create({data:{actor:user.email,action:'AUTHORIZE',resource:'agent-installations',resourceId:row.id,detail:{releaseId:v.releaseId,business:v.business||null,executorEnabled:v.executorEnabled}}});return {...publicInstallation(row),ticket,trustRoot:process.env.AGENT_UPGRADE_PUBLIC_KEY};
  });
 }
 private async authorized(tx:any,id:string,secret:string,initial=false){
  await lock(tx,id);
  const row=await tx.agentInstallation.findUnique({where:{id},include:{release:true}});if(row&&['RECOVERING','RECOVERED'].includes(row.status))throw new ConflictException('此安装任务已恢复，请创建新授权并保留原身份重试');if(!row||row.revokedAt||row.status==='CANCELLED')throw new UnauthorizedException('安装授权无效或已撤销');
  await lock(tx,'release:'+row.releaseId);row.release=await tx.agentRelease.findUnique({where:{id:row.releaseId}});
  const owner=await tx.user.findUnique({where:{id:row.ownerId}});if(!owner||owner.disabled||!['ADMIN','ANALYST','OPERATOR'].includes(owner.role))throw new UnauthorizedException('安装负责人权限已失效');assertBusiness(owner,(row.profile as any).business,(row.profile as any).targetAssetId);if((row.profile as any).targetAssetId)await assertScope(tx,owner,'assets',(row.profile as any).targetAssetId);currentRelease(row.release);
  if(row.assetId){await assertScope(tx,owner,'assets',row.assetId);const asset=await tx.asset.findUnique({where:{id:row.assetId}});if(!asset||asset.archivedAt||asset.tokenHash!==row.credentialHash)throw new UnauthorizedException('资产凭据或接入状态已撤销');}
  const ticket=initial&&row.expiresAt>new Date()&&equalSecret(row.ticketHash,hashToken(secret));
  const session=row.credentialHash&&row.leaseUntil>new Date()&&equalSecret(row.credentialHash,hashToken(secret));
  if(!secret||!ticket&&!session)throw new UnauthorizedException('安装凭证无效、过期或会话已结束');return row;
 }
 async claim(id:string,secret:string,body:unknown){const v=parse(claimInput,body);return this.db.$transaction(async tx=>{await lock(tx,id);const row=await this.authorized(tx,id,secret,true);const m=currentRelease(row.release);if(m.architecture!==v.architecture)throw new ConflictException('目标架构不匹配');
  if(row.claimedIdentity&&(row.claimedIdentity!==v.identity||row.credentialHash!==hashToken(v.credential)))throw new ConflictException('该授权已绑定其他持久身份');
  const profile=row.profile as any;const targetId=row.assetId||profile.targetAssetId;if(targetId)await tx.$queryRaw`SELECT id FROM "Asset" WHERE id=${targetId} FOR UPDATE`;let asset=targetId?await tx.asset.findUnique({where:{id:targetId}}):await tx.asset.findUnique({where:{identity:v.identity}});
  const wasManaged=!!asset?.identity&&!!asset?.tokenHash;
  if(asset&&!asset.archivedAt&&!asset.identity&&!asset.tokenHash&&profile.targetAssetId===asset.id)asset=await tx.asset.update({where:{id:asset.id},data:{identity:v.identity,tokenHash:hashToken(v.credential)}});
  if(asset&&(asset.archivedAt||asset.identity!==v.identity||asset.tokenHash!==hashToken(v.credential)))throw new ConflictException('已有身份不符合接入授权，不能覆盖');
  if(asset&&await tx.agentRolloutTarget.count({where:{assetId:asset.id,status:{in:['PENDING','CLAIMED','STAGED']},rollout:{status:{in:['RUNNING','PAUSED']}}}}))throw new ConflictException('先完成或取消此主机的升级计划，再安装或调整配置');
  if(asset&&wasManaged&&await tx.task.count({where:{assetId:asset.id,status:{in:profile.executorEnabled&&(asset.inventory as any)?.agentDiagnostics?.readOnlyCollector===true&&(asset.inventory as any)?.agentDiagnostics?.executorEnabled===false?['RUNNING','VERIFYING','UNKNOWN']:['APPROVED','RUNNING','VERIFYING','UNKNOWN']}}}))throw new ConflictException('先完成或核对未结束的修复任务，再安装或调整配置');
  if(!asset)asset=await tx.asset.create({data:{identity:v.identity,tokenHash:hashToken(v.credential),hostname:v.hostname,os:'linux',business:profile.business,tags:profile.tags,inventory:{agentVersion:m.version,installationId:id}}});
  if(profile.business&&asset.business!==profile.business)throw new ForbiddenException('已有资产业务归属不一致');
  if(profile.business)await tx.businessGroup.upsert({where:{name:profile.business},create:{name:profile.business},update:{}});
  const updated=await tx.agentInstallation.update({where:{id},data:{claimedIdentity:v.identity,credentialHash:hashToken(v.credential),leaseUntil:new Date(Date.now()+24*3600000),assetId:asset.id,status:row.status==='SUCCEEDED'?'SUCCEEDED':'REGISTERED'}});
  if(!row.claimedIdentity)await tx.audit.create({data:{actor:'installation:'+id,action:'CLAIM',resource:'assets',resourceId:asset.id,detail:{installationId:id,version:m.version}}});
  const taskPublicKey=profile.executorEnabled?taskVerificationKey():undefined;
  return {assetId:asset.id,token:v.credential,profile,release:row.release,challenge:updated.challenge,leaseUntil:updated.leaseUntil,taskPublicKey};
 });}
 async download(id:string,secret:string){return this.db.$transaction(async tx=>{const row=await this.authorized(tx,id,secret,true);return {bytes:await readArtifact(artifactRoot(),row.release.sha256,row.release.size),release:row.release};},{timeout:30000});}
 async bindExecutor(id:string,secret:string,body:unknown){const v=parse(z.object({publicKey:z.string().max(100),signature:z.string().max(100)}).strict(),body);return this.db.$transaction(async tx=>{await lock(tx,id);const row=await this.authorized(tx,id,secret);if(!(row.profile as any).executorEnabled||!row.assetId)throw new ForbiddenException('当前安装未授权执行器');
  const key=Buffer.from(v.publicKey,'base64'),sig=Buffer.from(v.signature,'base64'),message=Buffer.from(`selfguard-install-v1\n${id}\n${row.assetId}\n${row.challenge}`);
  if(key.length!==32||sig.length!==64||!verify(null,message,createPublicKey({format:'der',type:'spki',key:Buffer.concat([Buffer.from('302a300506032b6570032100','hex'),key])}),sig))throw new BadRequestException('执行器挑战签名无效');
  const asset=await tx.asset.findUniqueOrThrow({where:{id:row.assetId}});if(asset.executorPublicKey&&asset.executorPublicKey!==v.publicKey)throw new ConflictException('不能覆盖已有执行器信任');
  const changed=await tx.asset.updateMany({where:{id:asset.id,archivedAt:null,tokenHash:row.credentialHash,OR:[{executorPublicKey:null},{executorPublicKey:v.publicKey}]},data:{executorPublicKey:v.publicKey}});if(!changed.count)throw new ConflictException('执行器信任或资产授权已变化');await tx.audit.create({data:{actor:'installation:'+id,action:'BIND_EXECUTOR',resource:'assets',resourceId:asset.id,detail:{publicKey:v.publicKey}}});return {ok:true};
 });}
 async recover(id:string,secret:string,body:unknown){const v=parse(z.object({phase:z.enum(['PREPARE','COMPLETE'])}).strict(),body);return this.db.$transaction(async tx=>{await lock(tx,id);const row=await tx.agentInstallation.findUnique({where:{id},include:{release:true}});if(!row?.assetId||!secret||!row.credentialHash||!equalSecret(row.credentialHash,hashToken(secret)))throw new UnauthorizedException('恢复凭据无效');await tx.$queryRaw`SELECT id FROM "Asset" WHERE id=${row.assetId} FOR UPDATE`;const asset=await tx.asset.findUnique({where:{id:row.assetId}});if(!asset||asset.archivedAt||asset.tokenHash!==row.credentialHash)throw new UnauthorizedException('组件凭据已撤销');
  if(row.status==='SUCCEEDED')return {accepted:true,status:'SUCCEEDED'};
  const next=v.phase==='PREPARE'?'RECOVERING':'RECOVERED';if(v.phase==='COMPLETE'&&!['RECOVERING','RECOVERED'].includes(row.status))throw new ConflictException('先确认恢复，不能直接覆盖安装状态');
  if(row.status==='RECOVERED')return {accepted:false,status:'RECOVERED'};
  await tx.agentInstallation.update({where:{id},data:{status:next,detail:next==='RECOVERING'?'本地恢复已确认，拒绝迟到的成功回报':'受管文件已恢复；保留身份，以新任务重试'}});await tx.audit.create({data:{actor:'agent:'+asset.id,action:'INSTALLATION_'+next,resource:'agent-installations',resourceId:id,detail:{version:row.release.version}}});return {accepted:false,status:next};
 });}
 async report(id:string,secret:string,body:unknown){const v=parse(reportInput,body);return this.db.$transaction(async tx=>{await lock(tx,id);const row=await this.authorized(tx,id,secret);if(!row.assetId)throw new ConflictException('尚未注册');if(row.status==='SUCCEEDED'&&v.status!=='SUCCEEDED')throw new ConflictException('已完成安装不能倒退状态');if(v.version!==row.release.version)throw new ConflictException('运行版本与授权不一致');
  if(v.status==='SUCCEEDED'){const asset=await tx.asset.findUniqueOrThrow({where:{id:row.assetId}}),inventory=asset.inventory as any;
   if(asset.archivedAt||!asset.lastSeen||asset.lastSeen<row.createdAt||Date.now()-asset.lastSeen.getTime()>120000||inventory?.agentDiagnostics?.version!==v.version||inventory?.architecture!==row.release.architecture||['packageCollection','distributionCollection','serviceCollection','portCollection'].some(key=>inventory?.[key]?.complete!==true)||inventory?.agentDiagnostics?.readOnlyCollector===true&&inventory?.agentDiagnostics?.executorEnabled!==(row.profile as any).executorEnabled||(row.profile as any).executorEnabled&&!asset.executorPublicKey)throw new ConflictException('等待目标版本心跳、架构、采集完整性及执行器信任验收');
  }
  // Do not persist client details: arbitrary diagnostics may contain secrets.
  const detail=v.status==='SUCCEEDED'?'平台心跳与版本验收通过':v.status==='FAILED'?'安装失败；请在目标主机查看受保护诊断':v.status==='PARTIAL'?'本地已安装，平台验收未完成':v.status;
  await tx.audit.create({data:{actor:'installation:'+id,action:v.status,resource:'agent-installations',resourceId:id}});return publicInstallation(await tx.agentInstallation.update({where:{id},data:{status:v.status,detail}}));
 });}
 async revokeInstallation(user:any,id:string){return this.db.$transaction(async tx=>{await lock(tx,id);const row=await tx.agentInstallation.findUniqueOrThrow({where:{id}});if(user.role!=='ADMIN'&&row.ownerId!==user.id)throw new NotFoundException();await tx.audit.create({data:{actor:user.email,action:'REVOKE',resource:'agent-installations',resourceId:id}});return publicInstallation(await tx.agentInstallation.update({where:{id},data:{revokedAt:new Date(),...(row.status==='SUCCEEDED'?{}:{status:'CANCELLED'})}}));});}
}
@Controller('agent-releases') @UseGuards(AuthGuard)
export class AgentReleasesController{
 constructor(@Inject(InstallationService) private svc:InstallationService){}
 @Get() list(@Query()q:any){return this.svc.listReleases(q);}
 @Post() create(@Req()req:any,@Body()body:unknown){allow(req,['ADMIN']);return this.svc.createRelease(req.user,body);}
 @Get(':id/download') async download(@Param('id')id:string,@Res()res:any){const {bytes,release}=await this.svc.downloadRelease(id);res.setHeader('Content-Type','application/octet-stream');res.setHeader('Content-Disposition',`attachment; filename="selfguard-agent-${release.version}-linux-${release.architecture}"`);res.setHeader('Cache-Control','no-store');res.send(bytes);}
 @Post(':id/artifact') async upload(@Req()req:any,@Param('id')id:string){allow(req,['ADMIN']);return this.svc.uploadRelease(req.user,id,await uploadedBytes(req));}
 @Post(':id/packages') createPackage(@Req()req:any,@Param('id')id:string,@Body()body:unknown){allow(req,['ADMIN']);return this.svc.createPackage(req.user,id,body);}
 @Post('packages/:id/artifact') async uploadPackage(@Req()req:any,@Param('id')id:string){allow(req,['ADMIN']);return this.svc.uploadPackage(req.user,id,await uploadedBytes(req));}
 @Post('packages/:id/publish') publishPackage(@Req()req:any,@Param('id')id:string){allow(req,['ADMIN']);return this.svc.publishPackage(req.user,id);}
 @Get('packages/:id/download') async downloadPackage(@Param('id')id:string,@Res()res:any){const{bytes,package:pkg}=await this.svc.downloadPackage(id);res.setHeader('Content-Type','application/octet-stream');res.setHeader('Content-Disposition',`attachment; filename="selfguard-agent-${pkg.release.version}-linux-${pkg.release.architecture}.${pkg.format}"`);res.setHeader('Cache-Control','no-store');res.setHeader('X-Content-SHA256',pkg.sha256);res.send(bytes);}
 @Post(':id/publish') publish(@Req()req:any,@Param('id')id:string){allow(req,['ADMIN']);return this.svc.publishRelease(req.user,id);}
 @Post(':id/revoke') revoke(@Req()req:any,@Param('id')id:string){allow(req,['ADMIN']);return this.svc.revokeRelease(req.user,id);}
}
@Controller('agent-installations') @UseGuards(AuthGuard)
export class InstallationsController{
 constructor(@Inject(InstallationService) private svc:InstallationService,@Inject(Db)private db:Db){}
 @Get('options') options(@Req()req:any){return this.svc.installationOptions(req.user);}
 @Get() list(@Req()req:any,@Query()q:any){return this.svc.listInstallations(req.user,q);}
 @Post() async create(@Req()req:any,@Body()body:unknown){allow(req,['ADMIN','ANALYST','OPERATOR']);return this.svc.createInstallation(req.user,await platformInstallationBody(this.db,body));}
 @Post(':id/revoke') revoke(@Req()req:any,@Param('id')id:string){allow(req,['ADMIN','ANALYST','OPERATOR']);return this.svc.revokeInstallation(req.user,id);}
}
@Controller('agent/install')
export class AgentBootstrapController{
 constructor(@Inject(InstallationService) private svc:InstallationService){}
 @Post(':id/claim') claim(@Req()req:any,@Param('id')id:string,@Body()body:unknown){return this.svc.claim(id,bearer(req)||'',body);}
 @Post(':id/executor') executor(@Req()req:any,@Param('id')id:string,@Body()body:unknown){return this.svc.bindExecutor(id,bearer(req)||'',body);}
 @Post(':id/recovery') recovery(@Req()req:any,@Param('id')id:string,@Body()body:unknown){return this.svc.recover(id,bearer(req)||'',body);}
 @Post(':id/report') report(@Req()req:any,@Param('id')id:string,@Body()body:unknown){return this.svc.report(id,bearer(req)||'',body);}
 @Get(':id/artifact') async download(@Req()req:any,@Res()res:any,@Param('id')id:string){const {bytes,release}=await this.svc.download(id,bearer(req)||'');res.setHeader('Content-Type','application/octet-stream');res.setHeader('Content-Disposition',`attachment; filename="selfguard-agent-${release.version}-linux-${release.architecture}"`);res.setHeader('Cache-Control','no-store');res.setHeader('X-Content-SHA256',release.sha256);res.send(bytes);}
}
