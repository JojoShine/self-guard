import {isLinuxAsset} from './asset-os';
import {hostWafImageArchive} from './host-waf-image';
import type {Prisma} from '@prisma/client';
import {Platform} from './platform';import {rebindSiteRuleDeployment} from './waf-runtime';
import {Body,Controller,Get,Post,Param,Req,UseGuards,Inject,BadRequestException,ConflictException} from '@nestjs/common';
import {z} from 'zod';import {Db} from './db';import {AuthGuard,allow} from './auth';import {assertGlobal,assertScope,assertEvidence} from './scope';import {parse} from './validation';
export const hostWafBindingInput=z.object({assetId:z.string().uuid(),nginxConfig:z.string().regex(/^\/[A-Za-z0-9_./-]+\.conf$/).max(1000).refine(value=>!value.includes('//')&&!value.split('/').some(part=>part==='.'||part==='..'),'需要规范的绝对配置路径'),wafPort:z.number().int().min(1024).max(65535).default(18081),healthPath:z.string().regex(/^\/[A-Za-z0-9_./-]*$/).max(500).default('/'),entryUrl:z.string().url().refine(value=>{const u=new URL(value);return ['http:','https:'].includes(u.protocol)&&u.hostname==='127.0.0.1'&&!u.username&&!u.password&&!u.search&&!u.hash&&u.pathname==='/';},'填写本机 Nginx 入口，如 https://127.0.0.1:443')}).strict();
export function supportsHostWaf(inventory:any){const version=inventory?.agentDiagnostics?.version||inventory?.agentVersion||'';const match=/^(\d+)\.(\d+)\.(\d+)$/.exec(version);return !!match&&(Number(match[1])>0||Number(match[2])>4||Number(match[2])===4&&Number(match[3])>=9);}
export function supportsHostWafAutomation(inventory:unknown){const parsed=z.object({agentDiagnostics:z.object({version:z.string()})}).safeParse(inventory);if(!parsed.success)return false;const m=/^(\d+)\.(\d+)\.(\d+)$/.exec(parsed.data.agentDiagnostics.version);return !!m&&(Number(m[1])>0||Number(m[2])>4||Number(m[2])===4&&Number(m[3])>=14);}
@Controller('host-waf') @UseGuards(AuthGuard)
export class HostWafController{
 constructor(@Inject(Db)private db:Db,@Inject(Platform)private p:Platform){}
 @Get('options')async options(@Req()req:any){assertGlobal(req.user);const assets=await this.db.asset.findMany({where:{archivedAt:null,tokenHash:{not:null}},select:{id:true,hostname:true,os:true,lastSeen:true,inventory:true},orderBy:{hostname:'asc'},take:1000});return {assets:assets.map(({inventory,...asset})=>({...asset,supported:supportsHostWaf(inventory),automationSupported:supportsHostWafAutomation(inventory)})),image:process.env.HOST_WAF_IMAGE||process.env.HOST_WAF_IMAGE_ARM64||process.env.HOST_WAF_IMAGE_AMD64||'',sites:await this.db.site.findMany({select:{id:true,name:true,hostname:true,upstream:true,mode:true,enabled:true},orderBy:{name:'asc'},take:1000})};}
 @Get('assets/:id/report')async report(@Req()req:any,@Param('id')id:string){assertEvidence(req.user);await assertScope(this.db,req.user,'assets',id);const rows=await this.db.setting.findMany({where:{key:{in:['host-waf-status:'+id,'traffic-capture:'+id]}}});return {onboarding:rows.find(row=>row.key.startsWith('host-waf-status:'))?.value||null,capture:rows.find(row=>row.key.startsWith('traffic-capture:'))?.value||null};}
 @Post(':id/unassign')async unassign(@Req()req:any,@Param('id')id:string,@Body()body:unknown){allow(req,['ADMIN']);assertGlobal(req.user);const {reason}=parse(z.object({reason:z.string().trim().min(5).max(500)}).strict(),body);return this.db.$transaction(async tx=>{await tx.$queryRaw`SELECT pg_advisory_xact_lock(hashtext('host-waf-bindings'))::text`;const binding=await tx.setting.findUniqueOrThrow({where:{key:'host-waf-site:'+id}}),assetId=(binding.value as any).assetId;const report=await tx.setting.findUnique({where:{key:'host-waf-status:'+assetId}});if((report?.value as any)?.siteId!==id||(report?.value as any)?.status!=='ROLLED_BACK')throw new ConflictException('先在目标主机执行回退并上报已恢复结果，再解除分配');await tx.setting.delete({where:{key:binding.key}});await tx.audit.create({data:{actor:req.user.email,action:'HOST_WAF_UNASSIGN',resource:'sites',resourceId:id,detail:{assetId,reason}}});return {ok:true};});}
 @Post(':id/plan')async plan(@Req()req:any,@Param('id')id:string,@Body()body:unknown){allow(req,['ADMIN']);assertGlobal(req.user);const input=parse(hostWafBindingInput,body);await prepareHostWafPlan(this.db,id,input);return this.db.$transaction(tx=>assignHostWafPlan(tx,this.p,req.user.email,id,input));}

}

export type HostWafPlanRequest=ReturnType<typeof hostWafBindingInput.parse>&{businessMode?:'EXISTING'|'NEW';listenPort?:number;certificateFile?:string;certificateKeyFile?:string};
type HostWafReader=Pick<Prisma.TransactionClient,'site'|'asset'|'setting'>;
export async function prepareHostWafPlan(db:HostWafReader,id:string,input:HostWafPlanRequest){
const site=await db.site.findUniqueOrThrow({where:{id}}),asset=await db.asset.findUniqueOrThrow({where:{id:input.assetId}});
 if(!site.enabled||asset.archivedAt||!asset.tokenHash||!isLinuxAsset(asset))throw new BadRequestException('需要已接入的 Linux 资产与启用的站点');
 if(!supportsHostWaf(asset.inventory))throw new BadRequestException('目标 Agent 需要升级到 0.4.9 或更高版本后再接入');
 const upstream=new URL(site.upstream);if(upstream.protocol!=='http:'||upstream.pathname!=='/'||upstream.search||upstream.hash)throw new BadRequestException('首批自动接入支持无路径的 HTTP 反向代理上游');
 const arch=String((asset.inventory as Prisma.JsonObject)?.architecture||'');const image=process.env[arch==='amd64'?'HOST_WAF_IMAGE_AMD64':arch==='arm64'?'HOST_WAF_IMAGE_ARM64':'HOST_WAF_IMAGE']||process.env.HOST_WAF_IMAGE||'';if(!/^(?:sha256:[a-f0-9]{64}|[A-Za-z0-9./_:-]+@sha256:[a-f0-9]{64})$/.test(image))throw new ConflictException('先由部署管理员设置固定摘要的 HOST_WAF_IMAGE，并将对应镜像交付到目标主机；禁止使用浮动标签');
const archive=supportsHostWafAutomation(asset.inventory)?await hostWafImageArchive(arch):undefined;return {site,asset,plan:{...(supportsHostWafAutomation(asset.inventory)?{wafCPUQuota:4,wafMemoryBytes:1073741824}:{}),...(archive?{imageArchiveSha256:archive.sha256,imageArchiveBytes:archive.size}:{}),schema:'selfguard-nginx-v1',...input,siteId:site.id,hostname:site.hostname,upstream:site.upstream.replace(/\/$/,''),image,mode:site.mode}};
}
export async function assignHostWafPlan(tx:Prisma.TransactionClient,p:Platform,actor:string,id:string,input:HostWafPlanRequest){
 const {site,asset,plan:prepared}=await prepareHostWafPlan(tx,id,input);
  await tx.$queryRaw`SELECT pg_advisory_xact_lock(hashtext('host-waf-bindings'))::text`;
  const prior=await tx.setting.findUnique({where:{key:'host-waf-site:'+site.id}});if((prior?.value as any)?.status==='ACTIVE')throw new ConflictException('站点已完成同机接入；请先回退并解除分配后再生成新计划');if(prior&&(prior.value as any)?.assetId!==asset.id)throw new ConflictException('此站点已分配到其他资产，先解除旧接入再迁移');
  const existing=await tx.setting.findMany({where:{key:{startsWith:'host-waf-site:'},value:{path:['assetId'],equals:asset.id}}});if(existing.some(row=>row.key!=='host-waf-site:'+site.id))throw new ConflictException('首批接入每台主机支持一个明确的反向代理站点');
  await tx.$queryRaw`SELECT id FROM "Site" WHERE id=${site.id} FOR UPDATE`;
  const current=await tx.site.findUniqueOrThrow({where:{id:site.id}}),config=current.config as any;
  if(config.nginxIngress!==true||!Array.isArray(config.trustedProxyCidrs)||!config.trustedProxyCidrs.includes('127.0.0.1/32')){
   let updated=await tx.site.update({where:{id:site.id},data:{config:{...config,nginxIngress:true,trustedProxyCidrs:[...new Set([...(config.trustedProxyCidrs||[]),'127.0.0.1/32'])]},version:{increment:1}}});
   updated=await rebindSiteRuleDeployment(tx,updated,actor);await p.revision(tx,'sites',updated,actor);
  }
  const plan={...prepared};
  await tx.setting.upsert({where:{key:'host-waf-site:'+site.id},create:{key:'host-waf-site:'+site.id,value:{assetId:asset.id,status:'PENDING'}},update:{value:{assetId:asset.id,status:'PENDING'}}});
  await tx.audit.create({data:{actor:actor,action:'HOST_WAF_PLAN',resource:'sites',resourceId:site.id,detail:{assetId:asset.id,mode:site.mode}}});
  return {plan,command:'sudo /opt/selfguard-agent/current --onboard-nginx /root/selfguard-nginx.json',note:'生成计划仅分配站点；目标主机执行、入口验证和节点确认后才算已接入。'};
}
