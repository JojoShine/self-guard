import {Body,Controller,Get,Post,Param,Query,Req,UseGuards,Inject,ConflictException,ServiceUnavailableException} from '@nestjs/common';
import {createHash} from 'node:crypto';
import {z} from 'zod';
import {Db} from './db';
import {AuthGuard,allow} from './auth';
import {assertGlobal} from './scope';
import {parse} from './validation';
import {componentPageInput} from './construction-contracts';
import {persistWafDeployment,signWafRuntime,runtimeSite,validateStoredWafEnvelope,wafRuntimeSelectionInput} from './waf-runtime';

function runtimeEnabled(){if(process.env.WAF_RULE_RUNTIME_ENABLED!=='true')throw new ServiceUnavailableException('规则运行发布尚未开放；正在完成入站、误报和性能验收，候选导入和回放可继续使用');}
const changeInput=z.object({reason:z.string().trim().min(5).max(1000)}).strict();
function releaseDigest(row:any){return createHash('sha256').update(Buffer.from(row.envelope.payload,'base64')).digest('hex');}
export function hostingNodes(nodes:any[],binding:any){const assetId=binding?.value?.status==='ACTIVE'?binding.value.assetId:undefined;return nodes.filter(node=>assetId?node.id==='host-'+assetId:!node.id.startsWith('host-'));}
function acknowledged(row:any,nodes:any[]){const digest=releaseDigest(row);return nodes.filter(node=>(node.sites as any[]).some(site=>site.id===row.siteId&&site.version===row.siteVersion&&site.ruleReleaseSha256===digest)).map(node=>node.id);}

@Controller('waf-rule-deployments') @UseGuards(AuthGuard)
export class WafDeploymentsController {
 constructor(@Inject(Db) private db:Db){}
 @Get('options') async options(@Req()req:any){assertGlobal(req.user);return {runtimeEnabled:process.env.WAF_RULE_RUNTIME_ENABLED==='true',signingConfigured:!!process.env.WAF_RULE_SIGNING_KEY_FILE,sites:await this.db.site.findMany({select:{id:true,name:true,hostname:true,mode:true,version:true,enabled:true,ruleDeploymentId:true},orderBy:{name:'asc'},take:1000})};}
 @Get() async list(@Req()req:any,@Query()q:any){
  assertGlobal(req.user);const input=parse(componentPageInput,q),where=input.q?{OR:[{reason:{contains:input.q,mode:'insensitive' as const}},{actor:{contains:input.q,mode:'insensitive' as const}}]}:{};
  const [rows,total,nodes,sites]=await Promise.all([this.db.wafRuleDeployment.findMany({where,orderBy:[{createdAt:'desc'},{id:'asc'}],take:input.pageSize,skip:(input.page-1)*input.pageSize}),this.db.wafRuleDeployment.count({where}),this.db.wafNode.findMany({where:{lastSeen:{gte:new Date(Date.now()-60000)}}}),this.db.site.findMany({select:{id:true,name:true,version:true,ruleDeploymentId:true}})]);
  const bindings=await this.db.setting.findMany({where:{key:{startsWith:'host-waf-site:'}}});
  return {items:rows.map(row=>{const {envelope,...safe}=row,site=sites.find(site=>site.id===row.siteId),expected=hostingNodes(nodes,bindings.find(binding=>binding.key==='host-waf-site:'+row.siteId)),acks=acknowledged(row,expected),current=site?.ruleDeploymentId===row.id;return {...safe,siteName:site?.name||'已删除站点',current,acknowledgedNodes:acks,expectedOnlineNodes:expected.length,status:!current?'HISTORICAL':expected.length&&acks.length===expected.length?'ACKNOWLEDGED':'PENDING'};}),total};
 }
 @Post('observe/:bundleId') async observe(@Req()req:any,@Param('bundleId')bundleId:string,@Body()body:unknown){
  allow(req,['ADMIN']);assertGlobal(req.user);runtimeEnabled();const input=parse(wafRuntimeSelectionInput,body),bundle=await this.db.wafRuleBundle.findUniqueOrThrow({where:{id:bundleId}});
  if(bundle.status!=='BASIC_CHECK_PASSED'||!(bundle.report as any)?.publishable)throw new ConflictException('先完成当前固定规则内容的兼容检查');
  const passed=await this.db.wafRuleReplay.findMany({where:{bundleId,bundleSha256:bundle.sha256,engine:'selfguard-seclang-v1',threshold:input.threshold,passed:true}});
  if(!passed.some(row=>row.expectedBlocked)||!passed.some(row=>!row.expectedBlocked))throw new ConflictException('至少需要一份预期阻断和一份预期放行的真实 HTTP 样本验证通过');
  return this.db.$transaction(async tx=>{
   const releases=[];
   for(const id of [...input.siteIds].sort()){
    await tx.$queryRaw`SELECT id FROM "Site" WHERE id=${id} FOR UPDATE`;
    let site=await tx.site.findUniqueOrThrow({where:{id}});
    if(!site.enabled)throw new ConflictException('不能向已停用站点发布规则');
    if(!site.ruleDeploymentId){
     const baseline=await persistWafDeployment(tx,site,null,5,req.user.email,'首次外部规则发布前留存当前内置策略，供明确回退');
     site={...site,ruleDeploymentId:baseline.id};
    }
    const next=await tx.site.update({where:{id},data:{mode:'OBSERVE',version:{increment:1}}});
    releases.push(await persistWafDeployment(tx,next,bundle as any,input.threshold,req.user.email,input.reason));
   }
   return {items:releases.map(({envelope,...row})=>row),status:'PENDING',message:'已签发观察策略，需等待节点确认；尚未切换阻断'};
  },{timeout:20000});
 }
 @Post(':id/enforce') async enforce(@Req()req:any,@Param('id')id:string,@Body()body:unknown){
  allow(req,['ADMIN']);assertGlobal(req.user);runtimeEnabled();const input=parse(changeInput,body);
  return this.db.$transaction(async tx=>{
   const previous=await tx.wafRuleDeployment.findUniqueOrThrow({where:{id}});
   await tx.$queryRaw`SELECT id FROM "Site" WHERE id=${previous.siteId} FOR UPDATE`;
   const site=await tx.site.findUniqueOrThrow({where:{id:previous.siteId}});
   if(site.ruleDeploymentId!==id||site.version!==previous.siteVersion||site.mode!=='OBSERVE'||!site.enabled)throw new ConflictException('只能将当前观察发布切换为阻断，请刷新站点版本');
   const allNodes=await tx.wafNode.findMany({where:{lastSeen:{gte:new Date(Date.now()-60000)}}}),binding=await tx.setting.findUnique({where:{key:'host-waf-site:'+site.id}}),nodes=hostingNodes(allNodes,binding);
   if(!nodes.length||acknowledged(previous,nodes).length!==nodes.length)throw new ConflictException('在线节点尚未全部确认准确的签名版本，不能切换阻断');
   const payload=validateStoredWafEnvelope(previous.envelope);if(payload.builtin)throw new ConflictException('当前为内置策略，请在站点管理调整模式');
   const next=await tx.site.update({where:{id:site.id},data:{mode:'BLOCK',version:{increment:1}}}),release=await persistWafDeployment(tx,next,{id:payload.bundleId,sha256:payload.bundleSha256,files:payload.files},previous.threshold,req.user.email,input.reason);
   const {envelope,...safe}=release;return {...safe,status:'PENDING'};
  });
 }
 @Post(':id/rollback') async rollback(@Req()req:any,@Param('id')id:string,@Body()body:unknown){
  allow(req,['ADMIN']);assertGlobal(req.user);runtimeEnabled();const input=parse(changeInput,body);
  return this.db.$transaction(async tx=>{
   const target=await tx.wafRuleDeployment.findUniqueOrThrow({where:{id}});
   await tx.$queryRaw`SELECT id FROM "Site" WHERE id=${target.siteId} FOR UPDATE`;
   const site=await tx.site.findUniqueOrThrow({where:{id:target.siteId}}),payload=validateStoredWafEnvelope(target.envelope);
   if(site.ruleDeploymentId===id)throw new ConflictException('这个版本已经是当前发布');
   const next=await tx.site.update({where:{id:site.id},data:{mode:target.mode,version:{increment:1}}}),bundle=payload.builtin?null:{id:payload.bundleId,sha256:payload.bundleSha256,files:payload.files},row=await persistWafDeployment(tx,next,bundle,target.threshold,req.user.email,input.reason);
   const {envelope,...safe}=row;return {...safe,status:'PENDING'};
  });
 }
}

export async function signedWafConfiguration(db:Db,siteIds:string[]|null=null,excludedIds:string[]=[]){
 const sites=await db.site.findMany({where:siteIds===null?(excludedIds.length?{id:{notIn:excludedIds}}:{}):{id:{in:siteIds}},orderBy:{id:'asc'}}),ids=sites.flatMap(site=>site.ruleDeploymentId?[site.ruleDeploymentId]:[]),releases=await db.wafRuleDeployment.findMany({where:{id:{in:ids}}});
 const config={sites:sites.map(site=>{const wire=runtimeSite(site);if(!site.ruleDeploymentId)return process.env.WAF_RULE_SIGNING_KEY_FILE?{...wire,ruleRelease:signWafRuntime(site,null,5)}:wire;const row=releases.find(row=>row.id===site.ruleDeploymentId);if(!row||row.siteId!==site.id||row.siteVersion!==site.version)throw new ServiceUnavailableException('站点签名策略与配置版本不一致，节点保留上一有效版本');return {...wire,ruleRelease:row.envelope};})};if(Buffer.byteLength(JSON.stringify(config))>8*1024*1024)throw new ServiceUnavailableException('节点配置超过8 MiB预算，请缩小本次规则分发范围');return config;
}
