import {baseAgentDatabaseSources} from './database-monitor-binding';
import {storeHostMetrics} from './monitoring';
import {monitorReportInput} from './traffic-monitor-contract';
import {storeMonitorReport,monitorDesired} from './traffic-monitor';
import type {Response} from 'express';
import {readHostWafImage} from './host-waf-image';
import {recordCandidates} from './asset-discovery';
import {HostWafController} from './host-waf';
import {trafficCaptureInput} from './traffic-capture';
import {wafPublicTrustRoot} from './waf-runtime';
import {authorizeHostWaf} from './host-waf-identity';
import {requestTraceInput} from './request-trace';
import {requiresDataSecurity} from './data-security';
import {signedWafConfiguration} from './waf-deployments';
import {activeInstallationWhere} from './installations';
import {canAutoVerifyRisk} from "./risk-verification";
import {Prisma} from "@prisma/client";
import {assertTemplateEnabled} from "./templates";
import {lockEventStorage,assertEventCapacity} from "./storage";
import {recordAssetChange} from "./asset-history";
import {verifyExecutorResult} from "./executor-proof";
import {authorizeTask} from "./task-signing";
import {CorrelationService} from "./correlation";
import {stopFailedBatch} from "./batches";
import {evaluateScopedVulnerability as evaluateVulnerability} from "./rule-tools";
import {
  Controller,
  Post,
  Get,
  Body,
  Req,
  Param,
  Query,
  Res,
  Inject,
  UnauthorizedException,
  BadRequestException,
  ConflictException,
} from "@nestjs/common";
import { Db } from "./db";
import { Platform } from "./platform";
import { component, bearer } from "./auth";
import { hashToken, newToken } from "./security";
import { parse, text, findingInput } from "./validation";
import { redactEvent } from "./domain";
import { z } from "zod";
import { isDeepStrictEqual } from "node:util";
@Controller("agent")
export class AgentController {
  constructor(
    @Inject(Db) private db: Db,
    @Inject(Platform) private p: Platform,
  ) {}
  private async identity(req: any) {
    const token = bearer(req);
    if (!token) throw new UnauthorizedException();
    const a = await this.db.asset.findUnique({
      where: { tokenHash: hashToken(token) },
    });
    if (!a || a.archivedAt) throw new UnauthorizedException("Agent 身份无效");
    return a;
  }
  private async currentIdentity(tx:any,id:string,req:any){
    await tx.$queryRaw`SELECT id FROM "Asset" WHERE id=${id} FOR UPDATE`;
    const asset=await tx.asset.findUnique({where:{id}});
    if(!asset||asset.archivedAt||asset.tokenHash!==hashToken(bearer(req)))throw new UnauthorizedException('Agent 凭据已撤销或身份无效');
    return asset;
  }
  @Post("enroll") async enroll(@Req() req: any, @Body() body: unknown) {
    component(req, "ENROLLMENT_TOKEN");
    const v = parse(
      z
        .object({
          hostname: text,
          os: text,
          ip: z.string().max(100).optional(),
          identity: text,
          agentVersion: text.optional(),
          credential: z.string().min(32).max(128).optional(),
        })
        .strict(),
      body,
    );
    const token = v.credential || newToken();
    return this.db.$transaction(async (tx) => {
      const old = await tx.asset.findUnique({
        where: { identity: v.identity },
      });
      if (old) {
        if (v.credential && old.tokenHash === hashToken(v.credential))
          return { assetId: old.id, token: v.credential };
        throw new ConflictException("该身份已注册，不能覆盖现有凭据");
      }
      const asset = await tx.asset.create({
        data: {
          hostname: v.hostname,
          os: v.os,
          ip: v.ip,
          identity: v.identity,
          tokenHash: hashToken(token),
          lastSeen: new Date(),
          inventory: { agentVersion: v.agentVersion || "unknown" },
        },
      });
      await this.p.audit(tx, "agent:" + asset.id, "ENROLL", "assets", asset.id);
      return { assetId: asset.id, token };
    });
  }
  @Post("uninstall") async uninstall(@Req() req:any,@Body() body:unknown){
    const asset=await this.identity(req);const v=parse(z.object({assetId:z.string().uuid()}).strict(),body);
    if(v.assetId!==asset.id)throw new UnauthorizedException();
    return this.db.$transaction(async tx=>{
      await this.currentIdentity(tx,asset.id,req);
      if(await tx.task.count({where:{assetId:asset.id,status:{in:['APPROVED','RUNNING','VERIFYING','UNKNOWN']}}}))throw new ConflictException('有执行中、待确认或待复验任务，请先核对后卸载');
      if(await tx.agentRolloutTarget.count({where:{assetId:asset.id,status:{in:['PENDING','CLAIMED','STAGED']},rollout:{status:{in:['RUNNING','PAUSED']}}}}))throw new ConflictException('有未结束的升级目标，请先核对并完成或取消升级计划后卸载');
      if(await tx.agentInstallation.count({where:activeInstallationWhere(asset.id)}))throw new ConflictException('有未结束的安装或恢复授权，请先核对或撤销后卸载');
      await tx.asset.update({where:{id:asset.id},data:{tokenHash:null}});
      await this.p.audit(tx,'agent:'+asset.id,'UNINSTALL_REVOKE','assets',asset.id);
      return {ok:true,historyRetained:true};
    });
  }
  @Get("traffic-monitor/:id") async trafficMonitorControl(@Req()req:any,@Param("id")id:string){const asset=await this.identity(req);return this.db.$transaction(async tx=>{await this.currentIdentity(tx,asset.id,req);return monitorDesired(tx,asset.id,id)})}
  @Post("network-report") async networkReport(@Req()req:any,@Body()body:unknown){
    const asset=await this.identity(req);
    const v=parse(z.union([monitorReportInput,trafficCaptureInput,z.object({schema:z.literal('selfguard-nginx-v1'),siteId:z.string().uuid(),status:z.enum(['VERIFIED','FAILED','ROLLED_BACK']),mode:z.enum(['OBSERVE','BLOCK']),message:z.string().max(1000),updatedAt:z.string().datetime(),transactionDir:z.string().max(1000)}).strict()]),body);
    return this.db.$transaction(async tx=>{await this.currentIdentity(tx,asset.id,req);
      if(v.schema==='selfguard-traffic-monitor-v1')return storeMonitorReport(tx,asset.id,v);
      const key=(v.schema==='selfguard-traffic-v1'?'traffic-capture:':'host-waf-status:')+asset.id;
      if(v.schema==='selfguard-nginx-v1'){const assignment=await tx.setting.findUnique({where:{key:'host-waf-site:'+v.siteId}});if((assignment?.value as any)?.assetId!==asset.id)throw new UnauthorizedException('站点没有分配到当前资产');await tx.setting.update({where:{key:assignment!.key},data:{value:{assetId:asset.id,status:v.status==='VERIFIED'?'ACTIVE':v.status==='ROLLED_BACK'?'PENDING':(assignment!.value as any).status||'PENDING'}}});}
      await tx.setting.upsert({where:{key},create:{key,value:v},update:{value:v}});await this.p.audit(tx,'agent:'+asset.id,'NETWORK_REPORT','assets',asset.id,{schema:v.schema});return {ok:true};
    });
  }
  @Get("host-waf/image") async hostWafImage(@Req()req:any,@Query('sha256')sha256:string,@Res()res:Response){
    const asset=await this.identity(req);if(!/^[a-f0-9]{64}$/.test(sha256||''))throw new BadRequestException('镜像摘要无效');
    const bindings=await this.db.setting.findMany({where:{key:{startsWith:'host-waf-site:'},value:{path:['assetId'],equals:asset.id}}});if(!bindings.length)throw new UnauthorizedException('此资产没有已授权的同机WAF站点');
    const architecture=String((asset.inventory as {architecture?:string})?.architecture||'');const bytes=await readHostWafImage(architecture,sha256);await this.db.audit.create({data:{actor:'agent:'+asset.id,action:'HOST_WAF_IMAGE_DOWNLOAD',resource:'assets',resourceId:asset.id,detail:{sha256,architecture,size:bytes.length}}});res.setHeader('Content-Type','application/x-tar');res.setHeader('Content-Length',bytes.length);res.setHeader('Cache-Control','private, no-store');res.send(bytes);
  }
  @Post("host-waf/installation-plan") async hostWafInstallationPlan(@Req()req:any,@Body()body:unknown){
    const asset=await this.identity(req),v=parse(z.object({installationId:z.string().uuid()}).strict(),body);
    const installation=await this.db.agentInstallation.findUniqueOrThrow({where:{id:v.installationId}});
    if(installation.assetId!==asset.id||installation.status!=='SUCCEEDED'||installation.revokedAt)throw new UnauthorizedException('需要此资产已通过验收的安装授权');
    const owner=await this.db.user.findUniqueOrThrow({where:{id:installation.ownerId}}),profile=installation.profile as any;
    if(owner.disabled||owner.role!=='ADMIN'||!profile.hostWaf)throw new UnauthorizedException('同机 Web 接入授权已失效');
    const {siteId,...fields}=profile.hostWaf;
    return new HostWafController(this.db,this.p).plan({user:owner},siteId,{...fields,assetId:asset.id});
  }
  @Get("host-waf/bootstrap") async hostWafBootstrap(@Req() req:any){
    const asset=await this.identity(req);
    const bindings=await this.db.setting.findMany({where:{key:{startsWith:'host-waf-site:'},value:{path:['assetId'],equals:asset.id}}});
    const ids=bindings.map(row=>row.key.slice('host-waf-site:'.length));
    return {assetId:asset.id,publicKey:wafPublicTrustRoot(),config:await signedWafConfiguration(this.db,ids)};
  }
  @Post("host-waf/credential") async hostWafCredential(@Req() req:any){
    const asset=await this.identity(req),token=newToken();
    return this.db.$transaction(async tx=>{
      await this.currentIdentity(tx,asset.id,req);
      await tx.setting.deleteMany({where:{key:{startsWith:'host-waf-credential:'},value:{path:['assetId'],equals:asset.id}}});
      await tx.setting.create({data:{key:'host-waf-credential:'+hashToken(token),value:{assetId:asset.id,assetTokenHash:asset.tokenHash}}});
      await this.p.audit(tx,'agent:'+asset.id,'HOST_WAF_CREDENTIAL','assets',asset.id);
      return {token,nodeId:'host-'+asset.id};
    });
  }
  @Post("heartbeat") async heartbeat(@Req() req: any, @Body() body: unknown) {
    const a = await this.identity(req);
    const v = parse(
      z
        .object({
          inventory: z.record(z.string(), z.unknown()).default({}),
          findings: z
            .array(findingInput.omit({ assetId: true, instanceId:true }))
            .max(100)
            .default([]),
        })
        .strict(),
      body,
    );
    return this.db.$transaction(
      async (tx) => {
        const previous=await this.currentIdentity(tx,a.id,req);
        const current=await tx.asset.update({where:{id:a.id},data:{lastSeen:new Date(),inventory:v.inventory as any}});
        await recordAssetChange(tx,a.id,previous,current,'agent:'+a.id);
        if(v.inventory.resourceMetrics!==undefined)await storeHostMetrics(tx,this.p,a.id,v.inventory.resourceMetrics);
        await recordCandidates(tx,current,v.inventory);
        for(const f of v.findings){
         let ruleId:string|undefined;try{const evidence=JSON.parse(f.evidence);if(typeof evidence?.ruleId==='string')ruleId=evidence.ruleId;}catch{}
         const rule=ruleId?await tx.rule.findUnique({where:{id:ruleId}}):null;const instanceId=(rule?.config as {instanceId?:string}|undefined)?.instanceId;
         if(instanceId){const instance=await tx.databaseInstance.findFirst({where:{id:instanceId,hostIds:{has:a.id},archivedAt:null}});if(!instance)throw new BadRequestException('数据库规则实例不在此Agent采集范围');await this.p.ingest(tx,{...f,instanceId},undefined,rule?.config);}else await this.p.ingest(tx,f,a.id,rule?.config);
        }
        // Exact package matches are deliberately explicit, never infer vulnerable version ordering.
        const packages = Array.isArray(v.inventory.packages)
          ? v.inventory.packages.slice(0, 5000)
          : [];
        const rules = await tx.rule.findMany({
          where: { enabled: true, kind: "VULNERABILITY" },
          
        });
        for(const rule of rules){const result=evaluateVulnerability(rule.config,{...a,inventory:v.inventory});if(result.matched)await this.p.ingest(tx,{externalId:rule.id+':'+(rule.config as any).package,title:rule.name,kind:'RISK',severity:rule.severity,source:'vulnerability',evidence:result.evidence},a.id);}
        return { ok: true };
      },
      { timeout: 15000 },
    );
  }
  @Get("policy") async policy(@Req() req: any) {
    const asset=await this.identity(req);
    const instances=typeof req.query?.capabilities==='string'&&req.query.capabilities.split(',').includes('data-security-v2')?await this.db.databaseInstance.findMany({where:{hostIds:{has:asset.id},archivedAt:null},select:{id:true,engine:true,auditSources:true}}):[];
    const bindings=instances.length?await this.db.setting.findMany({where:{key:{startsWith:'database-monitor-binding:'+asset.id+':'}}}):[];
    const instanceIds=new Set(instances.map(i=>i.id));
    return {
      asset:{id:asset.id,tags:asset.tags,business:asset.business},
      databaseSources:baseAgentDatabaseSources(asset.id,instances,bindings),
      rules: (await this.db.rule.findMany({
        where: { enabled: true, kind: { in: ["BASELINE", "LOG", "FIM"] } },
        orderBy: { id: "asc" },
        
      })).filter(rule=>!(rule.config as {instanceId?:string})?.instanceId||instanceIds.has((rule.config as {instanceId:string}).instanceId)).filter(rule=>!['DATABASE_ACTIVITY','DATABASE_ACCESS'].includes((rule.config as {type?:string})?.type||'')&&!(rule.config as {instanceId?:string})?.instanceId||(typeof req.query?.capabilities==='string'&&req.query.capabilities.split(',').includes('data-security-v2'))).filter(rule=>!requiresDataSecurity(rule.config)||(typeof req.query?.capabilities==="string"&&req.query.capabilities.split(",").includes("data-security-v1"))),
    };
  }
  @Get("tasks") async tasks(@Req() req: any) {
    const a = await this.identity(req);
    return this.db.$transaction(async (tx) => {
      const current=await this.currentIdentity(tx,a.id,req);
      const diagnostics=(current.inventory as any)?.agentDiagnostics;if(diagnostics?.readOnlyCollector===true&&diagnostics?.executorEnabled!==true)return {items:[]};
      if(await tx.agentInstallation.count({where:activeInstallationWhere(a.id)}))return {items:[]};
      await tx.task.updateMany({
        where: {
          assetId: a.id,
          status: "APPROVED",
          expiresAt: { lt: new Date() },
        },
        data: { status: "EXPIRED" },
      });
      await tx.task.updateMany({
        where: {
          assetId: a.id,
          status: "RUNNING",
          claimedAt: { lt: new Date(Date.now() - 15 * 60000) },
        },
        data: { status: "UNKNOWN" },
      });
      for(const failed of await tx.task.findMany({where:{assetId:a.id,batchId:{not:null},status:{in:['FAILED','UNKNOWN']}},distinct:['batchId'],select:{batchId:true}}))await stopFailedBatch(tx,failed.batchId);
      await tx.$queryRaw`SELECT pg_advisory_xact_lock(hashtext('selfguard-task-claim'))::text`;
      const items = [];
      let cursor:{id:string;createdAt:Date}|undefined;
      let exhausted=false;
      while(items.length<5&&!exhausted){
        const after=cursor?Prisma.sql`AND ("createdAt",id)>(${cursor.createdAt},${cursor.id})`:Prisma.empty;
        const rows=await tx.$queryRaw<Array<{id:string;createdAt:Date}>>(Prisma.sql`SELECT id,"createdAt" FROM "Task" WHERE "assetId"=${a.id} AND status='APPROVED' AND "expiresAt">NOW() AND ("notBefore" IS NULL OR "notBefore"<=NOW()) AND ("windowEnd" IS NULL OR "windowEnd">NOW()) ${after} ORDER BY "createdAt",id LIMIT 100 FOR UPDATE SKIP LOCKED`);
        exhausted=rows.length<100;
        if(rows.length)cursor=rows[rows.length-1];
      for (const row of rows) {
        if(items.length>=5)break;
        const candidate=await tx.task.findUniqueOrThrow({where:{id:row.id}});
        if(candidate.batchId){const batch=await tx.taskBatch.findUnique({where:{id:candidate.batchId}});if(!batch||batch.status!=='RUNNING')continue;
         const failed=await tx.task.count({where:{batchId:batch.id,status:{in:['FAILED','UNKNOWN']}}});
         if(batch.stopOnFailure&&failed){await tx.taskBatch.update({where:{id:batch.id},data:{status:'STOPPED'}});await tx.task.updateMany({where:{batchId:batch.id,status:{in:['PENDING','APPROVED']}},data:{status:'CANCELLED',reason:'批次出现失败或未知结果'}});continue;}
         if(await tx.task.count({where:{batchId:batch.id,status:{in:['RUNNING','VERIFYING','UNKNOWN']}}}))continue;
        }
        try{await assertTemplateEnabled(tx,candidate.template);}catch(e){if(e instanceof ConflictException)continue;throw e;}
        const t = await tx.task.update({
          where: { id: row.id },
          data: { status: "RUNNING", claimedAt: new Date() },
        });
        await this.p.audit(tx, "agent:" + a.id, "CLAIM", "tasks", t.id);
        items.push({
          id: t.id,
          authorization:authorizeTask(t),
          template: t.template,
          parameters: t.parameters,
          expiresAt: t.expiresAt,
        });
      }
      }
      return { items };
    });
  }
  @Post("tasks/:id/result") async result(
    @Req() req: any,
    @Param("id") id: string,
    @Body() body: unknown,
  ) {
    const a = await this.identity(req);
    const v = parse(
      z
        .object({
          success: z.boolean(),
          evidence: z.string().max(16000),
          details: z.record(z.string(), z.unknown()).optional(),
        })
        .strict(),
      body,
    );
    return this.db.$transaction(async (tx) => {
      const old = await tx.task.findUnique({ where: { id } });
      if (!old || old.assetId !== a.id)
        throw new UnauthorizedException("任务不属于此 Agent");
      if(a.executorPublicKey&&!verifyExecutorResult(a.executorPublicKey,old.id,a.id,v)){
        v.success=false;v.evidence='执行器结果签名缺失或无效；实际状态需独立核对';v.details={resultUnknown:'true',executorProofRejected:'true',...(old.template==='VERIFY_READ'?{verifiedTaskId:(old.parameters as any)?.originalTaskId}:{})};
      }
      if(old.result&&isDeepStrictEqual(old.result,v))return {ok:true};
      if (["VERIFYING", "FAILED", "SUCCEEDED"].includes(old.status)) {
        if (isDeepStrictEqual(old.result, v)) return { ok: true };
        throw new ConflictException("结果已提交");
      }
      if (!["RUNNING", "UNKNOWN"].includes(old.status))
        throw new ConflictException("任务未领取");
      const changed = await tx.task.updateMany({
        where: { id, status: old.status },
        data: { status: v.success ? "VERIFYING" : v.details?.resultUnknown==="true" ? "UNKNOWN" : "FAILED", result: v as any },
      });
      if (!changed.count) throw new ConflictException("任务已变化");
      if(old.template==='VERIFY_READ'){
        const targetId=(old.parameters as any)?.originalTaskId;
        const target=targetId?await tx.task.findUnique({where:{id:targetId}}):null;
        if(!target||target.assetId!==a.id||targetId!==v.details?.verifiedTaskId)throw new BadRequestException('复测目标不一致');
        const unknown=v.details?.resultUnknown==='true';const resolved=v.success&&v.details?.verificationPassed==='true';
        await tx.task.update({where:{id:old.id},data:{status:unknown?'UNKNOWN':resolved?'SUCCEEDED':'FAILED',completedAt:unknown?null:new Date()}});
        if(['VERIFYING','UNKNOWN'].includes(target.status)){
          await tx.task.update({where:{id:target.id},data:{status:unknown?'UNKNOWN':resolved?'SUCCEEDED':'FAILED',verification:{actor:'independent-agent-read',evidence:v.evidence,taskId:old.id,resolved},completedAt:new Date()}});
          if(resolved&&target.template==='ROLLBACK'&&target.rollbackOf){const original=await tx.task.findUnique({where:{id:target.rollbackOf}});if(original&&original.assetId===a.id){await tx.task.update({where:{id:original.id},data:{status:'ROLLED_BACK'}});if(original.findingId)await tx.finding.update({where:{id:original.findingId},data:{status:'OPEN',reason:'已验证回滚，风险重新开放'}});}}
          else if(resolved&&target.findingId){const finding=await tx.finding.findUnique({where:{id:target.findingId}});if(finding&&canAutoVerifyRisk(finding,target))await tx.finding.update({where:{id:target.findingId},data:{status:'CLOSED',reason:v.evidence}});}
          if(!resolved)await stopFailedBatch(tx,target.batchId);
        }
      }else if(v.success&&['FILE_PERMISSION','CONFIG_VALUE','SERVICE_STATE','ROLLBACK'].includes(old.template)){
        await tx.task.create({data:{title:'独立复测：'+old.title,assetId:a.id,template:'VERIFY_READ',parameters:{originalTaskId:old.id},rollbackOf:old.id,status:'APPROVED',requestedBy:'system',approvedBy:old.approvedBy,expiresAt:new Date(Date.now()+3600000)}});
      }
      if(!v.success)await stopFailedBatch(tx,old.batchId);
      if (v.success && old.findingId && old.template!=='VERIFY_READ')
        await tx.finding.updateMany({
          where: {
            id: old.findingId,
            status: { notIn: ["CLOSED", "FALSE_POSITIVE"] },
          },
          data: { status: "VERIFYING" },
        });
      await this.p.audit(tx, "agent:" + a.id, "RESULT", "tasks", id, {
        success: v.success,
      });
      return { ok: true };
    });
  }
}
@Controller("waf")
export class WafController {
  constructor(
    @Inject(Db) private db: Db,
    @Inject(Platform) private p: Platform,
    @Inject(CorrelationService) private correlation: CorrelationService,
  ) {}
  @Post("heartbeat") async heartbeat(@Req() req: any, @Body() body: unknown) {
    const v = parse(
      z
        .object({
          nodeId: text,
          version: text,
          sites: z
            .array(
              z.object({ id: text, version: z.number().int().min(0),ruleReleaseSha256:z.string().regex(/^[a-f0-9]{64}$/).optional() }).strict(),
            )
            .max(1000),
          droppedEvents: z.number().int().min(0),
          accessHistory:z.array(z.object({id:text,siteId:z.union([text,z.literal("")]),method:z.string().max(16),path:z.string().max(1024),context:requestTraceInput.optional(),status:z.number().int().min(100).max(599),timestamp:z.string().datetime(),durationMicros:z.number().int().min(0).max(2147483647)}).strict()).max(1024).optional(),accessHistoryCapacity:z.number().int().min(0).optional(),accessHistoryCount:z.number().int().min(0).optional(),accessHistoryEvictedSinceStart:z.number().int().min(0).optional(),
          totalRequests:z.number().int().min(0).optional(),blockedRequests:z.number().int().min(0).optional(),observedRequests:z.number().int().min(0).optional(),upstreamErrors:z.number().int().min(0).optional(),accessLogDropped:z.number().int().min(0).optional(),upstreamHealth:z.array(z.object({siteId:text,healthy:z.boolean(),statusCode:z.number().int(),checkedAt:z.string().datetime()})).max(1000).optional(),
          startedAt: z.string().datetime(),
        })
        .strict(),
      body,
    );
    await authorizeHostWaf(this.db,req,[...v.sites.map(site=>site.id),...(v.accessHistory||[]).map(row=>row.siteId),...(v.upstreamHealth||[]).map(row=>row.siteId)],v.nodeId);
    if(req.hostWafNode&&(v.accessHistory||[]).some(row=>!row.id.startsWith(req.hostWafNode+':')||row.context&&!row.context.requestId.startsWith(req.hostWafNode+':')))throw new UnauthorizedException('访问记录的节点身份不一致');
    if(v.accessHistory?.length)await this.db.$transaction(async tx=>{await lockEventStorage(tx);const added=await tx.wafAccess.createMany({data:v.accessHistory!.map(e=>({...e,nodeId:v.nodeId,timestamp:new Date(e.timestamp)})),skipDuplicates:true});await assertEventCapacity(tx,'access',added.count);});
    await this.db.wafNode.upsert({
      where: { id: v.nodeId },
      create: {
        id: v.nodeId,
        version: v.version,
        sites: v.sites,
          stats:{accessHistoryCount:v.accessHistoryCount||0,accessHistoryEvictedSinceStart:v.accessHistoryEvictedSinceStart||0,totalRequests:v.totalRequests||0,blockedRequests:v.blockedRequests||0,observedRequests:v.observedRequests||0,upstreamErrors:v.upstreamErrors||0,accessLogDropped:v.accessLogDropped||0,upstreamHealth:v.upstreamHealth||[]},
        droppedEvents: v.droppedEvents,
        startedAt: new Date(v.startedAt),
      },
      update: {
        version: v.version,
        sites: v.sites,
          stats:{accessHistoryCount:v.accessHistoryCount||0,accessHistoryEvictedSinceStart:v.accessHistoryEvictedSinceStart||0,totalRequests:v.totalRequests||0,blockedRequests:v.blockedRequests||0,observedRequests:v.observedRequests||0,upstreamErrors:v.upstreamErrors||0,accessLogDropped:v.accessLogDropped||0,upstreamHealth:v.upstreamHealth||[]},
        droppedEvents: v.droppedEvents,
        startedAt: new Date(v.startedAt),
        lastSeen: new Date(),
      },
    });
    return { ok: true };
  }
  @Get("config") async config(@Req() req: any) {
    const ids=await authorizeHostWaf(this.db,req,[]);
    const assigned=ids===null?await this.db.setting.findMany({where:{key:{startsWith:'host-waf-site:'},value:{path:['status'],equals:'ACTIVE'}}}):[];
    return signedWafConfiguration(this.db,ids,assigned.map(row=>row.key.slice('host-waf-site:'.length)));
  }
  @Post("events") async events(@Req() req: any, @Body() body: unknown) {
    const v = parse(
      z
        .object({
          events: z
            .array(
              z
                .object({
                  id: text,
                  siteId: text,
                  ruleId: text,
                  path: z.string().max(4096),
                  method: z.string().max(16),
                  action: z.enum(["BLOCK", "OBSERVE", "ALLOW"]),
                  remoteIp: z.string().max(100),
                  context:requestTraceInput.optional(),
                  inspection:z.object({nodeId:text,siteVersion:z.number().int().min(1),bundleId:text,bundleSha256:z.string().regex(/^[a-f0-9]{64}$/),siteHostname:z.string().max(253),configuredUpstreamOrigin:z.string().url().max(2048).refine(value=>{const u=new URL(value);return ['http:','https:'].includes(u.protocol)&&!u.username&&!u.password&&!u.search&&!u.hash&&u.pathname==='/';}),score:z.number().int(),decisionStatus:z.number().int().min(0).max(599),complete:z.boolean(),failureKind:z.enum(['INSPECTION_INCOMPLETE_OR_UNAVAILABLE','QUEUE_CAPACITY','QUEUE_TIMEOUT','WORKER_DEADLINE','WORKER_UNAVAILABLE','WORKER_PROTOCOL','REQUEST_INCOMPLETE','REQUEST_INVALID','CANCELLED']).optional(),matches:z.array(z.string().max(100)).max(32),evidence:z.array(z.object({ruleId:z.string().max(100),variable:z.string().max(256),valueSha256:z.string().regex(/^[a-f0-9]{64}$/),valueBytes:z.number().int().min(0),messageTemplate:z.string().max(512).optional(),tags:z.array(z.string().max(128)).max(20).optional(),logDataSha256:z.string().regex(/^[a-f0-9]{64}$/).optional(),logDataBytes:z.number().int().min(0).optional()}).strict()).max(8),omittedEvidence:z.number().int().min(0)}).strict().optional(),
                  timestamp: z.string().datetime(),
                })
                .strict(),
            )
            .max(100),
        })
        .strict(),
      body,
    );
    await authorizeHostWaf(this.db,req,v.events.map(row=>row.siteId));
    if(req.hostWafNode&&v.events.some(row=>row.context&&!row.context.requestId.startsWith(req.hostWafNode+':')||row.inspection&&row.inspection.nodeId!==req.hostWafNode))throw new UnauthorizedException('事件的节点身份不一致');
    const result=await this.db.$transaction(
      async (tx) => {
        await lockEventStorage(tx);let inserted=0;
        for (const e of v.events) {
          const site = await tx.site.findUnique({ where: { id: e.siteId } });
          if (!site) throw new BadRequestException("站点不存在");
          const clean = {...redactEvent(e),...(e.context?{context:e.context}:{}),...(e.inspection?{inspection:e.inspection as any}:{})};
          const added = await tx.wafEvent.createMany({
            data: [
              {
                id: req.hostWafNode?req.hostWafNode+':'+e.id:e.id,
                siteId: e.siteId,
                ...clean,
                timestamp: new Date(e.timestamp),
              },
            ],
            skipDuplicates: true,
          });
          inserted+=added.count;
          if (added.count && e.action !== "ALLOW")
            await this.p.ingest(tx, {
              externalId:
                e.siteId +
                ":" +
                e.ruleId +
                ":" +
                clean.remoteIp +
                ":" +
                new Date(e.timestamp).toISOString().slice(0, 13),
              title: `${site.name} · ${e.ruleId}`,
              kind: "ALERT",
              severity: "MEDIUM",
              source: "waf",
              evidence: JSON.stringify({ siteId: e.siteId, ...clean }),
            });
        }
        await assertEventCapacity(tx,'wafEvents',inserted);
        return { ok: true };
      },
      { timeout: 15000 },
    );
    await this.correlation.ingest('waf',req.hostWafNode?'waf-events:'+req.hostWafNode:'waf-events',v.events.map(e=>({id:req.hostWafNode?req.hostWafNode+':'+e.id:e.id,siteId:e.siteId,type:'WAF_ATTACK',timestamp:e.timestamp,data:{ruleId:e.ruleId,action:e.action,method:e.method}})));
    return result;
  }
}
