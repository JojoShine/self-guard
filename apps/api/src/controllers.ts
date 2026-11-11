import {repairTemplateCatalog} from "./templates";
import { assertScope, assertGlobal, assertEvidence, assertLinks, resourceWhere } from "./scope";
import {
  Controller,
  Get,
  Post,
  Patch,
  Body,
  Param,
  Query,
  Req,
  UseGuards,
  Inject,
  BadRequestException,
  ConflictException,
  NotFoundException,
} from "@nestjs/common";
import { AuthGuard, allow } from "./auth";
import { Platform } from "./platform";
import { parse, text, pageInput } from "./validation";
import { z } from "zod";
@Controller()
@UseGuards(AuthGuard)
export class PlatformController {
  constructor(@Inject(Platform) private p: Platform) {}
  @Get("discoveries") discoveries(@Query() q: any, @Req() req:any) {
    return this.p.discoveries(q,req.user);
  }
  @Get("waf-access/:id") async accessDetail(@Param('id') id:string,@Req()req:any){
    assertGlobal(req.user);assertEvidence(req.user);
    const record=await this.p.db.wafAccess.findUnique({where:{id}});if(!record)throw new NotFoundException('该请求的访问记录尚未同步或已超过保留范围');
    return record;
  }
  @Get("waf-access") async access(@Query() q:any,@Req() req:any){
    assertGlobal(req.user);
    const v=parse(pageInput.extend({pageSize:z.coerce.number().int().min(1).max(100).default(15),nodeId:text.optional(),sortBy:z.enum(['createdAt','updatedAt','timestamp','durationMicros','status','nodeId']).default('timestamp')}),q);
    const where:any=v.nodeId?{nodeId:v.nodeId}:{};
    if(v.q){where.OR=['nodeId','siteId','method','path'].map(field=>({[field]:{contains:v.q,mode:'insensitive'}}));if(/^\d{3}$/.test(v.q))where.OR.push({status:Number(v.q)});}
    if(v.createdFrom||v.createdTo)where.timestamp={...(v.createdFrom?{gte:new Date(v.createdFrom)}:{}),...(v.createdTo?{lte:new Date(v.createdTo)}:{})};
    const sortBy=['timestamp','durationMicros','status','nodeId'].includes(v.sortBy)?v.sortBy:'timestamp';
    const [items,total]=await Promise.all([this.p.db.wafAccess.findMany({where,orderBy:[{[sortBy]:v.order},{id:'asc'}],take:v.pageSize,skip:(v.page-1)*v.pageSize}),this.p.db.wafAccess.count({where})]);
    return {items,total,scope:'节点最近1024条访问快照同步；可能遗漏高吞吐历史，参照节点淘汰计数'};
  }
  @Get("waf-nodes") async nodes(@Query() q:any,@Req() req:any) {
    assertGlobal(req.user);
    const v=parse(pageInput.extend({pageSize:z.coerce.number().int().min(1).max(100).default(15),sortBy:z.enum(['createdAt','updatedAt','lastSeen','version','id']).default('lastSeen')}),q);
    const where:any={};
    if(v.q)where.OR=['id','version'].map(field=>({[field]:{contains:v.q,mode:'insensitive'}}));
    if(v.createdFrom||v.createdTo)where.lastSeen={...(v.createdFrom?{gte:new Date(v.createdFrom)}:{}),...(v.createdTo?{lte:new Date(v.createdTo)}:{})};
    const sortBy=['lastSeen','version','id'].includes(v.sortBy)?v.sortBy:'lastSeen';
    const [items,total]=await Promise.all([this.p.db.wafNode.findMany({where,orderBy:sortBy==='id'?[{id:v.order}]:[{[sortBy]:v.order},{id:'asc'}],take:v.pageSize,skip:(v.page-1)*v.pageSize}),this.p.db.wafNode.count({where})]);
    return {items,total};
  }
  @Post("findings/:id/verify") async verifyFinding(
    @Param("id") id: string,
    @Body() body: unknown,
    @Req() req: any,
  ) {
    allow(req, ["ADMIN", "ANALYST"]);
    const v = parse(
      z
        .object({
          resolved: z.boolean(),
          evidence: z.string().trim().min(5).max(16000),
          expectedUpdatedAt: z.string().datetime().optional(),
        })
        .strict(),
      body,
    );
    return this.p.db.$transaction(async (tx) => {
      await assertScope(tx,req.user,"findings",id);
      const f = await tx.finding.findUnique({ where: { id } });
      if (!f || !['RISK','ALERT'].includes(f.kind) || f.status !== "VERIFYING")
        throw new BadRequestException("仅待验证风险或告警可以复查");
      if(v.expectedUpdatedAt&&Date.parse(v.expectedUpdatedAt)!==f.updatedAt.getTime())throw new ConflictException('记录已更新，请刷新后重新复查');
      const result = await tx.finding.updateMany({
        where: { id, status: "VERIFYING", updatedAt: f.updatedAt },
        data: {
          status: v.resolved ? f.kind==='RISK'?"CLOSED":"RESOLVED" : "IN_PROGRESS",
          reason: v.evidence,
        },
      });
      if (!result.count) throw new BadRequestException("记录已变化，请刷新");
      await this.p.audit(tx, req.user.email, "VERIFY", "findings", id, v);
      return tx.finding.findUnique({ where: { id } });
    });
  }
  @Get("overview") overview(@Req() req:any) {
    return this.p.overview(req.user);
  }
  @Post("rules/:id/run") runRule(
    @Param("id") id: string,
    @Body() b: unknown,
    @Req() req: any,
  ) {
    allow(req, ["ADMIN", "ANALYST"]);
    return this.p.runRule(id, b, req.user.email);
  }
  @Post("findings/import") import(@Body() b: unknown, @Req() req: any) {
    allow(req, ["ADMIN", "ANALYST"]);
    return this.p.import(b, req.user.email);
  }
  @Post(["tasks/:id/approve", "tasks/:id/reject", "tasks/:id/verify"])
  async task(@Param("id") id: string, @Body() b: unknown, @Req() req: any) {
    const action = req.path.split("/").pop();
    if(action==="verify")allow(req,["ADMIN","ANALYST"]);
    return this.taskView(
      await this.p.taskAction(id, action, b, req.user.email),
      req,
    );
  }
  @Get("reports/summary") async report(@Req() req: any) {
    const data = await this.p.overview(req.user);
    await this.p.db.audit.create({
      data: { actor: req.user.email, action: "EXPORT", resource: "reports" },
    });
    return {
      ...data,
      generatedAt: new Date().toISOString(),
      scope: "当前组织；风险/告警/事件分别统计，WAF 指标仅已接收安全事件",
    };
  }
  @Get(":resource/:id/versions") versions(
    @Param("resource") r: string,
    @Param("id") id: string,
    @Req() req:any,
  ) {
    return this.p.versions(r, id, req.user);
  }
  @Post(":resource/:id/restore") restore(
    @Param("resource") r: string,
    @Param("id") id: string,
    @Body() b: unknown,
    @Req() req: any,
  ) {
    allow(req, r === "sites" ? ["ADMIN"] : ["ADMIN", "ANALYST"]);
    return this.p.restore(r, id, b, req.user.email);
  }
  @Get(":resource/:id/comments") async comments(
    @Param("resource") resource: string,
    @Param("id") id: string,
    @Req() req: any,
  ) {
    assertEvidence(req.user);
    if (resource === "users") allow(req, ["ADMIN"]);
    await this.p.get(resource, id, req.user);
    return {
      items: await this.p.db.comment.findMany({
        where: { resource, resourceId: id },
        orderBy: { createdAt: "asc" },
        take: 200,
      }),
    };
  }
  @Post(":resource/:id/comments") async addComment(
    @Param("resource") resource: string,
    @Param("id") id: string,
    @Body() body: unknown,
    @Req() req: any,
  ) {
    allow(
      req,
      resource === "users" ? ["ADMIN"] : ["ADMIN", "ANALYST", "OPERATOR"],
    );
    assertEvidence(req.user);
    await this.p.get(resource, id, req.user);
    const v = parse(
      z.object({ body: z.string().trim().min(1).max(16000) }).strict(),
      body,
    );
    return this.p.db.$transaction(async (tx) => {
      const c = await tx.comment.create({
        data: {
          resource,
          resourceId: id,
          author: req.user.email,
          body: v.body,
        },
      });
      await this.p.audit(tx, req.user.email, "COMMENT", resource, id);
      return c;
    });
  }
  private taskView(row: any, req: any) {
    const template=repairTemplateCatalog.find(t=>t.id===row?.template);
    if(template)row={...row,plan:{...template,version:row.templateVersion||template.version,notBefore:row.notBefore,windowEnd:row.windowEnd,expiresAt:row.expiresAt,preflightStatus:'前置条件在目标主机执行前检查，审批预览不代表已经通过'}};
    if (
      row?.template === "CONFIG_VALUE" &&
      !["ADMIN", "OPERATOR"].includes(req.user.role)
    )
      return {
        ...row,
        parameters: {
          ...row.parameters,
          value: "[已隐藏]",
          expectedValue: "[已隐藏]",
        },
      };
    return row;
  }
  @Get(":resource") async list(
    @Param("resource") r: string,
    @Query() q: any,
    @Req() req: any,
  ) {
    if (["users", "audit"].includes(r)) allow(req, ["ADMIN"]);
    const result = await this.p.list(r, q, req.user);
    return r === "tasks"
      ? {
          ...result,
          items: result.items.map((item: any) => this.taskView(item, req)),
        }
      : result;
  }
  @Get(":resource/:id") async get(
    @Param("resource") r: string,
    @Param("id") id: string,
    @Req() req: any,
  ) {
    if (r === "users") allow(req, ["ADMIN"]);
    const result = await this.p.get(r, id, req.user);
    return r === "tasks" ? this.taskView(result, req) : result;
  }
  @Post(":resource") create(
    @Param("resource") r: string,
    @Body() b: unknown,
    @Req() req: any,
  ) {
    if(r==="assets"&&b&&typeof b==="object"&&"executorPublicKey" in b)allow(req,["ADMIN"]);
    allow(
      req,
      r === "users" || r === "sites"
        ? ["ADMIN"]
        : r === "tasks"
          ? ["ADMIN", "OPERATOR"]
          : ["ADMIN", "ANALYST"],
    );
    return this.p.create(r, b, req.user.email);
  }
  @Patch(":resource/:id") patch(
    @Param("resource") r: string,
    @Param("id") id: string,
    @Body() b: unknown,
    @Req() req: any,
  ) {
    if(r==="assets"&&b&&typeof b==="object"&&"executorPublicKey" in b)allow(req,["ADMIN"]);
    allow(
      req,
      ["users", "sites"].includes(r) ? ["ADMIN"] : ["ADMIN", "ANALYST"],
    );
    return this.p.patch(r, id, b, req.user.email);
  }
}
