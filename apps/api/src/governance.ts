import {assetScope,assertLinks,assertEvidence,restricted,resourceWhere} from "./scope";
import {
  Body, Controller, Get, Post, Patch, Param, Query, Req, UseGuards,
  Inject, forwardRef, ForbiddenException, NotFoundException, ConflictException,
  BadRequestException,
} from "@nestjs/common";
import { Prisma } from "@prisma/client";
import { z } from "zod";
import { Db } from "./db";
import { Platform } from "./platform";
import { AuthGuard, allow } from "./auth";
import { parse, role } from "./validation";
import { hashToken } from "./security";

export const approvalPolicyInput = z.object({
  approverRoles: z.array(role).min(1).max(4),
  allowSelfApproval: z.boolean().default(true),
}).strict();
const defaultApprovalPolicy = { approverRoles: ["ADMIN"], allowSelfApproval: true };
export const retentionInput = z.object({
  auditDays: z.number().int().min(30).max(3650).optional(),
  wafEventDays: z.number().int().min(1).max(3650).optional(),
  evaluationDays: z.number().int().min(1).max(3650).optional(),
  notificationDays: z.number().int().min(1).max(3650).optional(),
}).strict();
const defaultRetention = { auditDays: 365, wafEventDays: 90, evaluationDays: 90, notificationDays: 90 };
const notificationInput = z.object({
  enabled: z.boolean().optional(),
  approvals: z.boolean().optional(),
  taskFailures: z.boolean().optional(),
  criticalFindings: z.boolean().optional(),
}).strict();
const defaultNotifications = { enabled: true, approvals: true, taskFailures: true, criticalFindings: true };
type Tx = Prisma.TransactionClient;

export async function assertTaskApproval(db: Tx, task: { requestedBy: string }, actor: string) {
  const [user, setting] = await Promise.all([
    db.user.findUnique({ where: { email: actor } }),
    db.setting.findUnique({ where: { key: "approval-policy" } }),
  ]);
  const policy = parse(approvalPolicyInput, setting?.value || defaultApprovalPolicy);
  if (!user || user.disabled || !policy.approverRoles.includes(user.role as z.infer<typeof role>))
    throw new ForbiddenException("没有审批权限");
  if (!policy.allowSelfApproval && task.requestedBy === actor)
    throw new ForbiddenException("组织策略禁止自批，请由其他审批人处理");
}

@Controller("governance")
@UseGuards(AuthGuard)
export class GovernanceController {
  constructor(
    @Inject(Db) private db: Db,
    @Inject(forwardRef(() => Platform)) private platform: Platform,
  ) {}
  private async setting<T>(key: string, defaults: T): Promise<T> {
    const row = await this.db.setting.findUnique({ where: { key } });
    return { ...defaults, ...(row?.value as object || {}) };
  }
  private async saveSetting(key: string, value: Prisma.InputJsonValue, actor: string) {
    return this.db.$transaction(async tx => {
      await tx.setting.upsert({ where: { key }, create: { key, value }, update: { value } });
      await tx.audit.create({ data: { actor, action: "CONFIGURE", resource: "settings", resourceId: key, detail: value } });
      return value;
    });
  }
  @Get("approval-policy")
  async approvalPolicy() {
    return this.setting("approval-policy", defaultApprovalPolicy);
  }
  @Patch("approval-policy")
  async setApprovalPolicy(@Req() req: any, @Body() body: unknown) {
    allow(req, ["ADMIN"]);
    const value = parse(approvalPolicyInput, body);
    value.approverRoles = [...new Set(value.approverRoles)];
    return this.saveSetting("approval-policy", value, req.user.email);
  }
  @Get("retention")
  async retention(@Req() req: any) {
    allow(req, ["ADMIN"]);
    return this.setting("retention", defaultRetention);
  }
  @Patch("retention")
  async setRetention(@Req() req: any, @Body() body: unknown) {
    allow(req, ["ADMIN"]);
    const value = { ...await this.retention(req), ...parse(retentionInput, body) };
    return this.saveSetting("retention", value, req.user.email);
  }
  private async retentionCutoffs(req: any) {
    const policy = await this.retention(req);
    const now = Date.now();
    return {
      audit: new Date(now - policy.auditDays * 86400000),
      wafEvents: new Date(now - policy.wafEventDays * 86400000),
      evaluations: new Date(now - policy.evaluationDays * 86400000),
      notifications: new Date(now - policy.notificationDays * 86400000),
    };
  }
  @Post("retention/preview")
  async previewRetention(@Req() req: any) {
    const cutoffs = await this.retentionCutoffs(req);
    const [audit, wafEvents, evaluations, notifications] = await Promise.all([
      this.db.audit.count({ where: { createdAt: { lt: cutoffs.audit } } }),
      this.db.wafEvent.count({ where: { createdAt: { lt: cutoffs.wafEvents } } }),
      this.db.evaluation.count({ where: { createdAt: { lt: cutoffs.evaluations } } }),
      this.db.notification.count({ where: { createdAt: { lt: cutoffs.notifications } } }),
    ]);
    return { cutoffs, counts: { audit, wafEvents, evaluations, notifications } };
  }
  @Post("retention/purge")
  async purgeRetention(@Req() req: any, @Body() body: unknown) {
    allow(req, ["ADMIN"]);
    parse(z.object({ confirm: z.literal(true) }).strict(), body);
    const cutoffs = await this.retentionCutoffs(req);
    return this.db.$transaction(async tx => {
      const audit = await tx.audit.deleteMany({ where: { createdAt: { lt: cutoffs.audit } } });
      const wafEvents = await tx.wafEvent.deleteMany({ where: { createdAt: { lt: cutoffs.wafEvents } } });
      const evaluations = await tx.evaluation.deleteMany({ where: { createdAt: { lt: cutoffs.evaluations } } });
      const notifications = await tx.notification.deleteMany({ where: { createdAt: { lt: cutoffs.notifications } } });
      const deleted = { audit: audit.count, wafEvents: wafEvents.count, evaluations: evaluations.count, notifications: notifications.count };
      await tx.audit.create({ data: { actor: req.user.email, action: "PURGE", resource: "retention", detail: { deleted, cutoffs: Object.fromEntries(Object.entries(cutoffs).map(([key, value]) => [key, value.toISOString()])) } } });
      return { cutoffs, deleted };
    });
  }
  @Get("notification-settings")
  async notificationSettings(@Req() req: any) {
    return this.setting("notifications:" + req.user.id, defaultNotifications);
  }
  @Patch("notification-settings")
  async setNotificationSettings(@Req() req: any, @Body() body: unknown) {
    const value = { ...await this.notificationSettings(req), ...parse(notificationInput, body) };
    return this.saveSetting("notifications:" + req.user.id, value, req.user.email);
  }
  private async notificationScope(user:any) {
    const filters=[];
    for(const [resource,model] of [['assets','asset'],['findings','finding'],['tasks','task'],['incidents','incident']] as const) {
      const rows=await (this.db[model] as any).findMany({where:await resourceWhere(this.db,user,resource),select:{id:true}});
      filters.push({resource,resourceId:{in:rows.map((r:any)=>r.id)}});
    }
    return filters;
  }
  @Get("notifications")
  async notifications(@Req() req: any, @Query() query: any) {
    const v = parse(z.object({ page: z.coerce.number().int().min(1).default(1), pageSize: z.coerce.number().int().min(1).max(100).default(20) }), query);
    const where:any = { userId: req.user.id };
    if(restricted(req.user)) where.OR=await this.notificationScope(req.user);
    const [items, total, unread] = await Promise.all([
      this.db.notification.findMany({ where, orderBy: [{createdAt:"desc"},{id:"desc"}], take: v.pageSize, skip: (v.page - 1) * v.pageSize }),
      this.db.notification.count({ where }),
      this.db.notification.count({ where: { ...where, readAt: null } }),
    ]);
    return { items, total, unread, ...v };
  }
  @Patch("notifications/:id/read")
  async readNotification(@Req() req: any, @Param("id") id: string) {
    const changed = await this.db.notification.updateMany({ where: { id, userId: req.user.id, ...(restricted(req.user)?{OR:await this.notificationScope(req.user)}:{}) }, data: { readAt: new Date() } });
    if (!changed.count) throw new NotFoundException("通知不存在");
    return this.db.notification.findUniqueOrThrow({ where: { id } });
  }
  @Post("notifications/sync")
  async syncNotifications(@Req() req: any) {
    const settings = await this.notificationSettings(req);
    if (!settings.enabled) return { created: 0 };
    const candidates: Array<{ title: string; resource: string; resourceId: string; state: string }> = [];
    const policy = await this.approvalPolicy();
    if (settings.approvals && policy.approverRoles.includes(req.user.role)) {
      const tasks = await this.db.task.findMany({ where: { ...await resourceWhere(this.db,req.user,"tasks"),status: "PENDING", expiresAt: { gt: new Date() }, ...(!policy.allowSelfApproval ? { requestedBy: { not: req.user.email } } : {}) }, take: 100, orderBy: { createdAt: "desc" } });
      candidates.push(...tasks.map(t => ({ title: "待审批：" + t.title, resource: "tasks", resourceId: t.id, state: t.status })));
    }
    if (settings.taskFailures) {
      const tasks = await this.db.task.findMany({ where: { ...await resourceWhere(this.db,req.user,"tasks"),requestedBy: req.user.email, status: { in: ["FAILED", "UNKNOWN"] } }, take: 100, orderBy: { updatedAt: "desc" } });
      candidates.push(...tasks.map(t => ({ title: "修复任务需处理：" + t.title, resource: "tasks", resourceId: t.id, state: t.status })));
    }
    if (settings.criticalFindings) {
      const findings = await this.db.finding.findMany({ where: { ...await resourceWhere(this.db,req.user,"findings"),owner: { in: [req.user.email, req.user.name] }, severity: "CRITICAL", status: { notIn: ["CLOSED", "RESOLVED", "FALSE_POSITIVE"] } }, take: 100, orderBy: { updatedAt: "desc" } });
      candidates.push(...findings.map(f => ({ title: "严重问题：" + f.title, resource: "findings", resourceId: f.id, state: f.status })));
    }
    const result = await this.db.notification.createMany({ data: candidates.map(({ state, ...c }) => ({ ...c, userId: req.user.id, id: hashToken(JSON.stringify([req.user.id, c.resource, c.resourceId, state])) })), skipDuplicates: true });
    return { created: result.count };
  }
  @Get("imports")
  async imports(@Req() req: any) {
    allow(req, ["ADMIN", "ANALYST"]);
    const items = await this.db.importBatch.findMany({ where: req.user.role === "ADMIN" ? {} : { actor: req.user.email }, take: 100, orderBy: { createdAt: "desc" } });
    assertEvidence(req.user);
    return { items: restricted(req.user)?items.map(({items,result,...rest})=>rest):items, limit: 100 };
  }
  @Post("imports")
  async createImport(@Req() req: any, @Body() body: unknown) {
    allow(req, ["ADMIN", "ANALYST"]);
    assertEvidence(req.user);
    const v = parse(z.object({ items: z.array(z.unknown()).min(1).max(100) }).strict(), body);
    const batch = await this.db.importBatch.create({ data: { actor: req.user.email, status: "PENDING", items: v.items as Prisma.InputJsonValue } });
    const result=await this.runImport(batch.id, req.user.email, "PENDING",undefined,req.user);
    if(restricted(req.user)){const {items,...metadata}=result;return metadata;}
    return result;
  }
  @Post("imports/:id/retry")
  async retryImport(@Req() req: any, @Param("id") id: string, @Body() body: unknown) {
    allow(req, ["ADMIN", "ANALYST"]);
    assertEvidence(req.user);
    const v = parse(z.object({ items: z.array(z.unknown()).min(1).max(100).optional() }).strict(), body);
    const batch = await this.db.importBatch.findUnique({ where: { id } });
    if (!batch || (req.user.role !== "ADMIN" && batch.actor !== req.user.email)) throw new NotFoundException("导入批次不存在");
    if (batch.status !== "FAILED") throw new ConflictException("仅失败批次可重试");
    const result=await this.runImport(id, req.user.email, "FAILED", v.items as Prisma.InputJsonValue | undefined,req.user);
    if(restricted(req.user)){const {items,...metadata}=result;return metadata;}
    return result;
  }
  private async runImport(id: string, actor: string, expectedStatus: string, items?: Prisma.InputJsonValue,user?:any) {
    const claimed = await this.db.importBatch.updateMany({ where: { id, status: expectedStatus }, data: { status: "RUNNING", error: null, ...(items ? { items } : {}) } });
    if (!claimed.count) throw new ConflictException("批次已在处理，请刷新");
    const batch = await this.db.importBatch.findUniqueOrThrow({ where: { id } });
    try {
      return await this.db.$transaction(async tx => {
        // The status and imported rows commit together; retry never duplicates a committed batch.
        const raw = parse(z.array(z.unknown()).min(1).max(100), batch.items);
        const imported = [];
        for (const row of raw) {
          await assertLinks(tx,user,row);
          if(restricted(user)&&!(row as any)?.assetId)throw new BadRequestException('导入需要授权资产');
          imported.push(await this.platform.ingest(tx, row));
        }
        await tx.audit.create({ data: { actor, action: expectedStatus === "FAILED" ? "RETRY_IMPORT" : "IMPORT", resource: "import-batches", resourceId: id, detail: { count: imported.length } } });
        return tx.importBatch.update({ where: { id }, data: { status: "SUCCEEDED", error: null, result: { total: imported.length, findingIds: imported.map(f => f.id) } } });
      }, { timeout: 15000 });
    } catch (error) {
      const message = error instanceof BadRequestException ? error.message : "导入失败，请核对数据后重试";
      return this.db.importBatch.update({ where: { id }, data: { status: "FAILED", error: message, result: Prisma.DbNull } });
    }
  }
}
