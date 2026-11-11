import {Prisma} from "@prisma/client";
import {assetScope,restricted,resourceWhere} from "./scope";
import {
  Controller,
  Get,
  Post,
  Param,
  Req,
  UseGuards,
  Inject,
  NotFoundException,
} from "@nestjs/common";
import { Db } from "./db";
import { AuthGuard, allow } from "./auth";

@Controller("operations")
@UseGuards(AuthGuard)
export class OperationsController {
  constructor(@Inject(Db) private db: Db) {}
  @Get("health") async health(@Req() req: any) {
    allow(req, ["ADMIN"]);
    const started = Date.now();
    await this.db.$queryRaw`SELECT 1`;
    return {
      database: { ok: true, latencyMs: Date.now() - started },
      process: {
        uptimeSeconds: Math.floor(process.uptime()),
        nodeVersion: process.version,
      },
      checkedAt: new Date().toISOString(),
    };
  }
  @Get("business-groups") async businessGroups(@Req() req:any) {
    const groups = await this.db.asset.groupBy({
      where:assetScope(req.user),
      by: ["business"],
      _count: { _all: true },
    });
    const counts=new Map(groups.map(group=>[group.business,group._count._all]));
    const allowedNames=restricted(req.user)?[...new Set<string>([...(req.user.dataScope.businesses||[]),...groups.flatMap(group=>group.business?[group.business]:[])])]:null;
    const registered=await this.db.businessGroup.findMany({where:allowedNames?{name:{in:allowedNames}}:{},select:{name:true}});
    // Empty registered groups must remain selectable before their first asset is assigned.
    for(const group of registered)if(!counts.has(group.name))counts.set(group.name,0);
    return {items:[...counts].map(([business,assetCount])=>({business:business||"未分组",assetCount})).sort((a,b)=>b.assetCount-a.assetCount||a.business.localeCompare(b.business))};
  }

  @Get("trends") async trends(@Req() req:any) {
    const scoped=restricted(req.user);
    const ids=scoped?(await this.db.asset.findMany({where:assetScope(req.user),select:{id:true}})).map(a=>a.id):[];
    const assetFilter=scoped?Prisma.sql`AND "assetId" = ANY(${ids}::text[])`:Prisma.empty;
    const wafFilter=scoped?Prisma.sql`AND FALSE`:Prisma.empty;
    const start = new Date();
    start.setUTCHours(0, 0, 0, 0);
    start.setUTCDate(start.getUTCDate() - 29);
    // Aggregate in PostgreSQL so this endpoint does not download every event.
    const rows = await this.db.$queryRaw<
      Array<{ day: string; metric: string; count: bigint }>
    >(Prisma.sql`
   SELECT to_char("createdAt" AT TIME ZONE 'UTC','YYYY-MM-DD') AS day,'findings' AS metric,COUNT(*) AS count FROM "Finding" WHERE "createdAt">=${start} ${assetFilter} GROUP BY day
   UNION ALL SELECT to_char("createdAt" AT TIME ZONE 'UTC','YYYY-MM-DD'),'closed',COUNT(*) FROM "Finding" WHERE "createdAt">=${start} ${assetFilter} AND status IN ('CLOSED','RESOLVED') GROUP BY 1
   UNION ALL SELECT to_char("createdAt" AT TIME ZONE 'UTC','YYYY-MM-DD'),'tasks',COUNT(*) FROM "Task" WHERE "createdAt">=${start} ${assetFilter} GROUP BY 1
   UNION ALL SELECT to_char("createdAt" AT TIME ZONE 'UTC','YYYY-MM-DD'),'events',COUNT(*) FROM "WafEvent" WHERE "createdAt">=${start} ${wafFilter} GROUP BY 1`);
    const items = Array.from({ length: 30 }, (_, i) => ({
      day: new Date(start.getTime() + i * 86400000).toISOString().slice(0, 10),
      findings: 0,
      closed: 0,
      tasks: 0,
      events: 0,
    }));
    for (const row of rows) {
      const item = items.find((i) => i.day === row.day);
      if (
        item &&
        ["findings", "closed", "tasks", "events"].includes(row.metric)
      )
        (item as any)[row.metric] = Number(row.count);
    }
    return {
      items,
      timezone: "UTC",
      basis:
        "按创建日期分组；closed 表示该创建日期问题中当前已关闭或已解决的数量，不是当日关闭数量。",
    };
  }
  @Get("exports") async exports(@Req() req: any) {
    allow(req, ["ADMIN"]);
    const items = await this.db.audit.findMany({
      where: { action: "EXPORT" },
      select: { id: true, actor: true, resource: true, createdAt: true },
      orderBy: { createdAt: "desc" },
      take: 100,
    });
    return { items, limit: 100 };
  }
  @Post("assets/:id/revoke") async revoke(
    @Req() req: any,
    @Param("id") id: string,
  ) {
    allow(req, ["ADMIN"]);
    return this.db.$transaction(async (tx) => {
      const changed = await tx.asset.updateMany({
        where: { id },
        data: { tokenHash: null },
      });
      if (!changed.count) throw new NotFoundException("资产不存在");
      await tx.audit.create({
        data: {
          actor: req.user.email,
          action: "REVOKE_CREDENTIAL",
          resource: "assets",
          resourceId: id,
        },
      });
      return { ok: true };
    });
  }
  @Get("credentials") async credentials(@Req() req: any) {
    allow(req, ["ADMIN"]);
    // Select a boolean in the database; credential hashes never enter the response object.
    const items = await this.db.$queryRaw<
      Array<{
        id: string;
        hostname: string;
        enrolled: boolean;
        updatedAt: Date;
      }>
    >`SELECT id,hostname,("tokenHash" IS NOT NULL) AS enrolled,"updatedAt" FROM "Asset" ORDER BY hostname`;
    return {
      items,
      components: {
        enrollmentConfigured: Boolean(process.env.ENROLLMENT_TOKEN),
        wafConfigured: Boolean(process.env.WAF_TOKEN),
      },
    };
  }
  @Get("notifications") async notifications(@Req() req:any) {
    const taskWhere=await resourceWhere(this.db,req.user,'tasks');
    const findingWhere=await resourceWhere(this.db,req.user,'findings');
    const [pendingApprovals, failedTasks, criticalRisks] = await Promise.all([
      this.db.task.count({ where: { ...taskWhere, status: "PENDING" } }),
      this.db.task.count({ where: { ...taskWhere,status: { in: ["FAILED", "UNKNOWN"] } } }),
      this.db.finding.count({
        where: {
          ...findingWhere,
          kind: "RISK",
          severity: "CRITICAL",
          status: { notIn: ["CLOSED", "FALSE_POSITIVE"] },
        },
      }),
    ]);
    return {
      pendingApprovals,
      failedTasks,
      criticalRisks,
      channel: "in-app",
      checkedAt: new Date().toISOString(),
    };
  }
}
