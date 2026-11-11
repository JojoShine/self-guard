import {assertDatabaseRuleEngine,assertInstanceScope} from './database-instances';
import {findingSecurityDomain} from './security-domain';
import {databaseAccessInput,databaseActivityInput} from './data-security';
import {saveAssetRemoteAccess} from './asset-remote-access';
import {assetOperatingSystemData} from './asset-os';
import {databaseBaselineInput,databaseLogInput} from './data-security';
import {rebindSiteRuleDeployment,validateStoredWafEnvelope} from './waf-runtime';
import {assertTemplateEnabled} from "./templates";
import {ruleWithBaseConfig,evaluateScopedVulnerability as evaluateVulnerability} from "./rule-tools";
import {recordAssetChange} from "./asset-history";
import { assertGlobal, assertEvidence, assertLinks, assertScope, assetScope, dataScopeInput, evidenceAllowed, restricted, resourceWhere } from "./scope";
import {matchesOsvRange} from "./versions";
import {stopFailedBatch} from "./batches";
import { assertTaskApproval } from "./governance";
import {
  Injectable,
  Inject,
  BadRequestException,
  NotFoundException,
  ConflictException,
} from "@nestjs/common";
import { Prisma } from "@prisma/client";
import { Db } from "./db";
import { hashToken, hashPassword } from "./security";
import {
  parse,
  assetInput,
  findingInput,
  ruleInput,
  siteInput,
  pageInput,
  text,
  severity,
  role,
} from "./validation";
import {
  findingTransition,
  validateTaskParameters,
  validateConfigParameters,
  validateServiceParameters,
  taskTransition,
} from "./domain";
import { z } from "zod";
import { isIP } from "node:net";
type Tx = Prisma.TransactionClient;
export const safeAsset = {
  id: true,
  hostname: true,
  os: true,
  osDistribution: true,
  osVersion: true,
  ip: true,
  business: true,
  owner: true,
  tags: true,
  importance: true,
  inventory: true,
  archivedAt:true,
  executorPublicKey:true,
  lastSeen: true,
  createdAt: true,
  updatedAt: true,
} as const;
export const safeUser = {
  id: true,
  email: true,
  name: true,
  role: true,
  disabled: true,
  dataScope: true,
  createdAt: true,
} as const;
@Injectable()
export class Platform {
  constructor(@Inject(Db) readonly db: Db) {}
  async audit(
    tx: Tx,
    actor: string,
    action: string,
    resource: string,
    resourceId?: string,
    detail: any = {},
  ) {
    await tx.audit.create({
      data: { actor, action, resource, resourceId, detail },
    });
  }
  async discoveries(query: any, user?: any) {
    const v = parse(pageInput, query);
    const filters = [Prisma.sql`1=1`];
    if(v.securityDomain)filters.push(Prisma.sql`${v.securityDomain}=ANY("securityDomains")`);
    if (restricted(user)) {
      const findings = await this.db.finding.findMany({where:await resourceWhere(this.db,user,'findings'),select:{id:true}});
      const incidents = await this.db.incident.findMany({where:await resourceWhere(this.db,user,'incidents'),select:{id:true}});
      const ids=[...findings,...incidents].map(row=>row.id);
      filters.push(Prisma.sql`id = ANY(${ids}::text[])`);
    }
    if(v.q) filters.push(evidenceAllowed(user) ? Prisma.sql`(title ILIKE ${'%'+v.q+'%'} OR to_tsvector('simple',coalesce(title,'')||' '||coalesce(evidence,'')) @@ plainto_tsquery('simple',${v.q}))` : Prisma.sql`title ILIKE ${'%'+v.q+'%'}`);
    if (v.kind) filters.push(Prisma.sql`kind=${v.kind}`);
    if (v.status) filters.push(Prisma.sql`status=${v.status}`);
    if (v.severity) filters.push(Prisma.sql`severity=${v.severity}`);
    if (v.owner) filters.push(Prisma.sql`owner=${v.owner}`);
    if(v.createdFrom)filters.push(Prisma.sql`"createdAt">=${new Date(v.createdFrom)}`);
    if(v.createdTo)filters.push(Prisma.sql`"createdAt"<=${new Date(v.createdTo)}`);
    if(v.assetId||v.business){
      const assets=await this.db.asset.findMany({where:{AND:[await resourceWhere(this.db,user,'assets'),...(v.assetId?[{id:v.assetId}]:[]),...(v.business?[{business:v.business}]:[])]},select:{id:true}});
      const ids=assets.map(a=>a.id);
      const incidents=await this.db.incident.findMany({where:{AND:[await resourceWhere(this.db,user,'incidents'),{OR:[{assetIds:{hasSome:ids}},{links:{some:{finding:{assetId:{in:ids}}}}}]}]},select:{id:true}});
      filters.push(Prisma.sql`("assetId"=ANY(${ids}::text[]) OR id=ANY(${incidents.map(i=>i.id)}::text[]))`);
    }
    const base = Prisma.sql`WITH discoveries AS (
   SELECT id,title,kind,severity,status,"assetId",source,owner,"createdAt","updatedAt",evidence,"securityDomain"::text AS "securityDomain",ARRAY["securityDomain"::text] AS "securityDomains" FROM "Finding"
   UNION ALL
   SELECT i.id,i.title,'INCIDENT' AS kind,i.severity,i.status,NULL AS "assetId",'incident' AS source,i.owner,i."createdAt",i."updatedAt",i.description AS evidence,NULL::text AS "securityDomain",COALESCE((SELECT array_agg(DISTINCT f."securityDomain"::text) FROM "IncidentFinding" l JOIN "Finding" f ON f.id=l."findingId" WHERE l."incidentId"=i.id),ARRAY['UNCLASSIFIED']) AS "securityDomains" FROM "Incident" i
  )`;
    const condition = Prisma.join(filters, " AND ");
    const order=Prisma.raw(v.order==='asc'?'ASC':'DESC');
    const sort=Prisma.raw(['createdAt','updatedAt','title','severity'].includes(v.sortBy)?'"'+v.sortBy+'"':'"createdAt"');
    const items = await this.db.$queryRaw<any[]>(
      Prisma.sql`${base} SELECT * FROM discoveries WHERE ${condition} ORDER BY ${sort} ${order},id ${order} LIMIT ${v.pageSize} OFFSET ${(v.page - 1) * v.pageSize}`,
    );
    const total = await this.db.$queryRaw<any[]>(
      Prisma.sql`${base} SELECT count(*)::int AS total FROM discoveries WHERE ${condition}`,
    );
    return { items, total: total[0].total, page: v.page, pageSize: v.pageSize };
  }
  async list(resource: string, query: any, user?: any) {
    const v = parse(resource === "audit" ? pageInput.extend({resourceId:text.optional()}) : pageInput, query),
      where: any = await resourceWhere(this.db,user,resource);
    const map: Record<string, string> = {
      assets: "asset",
      findings: "finding",
      incidents: "incident",
      rules: "rule",
      tasks: "task",
      sites: "site",
      audit: "audit",
      users: "user",
      "waf-events": "wafEvent",
      evaluations: "evaluation",
    };
    if (!map[resource]) throw new NotFoundException();
    if(v.securityDomain){
      if(resource!=="findings")throw new BadRequestException('此列表不支持安全领域筛选');
      where.securityDomain=v.securityDomain;
    }
    if (v.q) {
      const fields: Record<string, string[]> = {
        assets: ["hostname", "business", "owner"],
        findings: ["title", "source", "owner", "evidence"],
        incidents: ["title", "description", "owner"],
        rules: ["name"],
        tasks: ["title"],
        sites: ["name", "hostname"],
        audit: ["actor", "action"],
        users: ["email", "name"],
        "waf-events": ["path", "ruleId"],
        evaluations: ["ruleName", "evidence"],
      };
      where.AND = [...(where.AND || []), {OR: fields[resource].filter(f => evidenceAllowed(user) || !["description","evidence"].includes(f)).map((f) => ({
        [f]: { contains: v.q, mode: "insensitive" },
      }))}];
    }
    if(v.owner&&['assets','findings','incidents'].includes(resource))where.owner=v.owner;
    if(v.business){
      if(resource==='assets')where.business=v.business;
      if(resource==='findings')where.AND=[...(where.AND||[]),{OR:[{asset:{is:{business:v.business}}},{instance:{is:{business:v.business}}}]}];
      if(resource==='tasks')where.AND=[...(where.AND||[]),{asset:{is:{business:v.business}}}];
      if(resource==='incidents'){
        const assets=await this.db.asset.findMany({where:{AND:[await resourceWhere(this.db,user,'assets'),{business:v.business}]},select:{id:true}});
        where.AND=[...(where.AND||[]),{OR:[{assetIds:{hasSome:assets.map(a=>a.id)}},{links:{some:{finding:{asset:{is:{business:v.business}}}}}}]}];
      }
    }
    if (v.status && ["findings", "incidents", "tasks"].includes(resource))
      where.status = v.status;
    if (v.severity && ["findings", "incidents", "rules"].includes(resource))
      where.severity = v.severity;
    if (v.kind && ["findings", "rules"].includes(resource)) where.kind = v.kind;
    if(v.assetId&&resource==="assets")where.id=v.assetId;
    if (v.assetId && ["findings", "tasks"].includes(resource))
      where.assetId = v.assetId;
    if (v.resourceId && resource === "audit") where.resourceId = v.resourceId;
    if(v.createdFrom||v.createdTo)where.createdAt={...(v.createdFrom?{gte:new Date(v.createdFrom)}:{}),...(v.createdTo?{lte:new Date(v.createdTo)}:{})};
    const sortAllowed:Record<string,string[]>={assets:['hostname','createdAt','updatedAt'],findings:['title','severity','createdAt','updatedAt'],incidents:['title','severity','createdAt','updatedAt'],rules:['name','severity','createdAt','updatedAt'],tasks:['title','createdAt','updatedAt'],sites:['name','hostname','createdAt','updatedAt']};
    const sortKey=(sortAllowed[resource]||['createdAt']).includes(v.sortBy)?v.sortBy:'createdAt';
    const delegate = (this.db as any)[map[resource]];
    const extra: any =
      resource === "assets"
        ? { select: safeAsset }
        : resource === "users"
          ? { select: safeUser }
          : resource === "incidents"
            ? { include: { links: true } }
            : {};
    const [items, total] = await Promise.all([
      delegate.findMany({
        where,
        orderBy: [{[sortKey]:v.order},{id:v.order}],
        skip: (v.page - 1) * v.pageSize,
        take: v.pageSize,
        ...extra,
      }),
      delegate.count({ where }),
    ]);
    return {
      items: items.map((i: any) =>
        resource === "incidents" ? this.incidentShape(i) : i,
      ),
      total,
      page: v.page,
      pageSize: v.pageSize,
    };
  }
  incidentShape(i: any) {
    const { links, ...rest } = i;
    return { ...rest, findingIds: links?.map((l: any) => l.findingId) || [] };
  }
  async get(resource: string, id: string, user?: any) {
    const map: Record<string, string> = {
      assets: "asset",
      findings: "finding",
      incidents: "incident",
      rules: "rule",
      tasks: "task",
      sites: "site",
      users: "user",
      "waf-events": "wafEvent",
    };
    if (!map[resource]) throw new NotFoundException();
    await assertScope(this.db,user,resource,id);
    const extra =
      resource === "assets"
        ? { select: safeAsset }
        : resource === "users"
          ? { select: safeUser }
          : resource === "incidents"
            ? { include: { links: true } }
            : {};
    const item = await (this.db as any)[map[resource]].findUnique({
      where: { id },
      ...extra,
    });
    if (!item) throw new NotFoundException();
    return resource === "incidents" ? this.incidentShape(item) : item;
  }
  async create(resource: string, body: unknown, actor: string) {
    const user=await this.db.user.findUnique({where:{email:actor}});
    await assertLinks(this.db,user,body);
    if (['rules','sites'].includes(resource)) assertGlobal(user);
    if (resource==='incidents' && restricted(user) && !(body as any)?.findingIds?.length) throw new BadRequestException('受限用户创建事件需要关联授权问题');
    if (resource==='assets' && restricted(user)) {
      const v=parse(assetInput,body);
      if (!user?.dataScope || !(user.dataScope as any).businesses?.includes(v.business)) throw new BadRequestException('资产业务不在授权范围');
    }
    return this.db.$transaction(async (tx) => {
      let item: any;
      if (resource === "assets") {
        const {sshAccess,...assetData}=parse(assetInput,body);
        item = await tx.asset.create({
          data: assetOperatingSystemData(assetData),
          select: safeAsset,
        });
        if(sshAccess)await saveAssetRemoteAccess(tx,user,item,sshAccess);
        if(item.business)await tx.businessGroup.upsert({where:{name:item.business},create:{name:item.business},update:{}});
      }
      else if (resource === "rules") {
        const v = parse(ruleInput, body);
        this.validateRule(v);
        if(typeof v.config.instanceId==='string'){const instance=await assertInstanceScope(tx,{role:user?.role||"VIEWER",dataScope:parse(dataScopeInput,user?.dataScope||{})},v.config.instanceId);if(instance.archivedAt)throw new BadRequestException('数据库实例已归档');assertDatabaseRuleEngine(instance.engine,v.config);}
        item = await tx.rule.create({
          data: {
            ...v,
            config: v.config as Prisma.InputJsonValue,
            ...(v.intervalSeconds
              ? { nextRunAt: new Date(Date.now() + v.intervalSeconds * 1000) }
              : {}),
          },
        });
      } else if (resource === "sites") {
        const v = parse(siteInput, body);
        this.validateSiteConfig(v.config || {});
        item = await tx.site.create({
          data: { ...v, config: v.config as Prisma.InputJsonValue },
        });
      } else if (resource === "incidents") {
        const v = parse(
          z
            .object({
              title: text,
              severity,
              description: z.string().max(16000).default(""),
              owner: text.optional(),
              findingIds: z.array(z.string().uuid()).max(100).default([]),
            })
            .strict(),
          body,
        );
        const { findingIds, ...data } = v;
        if (
          (await tx.finding.count({ where: { id: { in: findingIds } } })) !==
          new Set(findingIds).size
        )
          throw new BadRequestException("关联问题不存在");
        item = this.incidentShape(
          await tx.incident.create({
            data: {
              ...data,
              links: {
                create: [...new Set(findingIds)].map((findingId) => ({
                  findingId,
                })),
              },
            },
            include: { links: true },
          }),
        );
      } else if (resource === "tasks") {
        const v = parse(
          z
            .object({
              title: text,
              assetId: z.string().uuid(),
              findingId: z.string().uuid().optional(),
              template: z.enum(["FILE_PERMISSION", "CONFIG_VALUE", "SERVICE_STATE"]),
              parameters: z.unknown(),
              reason: z.string().max(2000).optional(),
            })
            .strict(),
          body,
        );
        await assertTemplateEnabled(tx,v.template);
        const parameters =
          v.template === "FILE_PERMISSION" ? validateTaskParameters(v.parameters) : v.template === "CONFIG_VALUE" ? validateConfigParameters(v.parameters) : validateServiceParameters(v.parameters);
        const asset = await tx.asset.findUnique({ where: { id: v.assetId } });
        if (!asset) throw new BadRequestException("资产不存在");
        if (v.findingId) {
          const f = await tx.finding.findUnique({ where: { id: v.findingId } });
          if (!f || f.assetId !== v.assetId || f.kind !== "RISK")
            throw new BadRequestException("风险必须属于目标资产");
        }
        item = await tx.task.create({
          data: {
            ...v,
            parameters,
            requestedBy: actor,
            expiresAt: new Date(Date.now() + 86400000),
          },
        });
      } else if (resource === "users") {
        const v = parse(
          z
            .object({
              email: z.string().email().max(254),
              name: text,
              password: z.string().min(16).max(256),
              role,
              dataScope: dataScopeInput.optional(),
            })
            .strict(),
          body,
        );
        item = await tx.user.create({
          data: {
            email: v.email.toLowerCase(),
            name: v.name,
            role: v.role,
            dataScope: v.dataScope,
            passwordHash: hashPassword(v.password),
          },
          select: safeUser,
        });
      } else throw new BadRequestException("不支持创建此资源");
      if (["rules", "sites"].includes(resource))
        await this.revision(tx, resource, item, actor);
      await this.audit(tx, actor, "CREATE", resource, item.id,resource==='tasks'?{template:item.template,templateVersion:item.templateVersion}:{});
      return item;
    });
  }
  validateSiteConfig(config: any) {
    for (const key of ["allowCidrs", "denyCidrs", "trustedProxyCidrs"])
      for (const entry of config[key] || []) {
        const [ip, bits, ...rest] = String(entry).split("/");
        const family = isIP(ip);
        const prefix = Number(bits);
        if (
          !family ||
          rest.length ||
          bits === undefined ||
          !/^\d+$/.test(bits) ||
          prefix < 0 ||
          prefix > (family === 4 ? 32 : 128)
        )
          throw new BadRequestException("CIDR 格式无效");
      }
    parse(
      z
        .object({
          nginxIngress:z.boolean().optional(),
          maxBodyBytes: z
            .number()
            .int()
            .min(1024)
            .max(8 * 1024 * 1024)
            .optional(),
          ratePerMinute: z.number().int().min(1).max(100000).optional(),
          pathRateLimits:z.array(z.object({path:z.string().startsWith("/").max(2000),ratePerMinute:z.number().int().min(1).max(100000)}).strict()).max(100).optional(),
          healthCheckPath:z.string().startsWith("/").max(2000).refine(x=>!x.startsWith("//")).optional(),
          allowCidrs: z.array(text).max(100).optional(),
          denyCidrs: z.array(text).max(100).optional(),
          allowedMethods: z.array(text).max(20).optional(),
          deniedPaths: z.array(text).max(100).optional(),
          trustedProxyCidrs: z.array(text).max(30).optional(),
          exceptions: z
            .array(
              z
                .object({
                  ruleId: text,
                  path: z.string().startsWith("/").max(2000),
                  param: text.optional(),
                })
                .strict(),
            )
            .max(100)
            .optional(),
        })
        .strict(),
      config,
    );
  }
  validateRule(v: any) {
    v=ruleWithBaseConfig(v);
    if(v.config?.ranges){try{for(const range of v.config.ranges)matchesOsvRange('0',range.events);}catch{throw new BadRequestException('版本范围事件无效或不受支持');}}
    if (v.intervalSeconds && v.kind !== "VULNERABILITY")
      throw new BadRequestException(
        "服务端调度仅用于漏洞规则；其他规则由 Agent 周期执行",
      );
    if(v.kind==='BASELINE'){
      const base=z.object({path:z.string().startsWith('/').max(4096),mode:z.enum(['0600','0640','0644']),type:z.literal('FILE_PERMISSION').optional()}).strict();
      const cfg=z.object({type:z.literal('CONFIG_VALUE'),path:z.string().startsWith('/').max(4096),key:text,value:z.string().max(4096)}).strict();
      const svc=z.object({type:z.literal('SERVICE_STATE'),service:z.string().regex(/^[a-zA-Z0-9_.@-]+$/),state:z.enum(['active','inactive','failed'])}).strict();
      parse(z.union([base,cfg,svc,databaseBaselineInput]),v.config);
    }
    else if (v.kind === "LOG")
      parse(z.union([databaseAccessInput,databaseActivityInput,databaseLogInput,z.object({contains:z.string().min(1).max(200),field:z.enum(["message","source"]).default("message"),threshold:z.number().int().min(1).max(1000).default(1),windowSeconds:z.number().int().min(1).max(86400).optional()}).strict()]),v.config);
    else if (v.kind === "FIM")
      parse(
        z.object({ path: z.string().startsWith("/").max(4096) }).strict(),
        v.config,
      );
    else
      parse(
        z
          .object({
            package: text,
            affectedVersion: text.optional(),
            ranges:z.array(z.object({type:z.literal('ECOSYSTEM'),events:z.array(z.object({introduced:text.optional(),fixed:text.optional(),last_affected:text.optional(),limit:text.optional()}).strict().refine(e=>Object.keys(e).length===1)).min(1).max(100)}).strict()).min(1).max(50).optional(),
            fixedVersion: text.optional(),
            ecosystem:text.optional(),
            advisory: text,
            os: text,
          })
          .strict().refine(c=>!!c.affectedVersion||!!c.ranges,'需要精确版本或明确受影响范围').refine(c=>!c.ranges||/^(Debian|Ubuntu)(:|$)/.test(c.ecosystem||''),'版本范围仅支持Debian/Ubuntu生态'),
        v.config,
      );
  }
  async patch(resource: string, id: string, body: unknown, actor: string) {
    const user=await this.db.user.findUnique({where:{email:actor}});
    await assertScope(this.db,user,resource,id);
    await assertLinks(this.db,user,body);
    if (['rules','sites'].includes(resource)) assertGlobal(user);
    if (resource==='assets' && restricted(user) && Object.hasOwn(body as object,'business')) {
      const v=body as any;
      if (!(user!.dataScope as any).assetIds?.includes(id) && !(user!.dataScope as any).businesses?.includes(v.business)) throw new BadRequestException('不能移出授权业务范围');
    }
    return this.db.$transaction(async (tx) => {
      let item: any;
      let findingPrevious: {status:string;owner:string|null;dueAt:Date|null}|undefined;
      if(resource==='assets'){
        const previous=await tx.asset.findUnique({where:{id}});const {sshAccess,...assetData}=parse(assetInput.partial(),body);item=await tx.asset.update({where:{id},data:assetOperatingSystemData(assetData,previous||undefined),select:safeAsset});if(sshAccess)await saveAssetRemoteAccess(tx,user,item,sshAccess);if(item.business)await tx.businessGroup.upsert({where:{name:item.business},create:{name:item.business},update:{}});await recordAssetChange(tx,id,previous,item,actor);
      }
      else if (resource === "findings") {
        const v = parse(
          z
            .object({
              status: text.optional(),
              owner: text.optional(),
              reason: z.string().max(4000).optional(),
              expiresAt: z.string().datetime().optional(),
              dueAt: z.string().datetime().nullable().optional(),
              expectedUpdatedAt: z.string().datetime().optional(),
            })
            .strict(),
          body,
        );
        const old = await tx.finding.findUnique({ where: { id } });
        if (!old) throw new NotFoundException();
        if(v.expectedUpdatedAt&&Date.parse(v.expectedUpdatedAt)!==old.updatedAt.getTime())throw new ConflictException('记录已更新，请刷新后重新处置');
        findingPrevious={status:old.status,owner:old.owner,dueAt:old.dueAt};
        if (v.status && v.status !== old.status)
          findingTransition(old.kind, old.status, v.status, v);
        const {expectedUpdatedAt,...data}=v;
        const changed = await tx.finding.updateMany({
          where: { id, updatedAt: old.updatedAt },
          data,
        });
        if (!changed.count) throw new ConflictException("记录已更新，请刷新");
        item = await tx.finding.findUnique({ where: { id } });
      } else if (resource === "incidents") {
        const v = parse(
          z
            .object({
              title: text.optional(),
              description: z.string().max(16000).optional(),
              owner: text.optional(),
              severity: severity.optional(),
              status: z
                .enum(["OPEN", "IN_PROGRESS", "VERIFYING", "CLOSED"])
                .optional(),
              conclusion: z.string().max(16000).optional(),
              verification: z.string().max(16000).optional(),
              findingIds: z.array(z.string().uuid()).max(100).optional(),
            })
            .strict(),
          body,
        );
        const old = await tx.incident.findUnique({ where: { id } });
        if (!old) throw new NotFoundException();
        const next: Record<string, string[]> = {
          OPEN: ["IN_PROGRESS"],
          IN_PROGRESS: ["VERIFYING"],
          VERIFYING: ["CLOSED", "IN_PROGRESS"],
          CLOSED: ["OPEN"],
        };
        if (
          v.status &&
          v.status !== old.status &&
          !next[old.status]?.includes(v.status)
        )
          throw new BadRequestException("非法事件状态转换");
        if (
          v.status === "CLOSED" &&
          (!(v.conclusion || old.conclusion)?.trim() ||
            !(v.verification || old.verification)?.trim())
        )
          throw new BadRequestException("结案需要结论和验证证据");
        const { findingIds, ...data } = v;
        if (findingIds) {
          if (
            (await tx.finding.count({ where: { id: { in: findingIds } } })) !==
            new Set(findingIds).size
          )
            throw new BadRequestException("关联问题不存在");
          await tx.incidentFinding.deleteMany({ where: { incidentId: id } });
          await tx.incidentFinding.createMany({
            data: [...new Set(findingIds)].map((findingId) => ({
              incidentId: id,
              findingId,
            })),
          });
        }
        const change = await tx.incident.updateMany({
          where: { id, updatedAt: old.updatedAt },
          data,
        });
        if (!change.count) throw new ConflictException("事件已更新，请刷新");
        item = this.incidentShape(
          await tx.incident.findUnique({
            where: { id },
            include: { links: true },
          }),
        );
      } else if (resource === "rules") {
        const v = parse(ruleInput.partial(), body);
        const old = await tx.rule.findUnique({ where: { id } });
        if (!old) throw new NotFoundException();
        this.validateRule({ ...old, ...v });
        const binding=(v.config||old.config) as {instanceId?:string};if(binding.instanceId){const instance=await assertInstanceScope(tx,{role:user?.role||"VIEWER",dataScope:parse(dataScopeInput,user?.dataScope||{})},binding.instanceId);if(instance.archivedAt)throw new BadRequestException("数据库实例已归档");assertDatabaseRuleEngine(instance.engine,(v.config||old.config) as Record<string,unknown>);}
        item = await tx.rule.update({
          where: { id },
          data: {
            ...v,
            config: v.config as any,
            ...(v.intervalSeconds !== undefined
              ? {
                  nextRunAt: v.intervalSeconds
                    ? new Date(Date.now() + v.intervalSeconds * 1000)
                    : null,
                }
              : {}),
            version: { increment: 1 },
          },
        });
      } else if (resource === "sites") {
        const v = parse(siteInput.partial(), body);
        await tx.$queryRaw`SELECT id FROM "Site" WHERE id=${id} FOR UPDATE`;
        const currentSite=await tx.site.findUniqueOrThrow({where:{id}});
        if(v.mode==='BLOCK'&&currentSite.mode==='OBSERVE'&&currentSite.ruleDeploymentId){
          const deployment=await tx.wafRuleDeployment.findUniqueOrThrow({where:{id:currentSite.ruleDeploymentId}});
          if(!validateStoredWafEnvelope(deployment.envelope).builtin)throw new BadRequestException('外部规则需要在发布记录中确认节点生效后切换阻断');
        }
        if (v.config) this.validateSiteConfig(v.config || {});
        item = await tx.site.update({
          where: { id },
          data: { ...v, config: v.config as any, version: { increment: 1 } },
        });
        item=await rebindSiteRuleDeployment(tx,item,actor);
      } else if (resource === "users") {
        const v = parse(
          z
            .object({
              name: text.optional(),
              role: role.optional(),
              disabled: z.boolean().optional(),
              dataScope: dataScopeInput.optional(),
              password: z.string().min(16).max(256).optional(),
            })
            .strict(),
          body,
        );
        const old = await tx.user.findUnique({ where: { id } });
        if (!old) throw new NotFoundException();
        if (
          old.email === actor &&
          (v.disabled || (v.role && v.role !== "ADMIN"))
        )
          throw new BadRequestException("不能撤销自身管理权限");
        const { password, ...data } = v;
        item = await tx.user.update({
          where: { id },
          data: {
            ...data,
            ...(password ? { passwordHash: hashPassword(password) } : {}),
          },
          select: safeUser,
        });
        if (password || v.disabled || v.role)
          await tx.session.deleteMany({ where: { userId: id } });
      } else throw new BadRequestException("不支持修改此资源");
      if (["rules", "sites"].includes(resource))
        await this.revision(tx, resource, item, actor);
      await this.audit(tx, actor, "UPDATE", resource, id, {
        fields: Object.keys(body as object),
        ...(resource === "findings"
          ? { status: item.status, reason: item.reason, owner:item.owner, dueAt:item.dueAt?.toISOString()??null, previous:findingPrevious?{status:findingPrevious.status,owner:findingPrevious.owner,dueAt:findingPrevious.dueAt?.toISOString()??null}:null }
          : {}),
      });
      return item;
    });
  }
  async ingest(tx: Tx, raw: unknown, forcedAsset?: string, trustedRuleConfig?:unknown) {
    const v = parse(findingInput, raw);
    const securityDomain=findingSecurityDomain(v.source,trustedRuleConfig);
    const assetId = forcedAsset || v.assetId;
    if (
      assetId &&
      !(await tx.asset.findUnique({
        where: { id: assetId },
        select: { id: true },
      }))
    )
      throw new BadRequestException("资产不存在");
    const dedupKey = hashToken(
      JSON.stringify([v.source, v.externalId, assetId || "", v.kind, ...(v.instanceId?[v.instanceId]:[])]),
    );
    // Serialize same-finding ingestion across concurrent heartbeats/imports.
    await tx.$queryRaw`SELECT pg_advisory_xact_lock(hashtext(${dedupKey}))::text`;
    const old = await tx.finding.findUnique({ where: { dedupKey } });
    if (!old) return tx.finding.create({ data: { ...v, assetId, dedupKey, securityDomain } });
    const reopen =
      ["CLOSED", "RESOLVED"].includes(old.status) ||
      (old.status === "ACCEPTED" &&
        old.expiresAt &&
        old.expiresAt < new Date());
    return tx.finding.update({
      where: { id: old.id },
      data: {
        securityDomain:old.securityDomain==='UNCLASSIFIED'?securityDomain:old.securityDomain,
        title: v.title,
        severity: v.severity,
        evidence: v.evidence,
        occurrences: { increment: 1 },
        ...(reopen ? { status: "OPEN" } : {}),
      },
    });
  }
  async import(body: unknown, actor: string) {
    const user=await this.db.user.findUnique({where:{email:actor}});
    assertEvidence(user);
    const v = parse(
      z.object({ items: z.array(findingInput).min(1).max(100) }).strict(),
      body,
    );
    for (const item of v.items) { await assertLinks(this.db,user,item); if(restricted(user)&&!item.assetId&&!item.instanceId)throw new BadRequestException("导入需要授权资产"); }
    return this.db.$transaction(
      async (tx) => {
        const items = [];
        for (const i of v.items) items.push(await this.ingest(tx, i));
        await this.audit(tx, actor, "IMPORT", "findings", undefined, {
          count: items.length,
        });
        return { items, total: items.length };
      },
      { timeout: 15000 },
    );
  }
  async taskAction(id: string, action: string, body: unknown, actor: string) {
    const user=await this.db.user.findUnique({where:{email:actor}});
    await assertScope(this.db,user,"tasks",id);
    return this.db.$transaction(async (tx) => {
      const old = await tx.task.findUnique({ where: { id } });
      if (!old) throw new NotFoundException();
      let data: any;
      if (action === "approve") {
        await assertTaskApproval(tx,old,actor);
        if (old.expiresAt < new Date())
          throw new ConflictException("任务已过期");
        data = {
          status: taskTransition(old.status, "approve"),
          approvedBy: actor,
        };
      } else if (action === "reject") {
        await assertTaskApproval(tx,old,actor);
        const v = parse(z.object({ reason: text }).strict(), body);
        data = {
          status: taskTransition(old.status, "reject"),
          reason: v.reason,
        };
      } else if (action === "verify") {
        const v = parse(
          z
            .object({
              resolved: z.boolean(),
              evidence: z.string().trim().min(5).max(16000),
            })
            .strict(),
          body,
        );
        data = {
          status: taskTransition(
            old.status,
            v.resolved ? "verify" : "failVerification",
          ),
          verification: { ...v, actor, at: new Date().toISOString() },
          completedAt: new Date(),
        };
        if(!v.resolved)await stopFailedBatch(tx,old.batchId);
        if (v.resolved && old.findingId)
          await tx.finding.update({
            where: { id: old.findingId },
            data: { status: "CLOSED", reason: v.evidence },
          });
      } else throw new NotFoundException();
      const change = await tx.task.updateMany({
        where: { id, status: old.status },
        data,
      });
      if (!change.count) throw new ConflictException("任务已更新");
      await this.audit(tx, actor, action.toUpperCase(), "tasks", id, {
        from: old.status,
        to: data.status,
      });
      return tx.task.findUnique({ where: { id } });
    });
  }
  async revision(tx: Tx, resource: string, item: any, actor: string) {
    const keys =
      resource === "rules"
        ? ["name", "kind", "severity", "enabled", "config", "intervalSeconds"]
        : ["name", "hostname", "upstream", "mode", "enabled", "config"];
    const snapshot = Object.fromEntries(keys.map((k) => [k, item[k]]));
    await tx.revision.create({
      data: {
        resource,
        resourceId: item.id,
        version: item.version,
        snapshot,
        actor,
      },
    });
  }
  async versions(resource: string, id: string, user?:any) {
    if (!["rules", "sites"].includes(resource)) throw new NotFoundException();
    await this.get(resource, id, user);
    return {
      items: await this.db.revision.findMany({
        where: { resource, resourceId: id },
        orderBy: { version: "desc" },
        take: 100,
      }),
    };
  }
  async restore(resource: string, id: string, body: unknown, actor: string) {
    if (!["rules", "sites"].includes(resource)) throw new NotFoundException();
    const v = parse(
      z.object({ version: z.number().int().min(1) }).strict(),
      body,
    );
    const revision = await this.db.revision.findUnique({
      where: {
        resource_resourceId_version: {
          resource,
          resourceId: id,
          version: v.version,
        },
      },
    });
    if (!revision) throw new NotFoundException("历史版本不存在");
    const snapshot =
      resource === "rules"
        ? {
            ...(revision.snapshot as any),
            intervalSeconds: (revision.snapshot as any).intervalSeconds ?? null,
          }
        : revision.snapshot;
    return this.patch(resource, id, snapshot, actor);
  }
  async runRule(id: string, body: unknown, actor: string) {
    const user=await this.db.user.findUnique({where:{email:actor}});
    const v = parse(
      z.object({ assetId: z.string().uuid().optional() }).strict(),
      body,
    );
    await assertLinks(this.db,user,v);
    const rule = await this.db.rule.findUnique({ where: { id } });
    if (!rule || !rule.enabled)
      throw new BadRequestException("规则不存在或已停用");
    if (rule.kind !== "VULNERABILITY")
      throw new BadRequestException(
        "此规则由 Agent 下次采集时执行；服务端无法直接读取主机文件",
      );
    const startedAt=new Date();let cursor:string|undefined,total=0;const items:any[]=[];
    for(;;){
      const assets=await this.db.asset.findMany({where:{AND:[assetScope(user)],...(v.assetId?{id:v.assetId}:cursor?{id:{gt:cursor}}:{}),createdAt:{lte:startedAt}},orderBy:{id:'asc'},take:100});
      if(!assets.length)break;
      await this.db.$transaction(async tx=>{
        for(const asset of assets){
          const result=evaluateVulnerability(rule.config,asset);
          const evaluation=await tx.evaluation.create({data:{ruleId:rule.id,ruleName:rule.name,kind:rule.kind,assetId:asset.id,...result}});
          if(items.length<100)items.push(evaluation);
          if(result.matched)await this.ingest(tx,{externalId:rule.id+':'+(rule.config as any).package,title:rule.name,kind:'RISK',severity:rule.severity,source:'vulnerability',evidence:result.evidence},asset.id);
        }
      },{timeout:30000});
      total+=assets.length;cursor=assets[assets.length-1].id;
      if(v.assetId)break;
    }
    if(!total)throw new BadRequestException('没有可检测资产');
    await this.audit(this.db,actor,'RUN','rules',id,{assets:total,startedAt:startedAt.toISOString()});
    return {items,total,returnedItems:items.length,resultsTruncated:total>items.length};
  }
  async overview(user?: any) {
    const assetsWhere=await resourceWhere(this.db,user,'assets');
    const findingsWhere=await resourceWhere(this.db,user,'findings');
    const tasksWhere=await resourceWhere(this.db,user,'tasks');
    const incidentsWhere=await resourceWhere(this.db,user,'incidents');
    const wafWhere=await resourceWhere(this.db,user,'waf-events');
    const [
      assets,
      risks,
      alerts,
      incidents,
      pendingTasks,
      criticalRisks,
      recent,
      wafRequests,
      wafBlocked,
      trafficNodes,
    ] = await Promise.all([
      this.db.asset.count({where:assetsWhere}),
      this.db.finding.count({
        where: {
          ...findingsWhere,
          kind: "RISK",
          status: { notIn: ["CLOSED", "FALSE_POSITIVE"] },
        },
      }),
      this.db.finding.count({
        where: {
          ...findingsWhere,
          kind: "ALERT",
          status: { notIn: ["RESOLVED", "FALSE_POSITIVE"] },
        },
      }),
      this.db.incident.count({ where: { ...incidentsWhere, status: { not: "CLOSED" } } }),
      this.db.task.count({
        where: {
          ...tasksWhere,
          status: {
            in: ["PENDING", "APPROVED", "RUNNING", "VERIFYING", "UNKNOWN"],
          },
        },
      }),
      this.db.finding.count({
        where: {
          ...findingsWhere,
          kind: "RISK",
          severity: "CRITICAL",
          status: { notIn: ["CLOSED", "FALSE_POSITIVE"] },
        },
      }),
      this.db.finding.findMany({ where:findingsWhere, take: 8, orderBy: { updatedAt: "desc" } }),
      this.db.wafEvent.count({where:wafWhere}),
      this.db.wafEvent.count({ where: { ...wafWhere, action: "BLOCK" } }),
      this.db.wafNode.findMany({where:{AND:[await resourceWhere(this.db,user,'waf-nodes'),{lastSeen:{gte:new Date(Date.now()-90000)}}]},select:{id:true,startedAt:true,stats:true}}),
    ]);
    return {
      assets,
      risks,
      alerts,
      incidents,
      pendingTasks,
      criticalRisks,
      recent,
      wafEvents: wafRequests,
      wafBlocked,
      wafTraffic:{nodes:trafficNodes.length,...Object.fromEntries(['totalRequests','blockedRequests','observedRequests','upstreamErrors'].map(key=>[key,trafficNodes.reduce((sum,node)=>sum+Number((node.stats as any)?.[key]||0),0)])),basis:'最近90秒有心跳节点的当前进程累计计数；节点重启重置，不是时间段全站流量或历史去重访问量'},
      updatedAt: new Date().toISOString(),
    };
  }
}
