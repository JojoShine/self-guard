import {
  Body, Controller, Get, Post, Patch, Param, Req, UseGuards, Inject,
  BadRequestException, ConflictException, NotFoundException,
} from "@nestjs/common";
import { Prisma } from "@prisma/client";
import { lookup as dnsLookup } from "node:dns";
import { request as httpsRequest, RequestOptions } from "node:https";
import { BlockList, isIP } from "node:net";
import { IncomingMessage, ClientRequest } from "node:http";
import { z } from "zod";
import { isDeepStrictEqual } from "node:util";
import { Db } from "./db";
import { AuthGuard, allow } from "./auth";
import { parse, text } from "./validation";
import { hashToken } from "./security";
import { matchesOsvRange, OsvRangeEvent } from "./versions";

const forbidden = new BlockList();
for (const [ip, bits] of [
  ["0.0.0.0", 8], ["10.0.0.0", 8], ["100.64.0.0", 10], ["127.0.0.0", 8],
  ["169.254.0.0", 16], ["172.16.0.0", 12], ["192.0.0.0", 24], ["192.0.2.0", 24],
  ["192.168.0.0", 16], ["198.18.0.0", 15], ["198.51.100.0", 24], ["203.0.113.0", 24],
  ["224.0.0.0", 4], ["240.0.0.0", 4],
] as const) forbidden.addSubnet(ip, bits, "ipv4");
forbidden.addSubnet("2001::", 23, "ipv6");
forbidden.addSubnet("2001:db8::", 32, "ipv6");
forbidden.addSubnet("2002::", 16, "ipv6");
const globalV6 = new BlockList();
globalV6.addSubnet("2000::", 3, "ipv6");
export function publicAddress(address: string) {
  const family = isIP(address);
  if (family === 4) return !forbidden.check(address, "ipv4");
  if (family === 6) return globalV6.check(address, "ipv6") && !forbidden.check(address, "ipv6");
  return false;
}
export function advisoryUrl(value: string, allowedHosts = process.env.ADVISORY_ALLOWED_HOSTS || "") {
  let url: URL;
  try { url = new URL(value); } catch { throw new BadRequestException("数据源 URL 无效"); }
  const hosts = ["api.osv.dev", ...allowedHosts.split(",").map(host => host.trim().toLowerCase()).filter(Boolean)];
  if (url.protocol !== "https:" || url.username || url.password || url.hash || url.search ||
      (url.port && url.port !== "443") || !hosts.includes(url.hostname) || isIP(url.hostname) || url.hostname.startsWith("["))
    throw new BadRequestException("仅允许官方 OSV HTTPS 地址或管理员明确允许的域名，禁止认证信息、查询参数和自定义端口");
  if (url.hostname === "api.osv.dev" && !/^\/v1\/vulns\/[a-zA-Z0-9._-]+$/.test(url.pathname))
    throw new BadRequestException("官方 OSV 地址必须为 /v1/vulns/<漏洞编号>");
  if (url.href.length > 500) throw new BadRequestException("数据源地址最多 500 字符");
  return url;
}
type Transport = (url: URL, options: RequestOptions, callback: (response: IncomingMessage) => void) => ClientRequest;
type FetchDependencies = { request?: Transport; lookup?: typeof dnsLookup };
export async function fetchAdvisory(value: string, dependencies: FetchDependencies = {}): Promise<unknown> {
  const url = advisoryUrl(value);
  const request = dependencies.request || httpsRequest;
  const resolve = dependencies.lookup || dnsLookup;
  return new Promise((done, fail) => {
    let settled = false;
    let req: ClientRequest;
    const finish = (error?: Error, result?: unknown) => {
      if (settled) return;
      settled = true; clearTimeout(timer);
      if (error) { req?.destroy(); fail(error); } else done(result);
    };
    const timer = setTimeout(() => finish(new Error("数据源请求超时（10 秒）")), 10000);
    timer.unref();
    const lookup: any = (hostname: string, options: any, callback: any) => {
      resolve(hostname, { all: true, verbatim: true }, (error, addresses) => {
        if (error) return callback(error);
        if (!addresses.length || addresses.some(entry => !publicAddress(entry.address)))
          return callback(new Error("数据源 DNS 指向非公开网络地址，已拒绝连接"));
        // Return only the validated records to the socket; no second resolution is performed.
        return options?.all ? callback(null, addresses) : callback(null, addresses[0].address, addresses[0].family);
      });
    };
    try {
      req = request(url, {
        method: "GET", agent: false, lookup, rejectUnauthorized: true,
        maxHeaderSize: 16384, headers: { Accept: "application/json", "User-Agent": "SelfGuard-Advisory/1.0" },
      }, response => {
        const status = response.statusCode || 0;
        if (status >= 300 && status < 400) { response.resume(); return finish(new Error("数据源重定向已拒绝")); }
        if (status !== 200) { response.resume(); return finish(new Error(`数据源 HTTP 状态 ${status}`)); }
        const chunks: Buffer[] = [];
        let bytes = 0;
        response.on("data", chunk => {
          bytes += Buffer.byteLength(chunk);
          if (bytes > 2 * 1024 * 1024) { finish(new Error("数据源响应超过 2 MiB 上限")); response.destroy(); return; }
          chunks.push(Buffer.from(chunk));
        });
        response.on("aborted", () => finish(new Error("数据源响应中断")));
        response.on("error", error => finish(error));
        response.on("end", () => {
          try { finish(undefined, JSON.parse(Buffer.concat(chunks).toString("utf8"))); }
          catch { finish(new Error("数据源响应不是有效 JSON")); }
        });
      });
      req.on("error", error => finish(error));
      req.end();
    } catch (error) { finish(error as Error); }
  });
}
const osvInput = z.object({
  id: z.string().min(1).max(200), withdrawn: z.string().datetime().optional(),
  database_specific: z.object({ severity: z.string().max(100).optional() }).optional(),
  affected: z.array(z.object({
    package: z.object({ name: text, ecosystem: text }),
    versions: z.array(text).max(10000).default([]),
    ranges: z.array(z.unknown()).max(10000).default([]),
    database_specific: z.object({ severity: z.string().max(100).optional() }).optional(),
  })).max(1000).default([]),
});
type OsvRange = { type: "ECOSYSTEM"; events: OsvRangeEvent[] };
type AdvisoryRuleConfig = {
  os: string; ecosystem: string; package: string; advisory: string;
  affectedVersion?: string; ranges?: OsvRange[];
};
const ecosystemRangeInput = z.object({
  type: z.literal("ECOSYSTEM"),
  events: z.array(z.object({ introduced: text.optional(), fixed: text.optional(), last_affected: text.optional(), limit: text.optional() }).strict()).min(1).max(100),
});
export function normalizeOsv(raw: unknown, url: string, sourceId: string) {
  const document = parse(osvInput, raw);
  const rules: Array<{ name: string; kind: string; severity: string; config: AdvisoryRuleConfig }> = [];
  let skippedRanges = 0, skippedEntries = 0;
  const skippedEcosystems = new Set<string>();
  const names = new Set<string>();
  const rangeGroups = new Map<string, { config: AdvisoryRuleConfig; severity: string }>();
  function addRule(config: AdvisoryRuleConfig, label: string, identity: string, severity: string) {
    const key = hashToken(JSON.stringify([document.id, config.ecosystem, config.package, identity])).slice(0, 16);
    const name = `${document.id} · ${config.package} ${label}`.slice(0, 410) + ` [osv-source:${sourceId}:${key}]`;
    if (names.has(name)) return;
    names.add(name); rules.push({ name, kind: "VULNERABILITY", severity, config });
    if (rules.length > 1000) throw new BadRequestException("数据源包含超过 1000 个检测规则，请缩小单条数据源范围");
  }
  if (!document.withdrawn) for (const affected of document.affected) {
    if (!/^(Debian|Ubuntu|Alpine)(:|$)/.test(affected.package.ecosystem)) {
      skippedRanges += affected.ranges.length;
      skippedEcosystems.add(affected.package.ecosystem); skippedEntries++; continue;
    }
    const level = (affected.database_specific?.severity || document.database_specific?.severity || "INFO").toUpperCase();
    const severity = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"].includes(level) ? level : "INFO";
    const config = { os: "linux", ecosystem: affected.package.ecosystem, package: affected.package.name, advisory: url };
    for (const version of affected.versions) addRule({ ...config, affectedVersion: version }, `= ${version}`, version, severity);
    const ranges: OsvRange[] = [];
    for (const rawRange of affected.ranges) {
      if (!/^(Debian|Ubuntu)(:|$)/.test(config.ecosystem) || !rawRange || typeof rawRange !== "object" || (rawRange as any).type !== "ECOSYSTEM") { skippedRanges++; continue; }
      const range = parse(ecosystemRangeInput, rawRange);
      // Validate every bound using the same Debian/OSV semantics as evaluation; do not expand versions.
      try { matchesOsvRange("0", range.events); }
      catch (error) { throw new BadRequestException(`OSV 范围无效：${(error as Error).message}`); }
      ranges.push(range);
    }
    if (!affected.versions.length && !ranges.length) skippedEntries++;
    if (ranges.length) {
      const groupKey = JSON.stringify([config.ecosystem, config.package]);
      const group = rangeGroups.get(groupKey);
      if (group) group.config.ranges!.push(...ranges);
      else rangeGroups.set(groupKey, { config: { ...config, ranges }, severity });
      if (rangeGroups.get(groupKey)!.config.ranges!.length > 50) throw new BadRequestException("单个软件包最多支持 50 个版本范围");
    }
  }
  for (const group of rangeGroups.values()) addRule(group.config, "· 受影响版本范围", "ECOSYSTEM_RANGES", group.severity);
  return { rules, skippedRanges, skippedEntries, skippedEcosystems: [...skippedEcosystems], withdrawn: !!document.withdrawn,
    exactVersionRules: rules.filter(rule => rule.config.affectedVersion !== undefined).length,
    rangeRules: rules.filter(rule => rule.config.ranges !== undefined).length,
  };
}
async function revision(tx: Prisma.TransactionClient, rule: any, actor: string) {
  await tx.revision.create({ data: { resource: "rules", resourceId: rule.id, version: rule.version, actor, snapshot: { name: rule.name, kind: rule.kind, severity: rule.severity, enabled: rule.enabled, config: rule.config, intervalSeconds: rule.intervalSeconds } } });
}
export async function syncAdvisory(db: Db, id: string, actor: string, fetcher = fetchAdvisory) {
  const source = await db.advisorySource.findUnique({ where: { id } });
  if (!source) throw new NotFoundException("数据源不存在");
  if (!source.enabled) throw new ConflictException("数据源已停用");
  advisoryUrl(source.url);
  const claimed = await db.advisorySource.updateMany({ where: { id, updatedAt: source.updatedAt, enabled: true, OR: [{ status: { not: "SYNCING" } }, { updatedAt: { lt: new Date(Date.now() - 120000) } }] }, data: { status: "SYNCING", error: null } });
  if (!claimed.count) throw new ConflictException("数据源正在同步，请稍后刷新");
  try {
    const normalized = normalizeOsv(await fetcher(source.url), source.url, source.id);
    const summary = { imported: normalized.rules.length, skippedRanges: normalized.skippedRanges, skippedEntries: normalized.skippedEntries, skippedEcosystems: normalized.skippedEcosystems, withdrawn: normalized.withdrawn, exactVersionRules: normalized.exactVersionRules, rangeRules: normalized.rangeRules, coverage: "EXACT_VERSIONS_AND_DEBIAN_RANGES", severityFallback: "INFO" };
    return await db.$transaction(async tx => {
      const oldRules = await tx.rule.findMany({ where: { kind: "VULNERABILITY", name: { contains: `[osv-source:${id}:` } } });
      const currentNames = new Set(normalized.rules.map(rule => rule.name));
      for (const old of oldRules) if (old.enabled && !currentNames.has(old.name)) {
        const disabled = await tx.rule.update({ where: { id: old.id }, data: { enabled: false, version: { increment: 1 } } });
        await revision(tx, disabled, actor);
      }
      for (const rule of normalized.rules) {
        const old = oldRules.find(item => item.name === rule.name);
        if (old && old.enabled && old.severity === rule.severity && isDeepStrictEqual(old.config, rule.config)) continue;
        const item = old
          ? await tx.rule.update({ where: { id: old.id }, data: { ...rule, enabled: true, version: { increment: 1 } } })
          : await tx.rule.create({ data: { ...rule, enabled: true } });
        await revision(tx, item, actor);
      }
      const status = !normalized.withdrawn && (normalized.skippedRanges || normalized.skippedEntries || !normalized.rules.length) ? "PARTIAL" : "SUCCEEDED";
      const saved = await tx.advisorySource.update({ where: { id }, data: { status, error: null, lastSyncAt: new Date() } });
      await tx.audit.create({ data: { actor, action: "SYNC", resource: "advisory-sources", resourceId: id, detail: summary } });
      return { source: saved, summary };
    }, { timeout: 30000 });
  } catch (error) {
    const message = error instanceof Error ? error.message.slice(0, 2000) : "数据源同步失败";
    const saved = await db.$transaction(async tx => {
      const failed = await tx.advisorySource.update({ where: { id }, data: { status: "FAILED", error: message } });
      await tx.audit.create({ data: { actor, action: "SYNC_FAILED", resource: "advisory-sources", resourceId: id, detail: { error: message } } });
      return failed;
    });
    return { source: saved, summary: null };
  }
}
const sourceInput = z.object({ name: text, url: z.string().min(1).max(500), format: z.literal("OSV").default("OSV"), enabled: z.boolean().default(true) }).strict();
@Controller("advisories")
@UseGuards(AuthGuard)
export class AdvisoriesController {
  constructor(@Inject(Db) private db: Db) {}
  @Get("sources")
  async sources() {
    const items = await this.db.advisorySource.findMany({ orderBy: { createdAt: "desc" }, take: 100 });
    const summaries = await this.db.audit.findMany({ where: { resource: "advisory-sources", action: "SYNC", resourceId: { in: items.map(item => item.id) } }, orderBy: { createdAt: "desc" }, take: 1000 });
    return { items: items.map(item => ({ ...item, lastResult: summaries.find(summary => summary.resourceId === item.id)?.detail || null })), limit: 100 };
  }
  @Post("sources")
  async create(@Req() req: any, @Body() body: unknown) {
    allow(req, ["ADMIN", "ANALYST"]);
    const v = parse(sourceInput, body); v.url = advisoryUrl(v.url).href;
    return this.db.$transaction(async tx => {
      const source = await tx.advisorySource.create({ data: v });
      await tx.audit.create({ data: { actor: req.user.email, action: "CREATE", resource: "advisory-sources", resourceId: source.id } });
      return source;
    });
  }
  @Patch("sources/:id")
  async patch(@Req() req: any, @Param("id") id: string, @Body() body: unknown) {
    allow(req, ["ADMIN", "ANALYST"]);
    const v = parse(sourceInput.partial(), body);
    if (v.url) v.url = advisoryUrl(v.url).href;
    return this.db.$transaction(async tx => {
      const source = await tx.advisorySource.findUnique({ where: { id } });
      if (!source) throw new NotFoundException("数据源不存在");
      if (source.status === "SYNCING" && source.updatedAt > new Date(Date.now() - 120000)) throw new ConflictException("同步期间不能修改数据源");
      const changed = await tx.advisorySource.updateMany({ where: { id, updatedAt: source.updatedAt }, data: { ...v, ...(v.url && v.url !== source.url ? { status: "IDLE", error: null, lastSyncAt: null } : source.status === "SYNCING" ? { status: "IDLE" } : {}) } });
      if (!changed.count) throw new ConflictException("数据源已变化，请刷新后重试");
      const item = await tx.advisorySource.findUniqueOrThrow({ where: { id } });
      if (v.enabled === false || (v.url && v.url !== source.url)) {
        const rules = await tx.rule.findMany({ where: { enabled: true, name: { contains: `[osv-source:${id}:` }, kind: "VULNERABILITY" } });
        for (const rule of rules) { const disabled = await tx.rule.update({ where: { id: rule.id }, data: { enabled: false, version: { increment: 1 } } }); await revision(tx, disabled, req.user.email); }
      }
      await tx.audit.create({ data: { actor: req.user.email, action: "UPDATE", resource: "advisory-sources", resourceId: id, detail: { fields: Object.keys(v) } } });
      return item;
    });
  }
  @Post("sources/:id/sync")
  async sync(@Req() req: any, @Param("id") id: string) {
    allow(req, ["ADMIN", "ANALYST"]);
    return syncAdvisory(this.db, id, req.user.email);
  }
}
