# 风险与告警领域归属基础 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans. 当前会话原生执行，保留已有修改，不提交或推送。

**Goal:** 将发现的主安全领域持久化，并支持有权限的数据内按领域查询，不把未知旧记录默认归类。

**Architecture:** 在现有 Finding 增加 NETWORK/DATA/UNCLASSIFIED 领域，入库按明确来源和服务端已验证规则配置分类。查询复用现有资产/实例权限；调查在发现汇总中按关联发现的领域参与筛选。此阶段不创建领域专属角色，也不提前迁移菜单。

**Tech Stack:** NestJS、Prisma/PostgreSQL、Zod、现有 TypeScript 测试。

**Spec:** [业务规划](../../网络安全与数据安全业务重构规划评审稿.md)第3/4/15节；[P0记录](../../安全观测P0验证记录.md)。领域归属不依赖尚未验收的探针，可独立推进；不标记 P0 已全部完成。

## Global Constraints

- 未知来源保留 UNCLASSIFIED，不能把日志、数据库主机或 instanceId 一律视为某个安全领域。
- 数据组件漏洞主归属 NETWORK，数据库操作/鉴权检测主归属 DATA。
- 保留旧输入契约、去重键、状态与既有资产/实例授权。不信任客户端直接声明领域或 JSON 中自报规则类型。
- 仅在隔离测试库验证迁移，不迁移生产数据库；部署前仍需先应用迁移再启动新版服务。
- 本阶段只是归属和查询过滤，领域权限授权、菜单、统计/报告统一过滤在后续任务完成，不能宣称已实现领域权限隔离。

## Review Focus

- 同一发现重放不丢状态/次数，已知领域不能被旧客户端降级为未知。
- 来源是漏洞且关联实例仍属网络；不通过标题/自由文本猜领域。
- 无法识别旧日志不丢失；迁移保留主键、关联与去重键。
- 领域筛选须与现有权限取交集，列表和数量一致。
- 跨域调查按关联领域参与过滤，不复制调查或更改所有权。

### Task 1：领域分类契约

Files: 新增 `apps/api/src/security-domain.ts`、`apps/api/test/security-domain.test.ts`。

Interface: `securityDomainInput` 为严格枚举；`findingSecurityDomain(source: string, trustedRuleConfig?: unknown)` 返回领域。只将固定来源 vulnerability/active-scan/agent-fim 分类 NETWORK，database-security 分类 DATA；已验证服务端数据库规则类型可分类 DATA；其他未知。

- [x] 先测试明确来源、实例漏洞、未知日志、伪造证据不参与归类和数据库规则类型；观察失败后实现，运行定向测试通过。

### Task 2：持久化与安全迁移

Files: 修改 `apps/api/prisma/schema.prisma`；新增 `20261105120000_finding_security_domain/migration.sql`。

- [x] 添加枚举和 Finding.securityDomain 默认 UNCLASSIFIED，增加领域/创建时间索引；仅按明确来源回填，保留其他记录。
- [x] 在独立临时数据库执行全部迁移和旧记录回填测试；确认无数据/关联丢失；生成客户端并构建 API。

### Task 3：归属写入与重放

Files: 修改 `apps/api/src/platform.ts`、`apps/api/src/components.ts`；在新定向测试/隔离测试覆盖入库。

- [x] Platform.ingest 增加仅服务端使用的可选可信规则配置上下文；Agent 心跳复用其已加载并校验过的规则，不从证据自由字段取类型。
- [x] 新记录持久化领域；旧记录重放时只用明确领域提升未知，不将明确归属降级；不改去重键和状态流程。
- [x] 测试创建、重放、未知来源与客户端无法提交领域字段，运行已有相关回归。

### Task 4：列表及发现汇总领域筛选

Files: 修改 `apps/api/src/validation.ts`、`apps/api/src/platform.ts`、`apps/api/src/scope.ts`；新增隔离验证 `apps/api/test/security-domain-db.cjs`。调查授权复用发现的完整资产/实例条件，禁止只看主机可见性后聚合私有实例领域。

- [x] pageInput 新增可选 securityDomain；发现列表以已有授权 where 叠加该条件；不支持的列表明确拒绝该过滤，不悄悄忽略。
- [x] discoveries 汇总加入发现单领域和调查关联领域集合，按任一关联领域过滤；不改变全量旧查询语义。
- [x] 验证 NETWORK/DATA/UNCLASSIFIED、未知枚举、分页/数量、混合调查及受限用户不见越权发现。

### Task 5：验证与交付记录

- [x] 跑新定向单测、既有分类/审计/权限回归、API 构建、隔离数据库迁移与查询；清理本轮测试环境。
- [x] 独立复核本次改动，修正重要问题，更新实施记录，明确未部署和领域权限仍待完成。

## 执行记录

2026-11-05：领域分类/持久化/迁移/查询已实现，3项新增单测、24项定向回归、API构建通过；独立临时库迁移及入库/重放/分页/权限测试通过。复核发现调查只按主机授权导致领域派生信息暴露，先以真实库回归复现，再让调查复用发现授权修复；修复后同一回归通过。完整API独立库回归结果见[实施记录](../../安全分域基础实施记录.md)，不以定向通过代替整仓全绿。未部署、未迁移生产库、未改菜单或发行新Agent。
