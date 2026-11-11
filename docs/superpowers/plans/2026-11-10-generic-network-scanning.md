# Generic Network Scanning Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:executing-plans and superpowers:dispatching-parallel-agents for independent domains below.

**Goal:** 用通用规则库、实际引擎和目标为中心的流程扩大网络安全检测，停止按品牌堆功能。
**Architecture:** 保留系统/应用漏洞匹配；完整官方模板目录+明确能力筛选；现有HTTP范围控制请求、Nuclei原生离线响应判断；批准版本冻结及统一结果处置。
**Tech Stack:** Existing NestJS/Prisma/React/Go scanner; pinned official Nuclei executable, no added frontend framework.
**Spec:** docs/superpowers/specs/2026-11-10-generic-network-scanning-design.md

## Global constraints
不重启远端PG、不启用SQL、不升级原collector、不扫未批准业务入口。三个独立实现域允许并行，修改范围不重叠。现有脏改动保留；先失败回归再修改产品代码。

- [x] A 原生响应执行：定义严格native模板能力与JSON契约，Go受控传输后原生离线判断，原生编译校验接口，进程限额/原件摘要/负例/不出网及部署依赖验证。负责services/scanner、scan-worker.ts、scan-template-worker.ts、nuclei-native.ts、原生执行专属测试。
- [x] B 通用规则库：完整官方快照与来源摘要、预算化读取、分类/CVE/兼容索引、分页检索及单次同步、显式批量编译和批准；不自动发起扫描/扩大范围。负责probe-rule-library*.ts、专属Prisma模型迁移如确需、scripts/sync-probe-library.cjs、专属测试。依赖A导出inspectNativeProbe(raw)、validateNativeProbeTemplate(rule)。
- [x] C 用户流程：移除品牌目录，通用规则库作为管理员维护入口；日常计划默认已批准兼容检查、原预览/固定范围/结果保留；指南围绕目标和通用能力。负责相关Web文件及对应测试，不改API/Go。
- [x] D 根整合：main/lifecycle、既有active计划原生规则批准检查与大规则集有界选用、固定引擎和完整库实装、真实HTTP正反+风险/复扫+拒绝越界、全相关回归及一次最终复核、本地加载、记录真实覆盖和缺口。

## Review focus
原生DSL不得调用网络/文件/代码；多请求条件不得降级成单响应；库版本更新不得扩大旧计划；授权撤销/路径/地址/额度始终在请求前生效；部分来源/未编译/不支持语义不能计为已检测。

Ruling: 通用计划上限调整为5000（原500会迫使用户拆分当前2073个兼容执行变体），并增加冻结数据/检查矩阵上界和预览额度；管理员编译批次仍为500。旧计划额度300和固定来源不变。官方HTTP403可用已完整校验的固定缓存，更新检查失败独立标示，不称最新。

验收收尾：本地完整官方目录14,148条，其中1,954条兼容规则的2,073个变体已通过实际管理员界面分5批编译批准；默认通用选项完整返回。隔离数据库验证完整2,073项预览、计划、冻结额度与排队，冻结数据6,251,382字节，无工作器执行或目标网络请求。API417项343通过/74按条件跳过/0失败，Web64文件235项及两端构建通过；实际HTTP、原生编译全集、浏览器与一次独立复核证据见 .artifacts/results/generic-network/。业务目标、生产镜像及持续负载验收不计入本轮完成范围；其余12,194条规则仍明确未适配。
