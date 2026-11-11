# Single Scan Launch Implementation Plan

> **For agentic workers:** Use superpowers:executing-plans for inline execution. Preserve the existing shared working tree.

**Goal:** 从单一入口完成选择、预览、明确执行与查看结果。
**Architecture:** 首页准备检查直接打开现有创建表单，复用既有API；执行后保留计划和运行并自动刷新。
**Tech Stack:** React / Ant Design / existing NestJS APIs; no new dependencies.
**Spec:** docs/superpowers/specs/2026-11-11-scan-launch-design.md

## Global Constraints
不批准新业务目标，不扫描业务，不重启数据库，不改API及原计划默认行为，不覆盖既有改动。

## Review Focus
读取失败和权限不足不得显示可执行；切换标签不得自动执行；只有明确按钮触发创建及排队；创建成功但执行失败不得重复建单；预览失效及目标撤销仍由既有边界拒绝。

- [x] 新入口：先增加并运行准备缺口和权限回归，再实现VulnerabilityWorkspace首页入口与明确下一步；保留来源、规则与计划管理。
- [x] 连贯执行：更新ScanPanel和ActiveScanPanel，添加显式启动请求、首次手动默认、预览后保存并运行、运行进度刷新及失败恢复；原编辑路径不改变。
- [x] 验证与指南：用现有隔离浏览器验收验证新入口到真实合成软件风险、故障恢复和权限；手机检查、Web测试和构建，更新指南与交付记录。

最终复核：两项P2（搜索误判无主机、返回/前进恢复待启动意图）均已RED→GREEN；启动前的可用清单检查使用独立未筛选查询，与表格分页、搜索分离。慢响应导致进度失效按重要问题处理，以4.5秒延迟回归RED→GREEN，只在当前响应结束后刷新当前运行。手机提示可读宽度及按钮上下排列同样RED→GREEN。未增API、迁移或依赖；没有业务Web目标，因此不将本轮视为新增Web业务启动成功验收。

已核对：Web64文件240项、隔离浏览器真实合成软件扫描与启动故障恢复、权限、搜索、历史导航、慢响应及5张Mermaid通过。本地只读检查确认0业务计划、0批准网络目标、2073批准规则，现有软件清单缺失或过期已在入口提前解释。证据见.artifacts/results/scan-launch/与.artifacts/results/vulnerability-workspace/verified.json。

最终Web类型检查与生产构建通过；保留既有依赖use-client及产物体积提示，不影响本轮功能验收。
