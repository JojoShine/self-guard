# Clear Security Workflow Implementation Plan

> **For agentic workers:** Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** 用户从资产接入到查看安全结果有明确路径，结果、证据、配置分层。
**Architecture:** 复用现有页面、接口与抽屉，保留旧路由和权限。新增主机流量工作区承载主机选择，复用持续监控和端口组件；协议页维护自己的URL与配置视图。
**Tech Stack:** React, TypeScript, Ant Design, Vitest.
**Spec:** docs/superpowers/specs/2026-11-06-clear-workflow-design.md

## Global Constraints
- 保留已有脏工作区、业务分组、API、权限和生产数据；不提交、发布或远程变更。
- 不将无采集解释成安全，不合并不同来源的流量计数或会话标识。
- 使用现有组件及样式变量，不添加依赖。

## Review Focus
- URL切换、刷新和返回后主机/事件/配置范围正确。
- 资产/源请求失败时不得显示另一主机的旧证据。
- 新用户没有资产、监控或探针时有明确下一步。
- 权限不足不暴露正文或采集控制，不把失败汇总为零。
- 无告警、离线回放、未采集和采集健康分别呈现。

### Task 1: 日常入口与URL
**Files:** navigation.ts, CoreWorkspace.tsx, network-sensor-query.ts and corresponding tests.
**Interfaces:** 保留network-hosts/network-sensors；SensorLocation增加可选view:'configuration'；sensorEventQuery默认flow且不发送view/recordId。
- [x] 写范围保留、配置URL回环、默认协议查询测试，运行确认失败。
- [x] 将网络入口改为流量分析、连接/协议标签；配置从独立按钮进入；扫描来源保留在扫描配置。
- [x] 运行相关Vitest，要求全部通过。

### Task 2: 概览的下一步
**Files:** Dashboard.tsx, Dashboard.test.tsx, dashboard-navigation.ts, dashboard.css.
**Interfaces:** loadCoreOverview仍使用6个已授权列表；安全问题查询精确status=OPEN，指标链接同样带OPEN；不推导采集覆盖。
- [x] 写OPEN查询和空态指导测试，运行确认失败。
- [x] 首屏呈现待确认问题与近期记录，再给出登记/确认采集/核查结果步骤和背景总量。
- [x] 运行概览及导航测试，要求全部通过。

### Task 3: 结果与配置分层
**Files:** HostTrafficWorkspace.tsx, HostNetworkPanel.tsx, NetworkSensorsPanel.tsx, main.tsx and tests.
**Interfaces:** 工作区接收role/onAsset/onConfigure；复用GET /assets、/assets/:id及TrafficMonitorSection。协议来源配置使用view=configuration，保留精确事件链接。
- [x] 写无主机时下一步、Agent信息不冒充流量、协议默认不混入stats、技术字段折叠等测试，运行确认失败。
- [x] 实现主机选择及请求隔离，复用采集抽屉；持续监控首屏只展示状态和记录，技术配置按需展开。
- [x] 协议记录默认flow；来源维护放在配置工作区，健康和事件详情继续可访问。
- [x] 简化数据审计入口与领域内告警列；移除日常告警页导入主按钮；资产接入步骤与能力说明保持可发现。
- [x] 运行相关测试，再运行完整Web测试与构建。

### Task 4: 真实浏览器与交付
**Files:** content/operation-guide.md, docs/核心安全功能裁剪实施记录.md, .artifacts/results/clear-workflow/.
- [x] 本地浏览器检查概览→流量→选主机→配置，以及协议→告警→证据、筛选/返回、空态和窄屏。
- [x] 独立复核本次变更；重要问题单次修复并回归，不扩展范围。
- [x] 保存验证证据，保持本地可预览；不部署生产。
