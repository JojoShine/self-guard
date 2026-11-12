# Database Automatic Onboarding Implementation Plan

> **For agentic workers:** Use superpowers:executing-plans, with independent ownership delegated according to superpowers:dispatching-parallel-agents. Preserve the dirty workspace.

**Goal:** 交付实例内可自行检查、安装、等待维护和验收的数据库接入流程。
**Architecture:** 现有SSH任务 + 明确目标的远程PG原生日志配置 + 独立只读Go采集服务；原监控和审计接口保持兼容。
**Tech Stack:** NestJS/Prisma/React/Go，远程Python标准库，无新依赖。
**Spec:** docs/superpowers/specs/2026-11-12-database-automatic-onboarding-design.md

## Global Constraints
不自动重启数据库；不操作业务PG14；不扩大基础Agent权限；不发布凭据；原文7天；原文独立授权；只用固定SSH身份；不确定结果不重试。

## Review Focus
- SSH、实例、账号范围变化后旧排队任务必须失效。
- 未接入独立入库连接的系统库不得开启全局SQL自采。
- 目录轮转、写队列失败和过期清理不能默默丢失或泄漏原文。
- 不支持的引擎或未提供日志不能显示安装成功。
- 安装成功与真实SQL收到分别验收，无业务查询不伪造数据。

## Tasks
- [x] API任务：先写权限、输入、等待维护、幂等测试，运行见红；实现database-onboarding.ts及统一任务排除、独立健康上报和模块注册；回归/构建。
- [x] 独立Go采集：先写目录轮转、加密持久队列、故障/背压测试，运行见红；实现--database-monitor，复用原解析和交付；只读授权刷新和独立健康；Go验证。
- [x] 远程执行：先写Python隔离目标/安装/准备后不重启测试，运行见红；实现固定目标CHECK/PREPARE/INSTALL/STOP脚本和安全systemd单元；真实隔离PG17验收。
- [x] 前端：先写流程/等待维护/失败和运行验收测试，运行见红；实例内统一接入面板，复用运行配置；更新现有指南。
- [x] 整合：类型/构建/关键权限回归、真实隔离端到端、独立复核，记录生产未启用的维护边界。部署只升级平台和采集工具，不调用生产SQL启用或PREPARE操作。

预检：API任务产出远程任务约定与健康API；Go采集消费服务配置并上报该健康API；前端消费统一任务状态；远程脚本通过私有stdin交付配置。约定详见各任务旁的接口说明，冲突由根任务统一处理。

## 验证与交付记录

前端70文件269测试通过；后端488测试408通过、80环境项跳过、0失败。独立PG17.11真实systemd验收确认：检查识别维护、PREPARE不重启/不即开SQL、旧目标指纹拒绝、原生CSV采集真实语句与错误、加密队列、实际安装的源日志过期/容量清理、停止后保留清理timer。HTTPS验收落点为隔离sink，正式鉴权/加密入库边界另由sql-ingress-isolation真实API验证。

独立复核两项Important已修：清理脚本语法错误以生成程序compile测试RED→GREEN；轮转保留集超过64文件改512文件/1024entries并250+文件回归RED→GREEN。真实systemd联调发现状态文件父目录UID999与root保护冲突，改读独立root私有state，未放宽保护，真实回传复验通过。

生产数据库SQL开关和重启仍未执行。平台版本发布及线上只读验收另保留部署记录。
