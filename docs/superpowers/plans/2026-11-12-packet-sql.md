# Packet SQL Implementation Plan

> **For agentic workers:** Use superpowers:executing-plans; independent API/UI tasks follow superpowers:dispatching-parallel-agents. Preserve shared dirty worktree.

**Goal:** 在已有流量访问证据中安全解析并展示SQL。
**Architecture:** 复用访问探针和证据存储，按需解码请求，保持独立授权/七天期限；实例内统一入口。
**Tech Stack:** NestJS/TypeScript/React/既有Go协议探针，无新依赖。
**Spec:** docs/superpowers/specs/2026-11-12-packet-sql-design.md

## Global Constraints
不重启或改数据库；不关闭TLS；不代用管理员；原文不进元数据；复用现有TCP重组与AES-GCM。

## Review Focus
认证报文不得作为SQL；准备与执行不得混淆；不同会话/记录不可猜关联；到期/缺段不能拼假完整；实例范围与双重原文授权不能被前端筛选清空。

- [ ] 根：RED→GREEN协议提取器traffic-sql.ts，PostgreSQL/MySQL字段和预算/坏帧/UTF8测试；以实际协议抓取结果复验。
- [ ] API：RED→GREEN读取原文权限、分段/期限/范围测试；access-observation.ts增加GET :id/sql和canReadSql，复用readChunk证据验证，不保存二次正文。
- [ ] UI：RED→GREEN按需读取、准备/执行与缺口文案、实例范围；新增TrafficSqlView，AccessObservationsPanel和实例内入口，指南说明TLS边界。
- [ ] 整合：类型/针对回归、真实PostgreSQL报文→已加密证据→正常登录权限接口→页面数据验证，完整构建；独立复核；部署只发布代码，不激活未授权生产抓取。

共享接口：parseCapturedSql(protocol:string,request:Buffer) => {state:'EXTRACTED'|'PARTIAL'|'UNAVAILABLE'|'UNSUPPORTED',statements:{sql:string,stage:'QUERY'|'PREPARE'|'EXECUTE'}[],reasons:string[]}；API响应再附protocol,source:'PACKET_REQUEST',observedAt,expiresAt?。code枚举由根统一。
