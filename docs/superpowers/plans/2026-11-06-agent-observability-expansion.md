# Agent 观测能力补充 Implementation Plan

**Goal:** 澄清流量记录，增加端口进程依据与常用数据库访问覆盖。
**Architecture:** 沿用主机心跳、原流量API、独立数据探针；仅新增可选心跳字段，不改路由与数据库结构。
**Tech Stack:** Go、React/Ant Design、现有捕获与验收工具。
**Spec:** docs/superpowers/specs/2026-11-06-agent-observability-expansion-design.md

## Global Constraints
保持旁路；不自动部署；不提升基础采集器权限；不读取进程命令行和环境；保留未知/缺口及原始字节；不增加依赖；不修改无关脏变更。

## Tasks
- [x] 端口与软件：失败用例→有界inode/进程关联→心跳与页面展示→主机/权限边界验证。
- [x] 流量记录：失败用例→名称、说明、统计与速率→桌面/窄屏验证。
- [x] MySQL：预编译/执行/关闭/错误/未知ID用例→有界状态关联与响应消费→协议回归。
- [x] Redis：多键/值隔离/HELLO AUTH用例→对象与账号关联→协议回归。
- [x] 运行相关Go/Web回归、构建，记录成熟检测引擎路线及真实验收边界，更新使用说明。
