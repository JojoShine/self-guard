# Suricata Integration Implementation Plan

**Goal:** 将独立旁路Suricata接入现有资产与网络安全工作区。
**Architecture:** 稳定API契约，资产绑定传感器及事件持久化，独立Go只读桥接器，现有告警及网络页展示；不修改业务转发。
**Tech Stack:** Go标准库、Nest/Prisma/PostgreSQL、React/Ant Design。
**Spec:** docs/superpowers/specs/2026-11-06-suricata-integration-design.md

## Global Constraints
沿用资产授权与证据权限；不提权基础Agent；不上传原始payload/认证头/查询串；不自动部署生产；保留现有脏变更；无新运行时依赖。

## Tasks
- [x] 固定契约并建立进度记录，分开后端、桥接器与前端文件所有权。
- [x] API：失败用例→schema迁移与严格校验→来源管理/撤销/批次事务/告警→真实临时数据库验收→只读任务复核。
- [x] Go桥接器：失败用例→EVE白名单→有界持久状态/确认/轮转→双架构构建与部署文档→只读任务复核。
- [x] UI：失败用例→来源右抽屉/健康/事件过滤/flow钻取→现有导航与告警证据链接→桌面/窄屏验证。
- [x] 隔离真实Suricata合成流量→采集器/API/告警端到端；全量相关检查、整体复核、交付记录。

## Review Focus
资产越权、令牌失效、乱序/重复批次、uint64精度、敏感字段外泄、轮转丢失、确认错误推进游标、旧EVE伪造在线、规则文件与实际加载混淆、禁用源仍采集。
