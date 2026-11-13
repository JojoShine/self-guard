# Interactive Demo Implementation Plan
> Execute inline using superpowers:executing-plans; preserve dirty workspace.

Goal: 让公开体验账号完成有持久结果的可写样例流程。
Architecture: 会话隔离 Setting 状态 + 保留身份专用受限 API；独立体验 UI，不提高生产角色。

- [ ] API RED/GREEN：会话分区、非体验拒绝、精确路由、参数/限额、版本冲突、重置、过期和事务回滚；接入 AuthGuard/main。
- [ ] UI RED/GREEN：登录说明不再只读；独立体验页完成资产、任务、结果处置、SQL解析与重置，明确样例边界。
- [ ] 针对测试、完整构建和集成权限检查；隔离发布工作副本中只提交本次文件，正式CI通过后发布部署。
- [ ] 线上使用正常体验登录，验证写入、双会话隔离、越权拒绝与重置；数据库/基础Agent不重启。
