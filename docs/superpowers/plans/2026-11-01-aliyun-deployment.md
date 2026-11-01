# 阿里云静态前端与镜像后端部署计划

> 执行方式：使用 executing-plans 逐项执行，用户明确禁止子代理。仓库首次创建前无 Git 历史，不创建无意义 worktree；后续直接在本任务目录完成首版交付。

**目标：** 按 deploy-standards 将安全平台部署到 https://tbtparent.me/self-guard/，完成真实页面和 Agent 接入验证。

**已确认架构：** DB_MODE=bundled，WEB_MODE=static。宿主机 Nginx 提供版本化前端；一个 NestJS 后端业务镜像兼任迁移、初始化任务；PostgreSQL 随栈。tbtparent 为 Ubuntu22.04/amd64，使用已核实的保存连接。仓库 JojoShine/self-guard 为用户授权新建私有仓库。

**规范：** https://github.com/JojoShine/deploy-standards/blob/main/DEPLOYMENT.md

## 固定约束

- 业务名 self-guard；服务器 /opt/self-guard；Compose self-guard-production；BASE_PATH=/self-guard。
- APP_PORT=31009，部署前再次检查占用。后端容器8080、仅绑定127.0.0.1；数据库不发布端口。
- Nginx /etc/nginx/business/tbtparent.me/self-guard.conf 只包含 location，不修改域名/证书/原有业务 location。
- GitHub Actions 构建并验收候选镜像，GHCR私有发布；正式版本提升同一产物，不在服务器构建。
- 应用运行、迁移、首次初始化分离且共用同一镜像摘要；数据库管理、迁移、运行角色分离。
- 不上传源码、开发依赖或真实秘密到 GitHub。秘密文件权限0600；不将密码写入命令行/日志。
- 迁移清理后现有必要数据和配套制品/密钥，保留 tbtparent 资产。恢复必须核对正式目录内容；不生成测试业务数据。
- 不更改既有WAF高级规则兼容性/性能验收门槛，不对现有业务自动执行流量接管。

## 执行任务

- [x] 读取规范、确认拓扑、创建私有仓库、只读预检服务器与入口。
- [ ] 子路径全链路：前端静态/请求/下载/图标；后端路由和健康；平台配置/安装命令；Agent安装/上报/受控升级下载。回归根路径；拒绝非规范路径；子路径不能借根路径接口完成验证。
- [ ] 生产交付：runtime镜像、显式bin命令、真实健康、受限角色准备、持久化、备份、生产Compose及环境示例；Nginx片段只覆盖self-guard。
- [ ] CI与发布：锁依赖、固定Action提交、隔离PostgreSQL验证迁移/重复初始化/权限/持久化、静态资源/API/健康链路；候选镜像和静态压缩包及SHA/manifest；版本只提升同一组产物。
- [ ] 云端部署：准确版本与摘要，受限秘密、数据/制品备份与恢复，迁移成功后启动，静态版本链接切换、nginx -t后加载；验证旧业务首页/API未受影响。
- [ ] 完成实际HTTPS登录、各目录读取、Agent下载/安装/心跳；记录部署清单、恢复步骤及测试证据。

## 验证重点

- /self-guard/api、静态资源、健康和安装命令都保留路径；根站点现有 /api 不改写。
- 不允许路径遍历、编码斜杠、查询/片段、凭据混入平台基础地址；受控下载授权仍绑定精确协议、来源和目标路径。
- 迁移角色不能管理数据库角色；运行角色不能建表或改迁移历史；重复初始化不覆盖已有管理员密码。
- 当前和上一静态版本/镜像/配置与数据库备份可恢复；应用回滚不自动回滚数据库。
- 私有GHCR权限和云端下载连通性须实际验证，失败不冒充部署成功。
