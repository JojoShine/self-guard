# Self Guard 部署

## 已确认方案

2026-11-01 用户确认：PostgreSQL 随栈部署；前端以版本化静态文件由宿主机 Nginx 提供；后端为镜像。另有自研 WAF 辅助组件镜像，用于规则兼容性检查和节点能力，不在本次部署中接管现有站点。

- 业务/仓库：`self-guard` / 私有 `JojoShine/self-guard`。
- 目标：tbtparent，Ubuntu22.04 amd64；入口 `https://tbtparent.me/self-guard/`。
- `DB_MODE=bundled`，`WEB_MODE=static`，`BASE_PATH=/self-guard`。
- 前端资源 `/self-guard/assets/`，API `/self-guard/api/`，就绪 `/self-guard/healthz`；不占用域名根 `/api/`。
- 服务器目录 `/opt/self-guard`，Compose 项目 `self-guard-production`；后端仅 `127.0.0.1:31009 -> 8080`。端口部署前核对。
- PostgreSQL17 官方镜像使用发布清单内准确摘要，命名卷 `self-guard-production_postgres_data`；不发布5432。
- 仅支持本次明确确认的静态前端＋随栈数据库组合。子路径 Agent 使用0.4.11及以上；旧根路径发行保持不可变。

遵循 [统一部署规范](https://github.com/JojoShine/deploy-standards/blob/main/DEPLOYMENT.md)。服务器仅下载部署文件/静态产物、拉取准确镜像；不上传业务源码、不安装业务依赖、不在服务器构建。

## 发布与产物

CI 对锁文件安装依赖，构建带 `runtime` 目标的后端及WAF辅助镜像；前端使用 `BASE_PATH=/self-guard` 构建。主分支在隔离PostgreSQL验证角色准备、迁移及重复运行、初始化幂等、真实健康、运行权限、持久化重启、Nginx静态/API/健康完整链路后发布候选镜像。

`vX.Y.Z` 标签只提升该提交已通过main验收的镜像和静态压缩包，不重新构建。版本不可覆盖。Release提供：

- `self-guard-<version>-deploy.tar.gz`：完整生产Compose、环境示例、Nginx片段、数据库角色准备、备份脚本和本文。
- `self-guard-web.tar.gz`：顶层目录 `self-guard/`，含已构建前端。
- `release-manifest.json`：源码提交、版本、确认模式、BASE_PATH、后端/WAF/数据库准确镜像摘要、静态文件SHA-256。
- `acceptance.json`：对应候选产物的隔离验收结果。

GHCR镜像为私有，部署前核对具备读取当前仓库包权限的只读凭据；通过标准输入登录，勿把密码写进命令或提交到仓库。保留上一版本清单、配置及静态产物。

## 服务器首次准备

1. 核对Docker Engine、Compose v2、Nginx、架构、磁盘和31009端口；检查已有location，禁止覆盖其他业务。创建`/opt/self-guard`，展开指定版本部署包。
2. 生成独立随机数据库管理、迁移、运行密码，分别存储在`secrets/db-admin-password`、`db-migrator-password`、`db-runtime-password`。文件0600，PostgreSQL容器用户999可读。管理秘密只挂载到数据库初始化流程。
3. 创建`secrets/pgpass`（0600）用于备份的运行角色：`postgres:5432:selfguard:selfguard_runtime:<运行密码>`。它是秘密，不能写入文档、命令行或日志。
4. 从`.env.prod.example`制作`.env.prod`（0600），按发布清单填写全部镜像摘要和连接。`DATABASE_URL`仅运行角色；`MIGRATION_DATABASE_URL`仅迁移角色；空BASE_PATH也须显式填写，本方案固定`/self-guard`。
5. 准备`data/intelligence`、`data/agent-artifacts`归属1000:1000，`data/waf`归属10001:10001。Agent制品和情报原始文件需要与数据库目录配套；数据库中有目录不代表对应文件已存在。
6. 加密密钥、任务签名密钥、Agent发行公钥及组件令牌使用独立受限配置。迁移现有加密记录时，保留相应加密密钥；不得临时生成新密钥导致现有连接/证书无法解密。签名私钥不进入前端或Agent下载包。

数据库初始化入口只在空卷执行：创建`selfguard_bootstrap`管理账号、受限`selfguard_migrator`和`selfguard_runtime`，将public schema交给迁移角色；运行角色只有所需DML、序列读取和迁移历史只读权限。迁移账号不能创建角色或数据库；运行账号不能建表或修改迁移历史。已有卷不重复初始化，不通过删卷修复故障。

## 部署顺序

在`/opt/self-guard`执行。每一步失败即停止后续步骤。

```sh
docker compose --env-file .env.prod -f compose.prod.yaml pull
docker compose --env-file .env.prod -f compose.prod.yaml up -d --no-build --wait postgres
docker compose --env-file .env.prod -f compose.prod.yaml run --rm --no-deps migrate
```

首次数据库准备完成后，核对Compose网络网关，将宿主机Nginx到容器的来源网关地址以`/32`加入`TRUSTED_PROXY_CIDRS`。只信任受控代理，不照抄其他机器的地址。

全新安装需要显式运行`/app/bin/bootstrap`，通过受限`.env.bootstrap`提供管理员邮箱及至少16字符密码。基础Compose不自动加载该文件：`deploy/production.py bootstrap`按数据读取此文件，通过只含变量名的参数向一次性app任务注入秘密。重复运行不覆盖已有管理员密码，不生成演示数据。初始化结束后收起/删除该文件。

迁移现有清理后的数据时，先备份，在隔离空目标库使用迁移角色恢复；恢复命令不带原所有者和权限，再执行迁移以核对历史及运行角色授权。不要在已有业务库上重复恢复或清空数据。数据、原始情报、Agent制品和加密密钥须一起核对，单独恢复数据库不算完成。

```sh
docker compose --env-file .env.prod -f compose.prod.yaml up -d --no-build --wait app waf backup
docker compose --env-file .env.prod -f compose.prod.yaml ps
```

后端默认只启动应用，不迁移、不初始化。`app`、`migrate`和显式bootstrap使用完全相同的后端镜像摘要；初始化密码不持续传给app，数据库管理密码不传给app/migrate。

验证静态压缩包SHA-256后，将它展开到`web/releases/<version>/`，原子更新`web/current`链接（其下有`self-guard/index.html`）。保留上一链接。安装业务片段到`/etc/nginx/business/tbtparent.me/self-guard.conf`，只在既有TLS server中加载；先`nginx -t`，通过才reload。片段不声明server、listen、证书或域名，不改原站点跳转。

## 验收

- 请求真实HTTPS `/self-guard/`，核对页面标题及全部静态资源前缀。
- `/self-guard/healthz`必须返回`ready=true`，同时检查真实运行角色和镜像内迁移校验值；`/self-guard/livez`为应用内部存活接口。
- 登录、读取资产和配置；不存在的API应返回JSON错误，不能被SPA回退变为HTML；不存在的脚本也返回404。
- `/self-guard/api/agent-platform/identity`必须属于当前实例；统一接入入口保存完整子路径。
- 下载签名Agent，验证摘要；实际安装、注册、心跳和采集持续通过才标记接入成功。升级下载保持协议/来源/路径与目标绑定，不向其他业务路径转发组件凭据。
- 对比既有网站首页及根API响应，确认原业务路由未改变。

## 备份、维护与恢复

备份侧车只使用运行角色读取数据库并写平台备份状态，包含情报原始对象及清单；在平台备份设置中开启周期。部署前另外执行一次`backup`服务中的`/scripts/scheduled-backup.sh --once`并核验退出码。敏感`.env.prod`、密钥、Agent制品目录和WAF状态另作受限备份，文件权限0600，不放在静态目录。数据库dump和依赖文件须定期隔离还原核对。

默认保留7个周期备份，可在平台调整为1–30个。日志按单文件10MiB、3份轮转；监控`/opt/self-guard`和Docker数据盘空间，维护宿主机证书续期。PostgreSQL主版本升级需单独备份和恢复演练，不随应用自动升级主版本。

升级前保留当前配置、release-manifest、镜像/静态版本和已验证备份；先迁移成功再启动新应用。入口验收失败时恢复上一静态链接和上一组镜像/配置，重新检查健康与旧业务。应用回滚不自动回滚数据库，不删除数据库卷；破坏性迁移另行安排恢复窗口。单实例替换可能有短暂中断，本方案不宣称零停机或高可用。
