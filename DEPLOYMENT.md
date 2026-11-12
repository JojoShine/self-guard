# Self Guard 部署

## 已确认方案

2026-11-01 用户确认：PostgreSQL 随栈部署；前端以版本化静态文件由宿主机 Nginx 提供；后端为镜像。2026-11-11用户确认移除不再需要的自研WAF运行组件；当前仅交付平台后端、静态前端、随栈PostgreSQL与备份。历史记录保留。

- 业务/仓库：`self-guard` / 公开 `JojoShine/self-guard`。
- 目标：tbtparent，Ubuntu22.04 amd64；入口 `https://tbtparent.me/self-guard/`。
- `DB_MODE=bundled`，`WEB_MODE=static`，`BASE_PATH=/self-guard`。
- 前端资源 `/self-guard/assets/`，API `/self-guard/api/`，就绪 `/self-guard/healthz`；不占用域名根 `/api/`。
- 服务器目录 `/opt/self-guard`，Compose 项目 `self-guard-production`；后端仅 `127.0.0.1:31009 -> 8080`。端口部署前核对。
- PostgreSQL17 官方镜像使用发布清单内准确摘要，命名卷 `self-guard-production_postgres_data`；不发布5432。
- 仅支持本次明确确认的静态前端＋随栈数据库组合。子路径 Agent 使用0.4.11及以上；旧根路径发行保持不可变。

遵循 [统一部署规范](https://github.com/JojoShine/deploy-standards/blob/main/DEPLOYMENT.md)。服务器仅下载部署文件/静态产物、拉取准确镜像；不上传业务源码、不安装业务依赖、不在服务器构建。

## 发布与产物

CI 对锁文件安装依赖，构建带 `runtime` 目标的后端镜像；前端使用 `BASE_PATH=/self-guard` 构建。主分支在隔离PostgreSQL验证角色准备、迁移及重复运行、初始化幂等、真实健康、运行权限、持久化重启、Nginx静态/API/健康完整链路后发布候选镜像。

`vX.Y.Z` 标签只提升该提交已通过main验收的镜像和静态压缩包，不重新构建。版本不可覆盖。Release提供：

- `self-guard-<version>-deploy.tar.gz`：完整生产Compose、环境示例、Nginx片段、数据库角色准备、备份脚本和本文。
- `self-guard-web.tar.gz`：顶层目录 `self-guard/`，含已构建前端。
- `release-manifest.json`：源码提交、版本、确认模式、BASE_PATH、后端/数据库准确镜像摘要、静态文件SHA-256。
- `acceptance.json`：对应候选产物的隔离验收结果。

源码仓库按用户2026-11-11要求为公开；GHCR制品访问权限独立核对，私有制品使用只读凭据；通过标准输入登录，勿把密码写进命令或提交到仓库。保留上一版本清单、配置及静态产物。

## 服务器首次准备

1. 核对Docker Engine、Compose v2、Nginx、架构、磁盘和31009端口；检查已有location，禁止覆盖其他业务。创建`/opt/self-guard`，展开指定版本部署包。
2. 生成独立随机数据库管理、迁移、运行密码，分别存储在`secrets/db-admin-password`、`db-migrator-password`、`db-runtime-password`。文件0600，PostgreSQL容器用户999可读。管理秘密只挂载到数据库初始化流程。
3. 创建`secrets/pgpass`（0600）用于备份的运行角色：`postgres:5432:selfguard:selfguard_runtime:<运行密码>`。它是秘密，不能写入文档、命令行或日志。
4. 从`.env.prod.example`制作`.env.prod`（0600），按发布清单填写全部镜像摘要和连接。`DATABASE_URL`仅运行角色；`MIGRATION_DATABASE_URL`仅迁移角色；空BASE_PATH也须显式填写，本方案固定`/self-guard`。
5. 准备`data/intelligence`、`data/agent-artifacts`归属1000:1000。Agent制品和情报原始文件需要与数据库目录配套；数据库中有目录不代表对应文件已存在。
6. 加密密钥、任务签名密钥、Agent发行公钥及组件令牌使用独立受限配置。迁移现有加密记录时，保留相应加密密钥；不得临时生成新密钥导致现有连接/证书无法解密。签名私钥不进入前端或Agent下载包。

数据库初始化入口只在空卷执行：创建`selfguard_bootstrap`管理账号、受限`selfguard_migrator`和`selfguard_runtime`，将public schema交给迁移角色；运行角色只有所需DML、序列读取和迁移历史只读权限。迁移账号拥有本数据库内创建schema所需的CREATE权限，但没有全局CREATEDB或CREATEROLE权限，不能创建其他数据库或角色；运行账号不能建表或修改迁移历史。已有卷不重复初始化，不通过删卷修复故障。

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
docker compose --env-file .env.prod -f compose.prod.yaml up -d --no-build --wait app backup
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

备份侧车只使用运行角色读取数据库并写平台备份状态，包含情报原始对象及清单；在平台备份设置中开启周期。部署前另外执行一次`backup`服务中的`/scripts/scheduled-backup.sh --once`并核验退出码。敏感`.env.prod`、密钥、Agent制品目录另作受限备份，文件权限0600，不放在静态目录。数据库dump和依赖文件须定期隔离还原核对。

默认保留7个周期备份，可在平台调整为1–30个。日志按单文件10MiB、3份轮转；监控`/opt/self-guard`和Docker数据盘空间，维护宿主机证书续期。PostgreSQL主版本升级需单独备份和恢复演练，不随应用自动升级主版本。

升级前保留当前配置、release-manifest、镜像/静态版本和已验证备份；先迁移成功再启动新应用。入口验收失败时恢复上一静态链接和上一组镜像/配置，重新检查健康与旧业务。应用回滚不自动回滚数据库，不删除数据库卷；破坏性迁移另行安排恢复窗口。单实例替换可能有短暂中断，本方案不宣称零停机或高可用。


## 移除历史WAF（2026-11-11）

当前生产Compose和CI不再创建或依赖WAF服务，不要求WAF_IMAGE/WAF_TOKEN；运行规则发布保持关闭。旧版本导出工具仍可按旧清单取得WAF镜像，用于审计/恢复，不让新版发布重新安装它。仅在新版本健康和入口验收通过后，移除本项目旧WAF容器及已归档的data/waf专用状态；保留可恢复的旧清单/镜像记录。删除旧WAF镜像前核对所有容器引用，只删除未使用的本项目镜像，不执行全机prune，不删除历史平台记录或其他站点Nginx。宿主PG14业务库与原Agent配置不在此次升级范围。

### 数据库自动接入与平台自身审计

数据库实例的“自动接入”提供主机选择、固定 SSH 身份检查、独立采集服务安装、维护等待和真实数据验收。PostgreSQL 原生模式适配宿主机和显式 Docker 容器；已有其他引擎审计文件沿用受支持格式，不会自动安装受许可约束的审计插件。运行指标仍使用已有独立只读连接配置。独立采集服务不修改基础 Agent 的采集根目录、身份或执行器权限。

原生 PostgreSQL 安装会修改该服务的日志配置，使用独立 CSV 目录，关闭绑定参数记录，开启语句完成及错误记录；影响整个 PostgreSQL 服务的全部数据库。日志原文按七天期限清理，专用原始日志目录以256MiB为容量目标清理非活动旧文件，容量提前删除会显示采集缺口；活动文件独自超预算会显示异常，不能宣称完整。源日志按小时或大小轮转，独立清理定时器在停止采集后继续运行。已有 FILE 来源不由平台删除，其原始文件期限应由原系统配置。

`logging_collector=off` 时，平台不会自动重启数据库。“准备重启后接入”只持久设置 `logging_collector=on`，不执行 reload，不开启 SQL 执行日志。维护后重新检查并安装，才配置 SQL 日志。未留日志的历史 SQL 无法补回。

监控平台自身 PostgreSQL 前，部署管理员必须配置独立审计入库连接 `AUDIT_DATABASE_URL`。未配置时普通外部数据库接入仍可用，自身数据库启用会被阻止。该连接必须与 `DATABASE_URL` 使用同一主机、端口、数据库和 schema，用户名固定 `selfguard_sql_ingest`，`sslmode=require&sslaccept=strict`；私有 CA 还应通过 `sslcert` 指向容器内可信 CA 文件，连接池最多2。

专用登录角色应为 NOSUPERUSER、NOCREATEDB、NOCREATEROLE、NOREPLICATION、NOBYPASSRLS，单向继承平台运行角色；平台运行角色不能切换到该入库角色。为专用角色设置 `log_min_duration_statement=-1`、`log_statement=none`、`log_min_duration_sample=-1`、`log_transaction_sample_rate=0`、`log_duration=off`、`log_min_error_statement=panic`。应用启动会实际核对 TLS、角色继承及这些配置，配置无效即拒绝启动，防止审计写入递归产生新 SQL。密码使用部署密钥机制保存，不能写入仓库、命令参数或操作日志；不以可伪造的 application_name 免除采集。
