# Self Guard

自主安全平台：React + Vite + Zustand + Ant Design；NestJS + Prisma + PostgreSQL；Go Agent 与 Go WAF。

初版功能按确认的需求接入，项目环境中的功能验收与生产现场验收分开记录。功能、测试证据和运行边界见 [验收矩阵](docs/验收矩阵.md)，复现及 TLS/双 API/密钥维护见 [运行与验收说明](docs/运行与验收说明.md)。

## 当前运行入口

- 管理界面：<http://127.0.0.1:5180>
- API：<http://127.0.0.1:4010/api>
- 管理员邮箱：`admin@selfguard.local`
- 随机初始密码保存在本目录 `.env` 的 `ADMIN_PASSWORD`，不写入源码或公开文档。

`.env` 为本地私有文件，不应提交或分享。当前数据库包含自动测试创建的标记记录；它们是实际 API/Agent 测试结果，不是产品演示数据。

## 界面规范

统一视觉与交互规范见 [设计系统 V1](docs/ui/设计系统V1.md)，登录、Logo、深色导航、浅色工作区、卡片、表格、表单和详情共同使用同一套规则。平台内可从“系统管理 → 界面规范”查看组件预览。设计令牌位于 `apps/web/src/theme.ts`；本轮真实页面与分辨率验收见 [界面验收记录](docs/ui/界面验收记录.md)。

## 本地启动

正常 Docker 构建（需要足够磁盘空间）：

```sh
./scripts/init-env.sh
node scripts/provision-keys.cjs
docker compose up -d --build
```

当前环境 Docker 虚拟磁盘已满，因此联调使用已有镜像与项目目录挂载，不删除其他项目资源：

```sh
./scripts/init-env.sh
node scripts/provision-keys.cjs
./scripts/prepare-dev-runtime.sh
docker compose -f compose.dev.yaml up -d
```

`provision-keys.cjs` 需要本机 Node.js（项目使用 22）。它只为缺失或空白的加密密钥和任务签名密钥生成值，保留已有非空密钥，并以原子替换方式把 `.env` 权限设为 `0600`。重复运行不会轮换密钥；相同值与空白重复项会合并，不同非空值的冲突会报错并保持原文件不变。不要删除或重建已有 `DATA_ENCRYPTION_KEY`，否则已加密配置无法解密。公钥写入 `.artifacts/executor-public-key.txt`，私钥不会输出到终端；配置本地执行器时仅分发该公钥。

该开发方案在启动时运行数据库迁移、检查管理员账户并编译 API，Web 使用 Vite。两种启动方式共享宿主端口，不要同时启动。标准构建流程的镜像验证仍受磁盘限制，不能把开发栈验证等同于生产镜像验证。

## 目录

- `apps/api`：管理后端、Prisma 模型和迁移、业务与集成测试。
- `apps/web`：浅色管理界面、API 客户端、页面与浏览器操作测试。
- `services/agent`：独立 Go 采集、策略与受控修复组件。
- `services/waf`：独立 Go 反向代理、规则检查与管理同步。
- `scripts`：环境初始化、浏览器烟测、真实组件测试和备份恢复验证。
- `docs`：实施计划与需求验收矩阵。
- `.artifacts`：本地测试数据、截图、开发数据库及编译缓存，不提交。

## 验证

后端单元与真实数据库集成测试（会创建测试记录，最后执行登录限流回归）：

```sh
docker compose -f compose.dev.yaml exec -T api sh -c 'npm run build && node test/run-isolated-http.cjs'
# 随机测试schema与独立API进程；结束只删除该测试schema，不重置共享业务库。
```

前端：

```sh
docker compose -f compose.dev.yaml exec -T web npm test
docker compose -f compose.dev.yaml exec -T web npm run build
```

Go 组件：在各自目录运行 `go test ./...`；建议 Linux 容器验证实际运行平台。当前使用已有 `golang:1.27.3-alpine` 镜像验证，Agent 源码最低 Go 1.25（使用受根目录约束的文件读取），其余组件见各自 `go.mod`。

浏览器：安装 Playwright 与 Chrome 后，在根目录运行 `node scripts/browser-smoke.cjs`；可通过 `PLAYWRIGHT_MODULE` 指定 Playwright 模块路径。更完整的表单流程为 `apps/web/browser-actions.cjs`，按文件中的运行目录与环境运行。

全部基础检查可运行 `./scripts/check.sh`。

真实组件联调：先将 Linux 静态 Agent/WAF 编译至 `.artifacts/bin/agent` 和 `.artifacts/bin/waf`，启动开发栈后运行 `node scripts/component-e2e.cjs`。脚本只操作 `.artifacts/fixture-*` 文件及 `selfguard-test-*` 专用临时容器，验证完成后清理这些容器。脚本失败时会留下容器供诊断。

## 备份恢复

```sh
./scripts/backup.sh
./scripts/verify-backup.sh .artifacts/backups/<备份文件>.dump
```

手动和定时备份共用锁定流程。新备份同时生成 `.dump.artifacts` 清单，并在同级 `intelligence-objects` 目录保留校验后的原始情报文件；迁移备份时需一起携带。验证脚本恢复到独立临时数据库，核对其引用的原始文件大小和SHA-256后删除临时库，不覆盖运行数据库。历史无清单备份会明确提示没有验证原包。生产恢复、证书材料与组件状态的综合灾备仍需进一步验证。

## 已实现的主要流程

- 登录、角色权限、会话注销、审计及管理员用户管理。
- Agent 注册、清单与发现上报、风险去重和凭据撤销。
- 规则配置、版本恢复、远程策略、手工精确版本漏洞规则、定时执行与检测记录。
- 全部发现、风险/告警/事件关联、备注、分派及合法状态转换。
- 文件权限及精确配置项修复审批、原子领取、持久结果回传及独立复测。
- WAF 站点策略、基础攻击规则、观察/阻断、IP/方法/路径策略、限速、脱敏事件与节点状态。
- 业务分组、报告快照、趋势、导出审计、站内待办、平台健康。

修复默认禁用，必须显式配置 Agent 允许根目录；只使用测试或明确授权的目标。WAF 默认观察模式，启用阻断前应验证业务误报。

## 当前能力边界

- 漏洞检测已支持受限OSV公告源、Debian/Ubuntu版本范围和精确版本；更广公告生态及厂商范围仍未覆盖。
- 修复当前支持文件权限、精确 KEY=VALUE 配置项与白名单服务状态三个模板，不宣称已实现需求中的全部配置/补丁场景。
- 已有签名远程灰度、失败恢复、采集/执行权限分离、细粒度数据/证据授权及本机资源实测。未宣称认证所有发行版、生产主机或资源组合。
- 日志支持跨块完整行、窗口及服务端多条件关联。正文默认不上传，明确开启后仍脱敏；所有缓存和存储有上限。
- WAF 为基础启发式规则；事件使用有界持久 outbox、重试和丢弃计数，不承担大流量清洗。
- 已有证据附件、HTTPS 外部通知、定期备份/隔离恢复、存储上限和保留清理、平台证书轮换及双 API 故障演练。数据库仍为单节点，不承诺数据库自动切换或生产 SLA。

完整范围和逐项状态见 [需求建设方案](需求建设方案.md) 与 [验收矩阵](docs/验收矩阵.md)。

日常操作见 [用户操作手册](docs/用户操作手册.md)，隔离数据库测试可运行 `docker compose -f compose.dev.yaml exec -T api node test/isolated.cjs`。
