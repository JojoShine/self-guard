# Database Self-Service Implementation Plan

> **For agentic workers:** superpowers:executing-plans; dispatching-parallel-agents for the independent ownership domains below. Preserve the shared dirty working tree. No commits requested.

**Goal:** 补齐新实例自助接入、实际能力提示与多引擎采集链路。
**Architecture:** 复用既有实例/监控/审计；后端固定只读采样，前端统一配置和验收，原文显式选择。
**Tech Stack:** NestJS/Prisma/React/Go Agent; bounded database-native drivers as needed.
**Spec:** docs/superpowers/specs/2026-11-11-database-self-service-design.md

## Global Constraints
不重启或配置业务库，不升级原collector，不记录凭据或原文，不绕过TLS/授权；不伪造专有引擎实库验证。新依赖仅数据库官方驱动及必要类型，固定版本，统一由A修改npm包文件。

## Review Focus
登记成功不冒充采集成功；审计连接不冒充SQL；运行统计不读取业务SQL；秘密不得进入日志和普通元数据；超时实际关闭连接；缺字段、权限与引擎身份不匹配不得算正常。

- [x] A 多引擎运行监控整合：拥有database-runtime-contract.ts、database-native-metrics.ts、postgres-monitor.ts、monitoring.ts及相关专属测试、API npm包文件。实现MySQL/Redis实际只读采样与现有API/租约/存储整合，保留PG旧契约，调用B的vendor采样器。
- [x] B 厂商运行采样：拥有database-vendor-metrics.ts及专属测试/验收脚本；Oracle、DM、Kingbase、Vastbase原生只读采样与身份/能力检查。驱动依赖交给A统一修改；真实可用介质隔离验证，无介质如实标明。
- [x] C 前端自助流程：拥有DatabaseInstancesPanel、DatabaseCollectionStatus、OperationalMonitoring、DatabaseAuditPanel及相关测试；保存后进入接入概览、按引擎展示能力/缺口和配置、同实例查看连接与SQL/命令、运行连接保存并验证。使用根约定的能力API与通用指标结构，不改后端、包文件或指南。
- [x] 根整合：能力API、审计接入验收计数与权限、Vastbase枚举及必要兼容、显式SQL/命令适配、主模块/部署、指南、隔离浏览器/真实库回归、本地加载、一次最终独立复核及未完成项记录。

接口：genericDatabaseMetricInput使用schema selfguard-database-metrics-v1、engine/version/database/capturedAt/configurationVersion/status/issues，以及可选的顶层数值指标。readVendorDatabaseMetrics(engine,config,password,configurationVersion,previous?)导出给A，参数类型DatabaseRuntimeConfig，返回GenericDatabaseMetric。运行API路径仍为/database-instances/:id/runtime-monitor。


## 实施与验证记录（2026-11-11）

已完成自助实例保存→同实例接入与验收→保存并验证运行连接→独立配置审计/原文来源→同实例查看的流程。运行指标、连接、操作元数据、语句/命令记录、未到期原文分别计数；新原文来源同时核对Agent能力声明，主机在线不能替代格式支持。普通来源保持剔除正文，新增格式显式保留原文并复用加密、独立权限和7天期限。

架构调整依据：真实泛型运行配置暴露既有OperationalMonitor_target约束只允许POSTGRESQL。追加20261111150000_database_runtime_engines迁移兼容HOST/POSTGRESQL并增加DATABASE，不改旧迁移；隔离结构验证后仅对本地平台应用。服务模块继续沿用既有PostgresMonitoring类及API路径，避免并行调度器。

- MySQL8.4.7：普通账号固定统计、错密码、匹配DNS的可信CA TLS成功及不可信证书拒绝通过。5.7/8.0有适配但本轮未重做实库验收。TLS字面IP在认证前拒绝，需证书匹配DNS。
- Redis7.4.11：INFO-only ACL成功、缺权限、错密码、可信CA与错误CA通过；实际慢日志→受限转换→0.4.24签名Agent解析通过，可由scripts/redis-command-acceptance.cjs复验。不读取键值、不运行MONITOR、不自动开启业务慢日志。SLOWLOG只覆盖慢命令且可能由Redis截断参数。
- Oracle26ai/23.26.3：隔离实例实际系统统计成功，缺失字段PARTIAL。真实驱动TLS合成握手的可信CA/错误CA/错误主机名三项通过；第一轮slim镜像缺少Java/PKI组件，完整TCPS当时未验收；第二轮已补齐，见下文真实TCPS结果。当前Thin仅12.1+，11g需要独立Thick客户端交付。
- 达梦DM8：真实回环隔离系统统计通过。官方dmdb1.0.52452不校验服务端证书/主机名，且限制修改和再分发；已从npm依赖删除，远端TLS保持拒绝。部署自有受信任客户端仅可通过绝对SELFGUARD_DM_DRIVER_PATH显式加载，不能把此隔离结果当作远端生产交付。证据见.artifacts/results/database-vendor-acceptance/driver-evidence.json。
- 人大金仓/海量Vastbase：已有真实产品身份与各自统计视图的适配，不接受普通PG或openGauss替代品。尚无真实产品介质验收；审计需管理员受控转换标准事件，不能声称已自动接入厂商全部原生日志。

最终独立复核发现并修正：厂商仅查到版本而无任何有效统计时拒绝采样，不再标验证成功；厂商差分严格限定1–180秒，断流不带入旧死锁。新增回归先失败再通过，不重复复核。

验证结果：前端完整65文件250测试通过；新增采集器能力提示后相关5文件19测试与类型检查通过。后端完整445测试中365通过、80个需额外环境条件的测试跳过；最终监控/厂商/权限契约29项通过，随机结构配置及入库范围测试通过。Go Agent完整测试与vet通过，Python转换器5项通过，前后端构建通过。浏览器真实HTTP验证七引擎原文加密、幂等、范围/独立授权、到期拒读、新增实例直达验收、失败配置保留、周期采集不自动启用、Redis命令措辞、桌面/手机无横向溢出及5张Mermaid图。证据在.artifacts/results/database-onboarding、database-final-focused.log、database-final-db.log及scan-launch/database-agent-all-green.log。

采集0.4.24/sequence49双架构签名tar.gz/deb/rpm已生成，源码摘要匹配；仅发布到当前本地平台供后续安装。未升级任何现有Agent，未重启或修改121.196.245.95业务数据库。操作指南随页面加载；当前本地前端5180、后端4000健康。

## 后续仍需验收的范围

1. Oracle26ai完整TCPS及专用最小统计账号已通过隔离验收；用户实际服务名/权限仍逐库核对。11g Thick模式仍待相应客户端独立交付。
2. 达梦厂商提供支持严格CA和主机名验证且许可允许部署的客户端后，再补远端运行采样；审计快照接入独立可用。
3. 金仓与Vastbase真实产品版本、认证方式、统计视图权限及审计导出格式验收。缺少介质期间不声称生产完成。
4. MySQL Enterprise Audit需实际插件授权与来源验收；Oracle新增SQL_TEXT模板需目标真实审计记录验证。原SQL保护链路已用隔离标准事件验证，不等于插件已在业务库启用。
5. 固定HTTPS正式部署、各目标数据库日志/导出调度及权限由部署管理员安排；保存配置不会自动开启审计或授予权限。现有PostgreSQL14 SQL原文仍预留维护窗口。

参考：Redis INFO与SLOWLOG官方文档、MySQL8系统统计文档、node-oracledb Thin初始化文档、达梦Node驱动及审计文档、金仓sys统计视图和VastbaseG100统计视图。具体链接已在来源说明和对应采集实现/证据中记录。


官方参考：
- [Redis INFO](https://redis.io/docs/latest/commands/info/)、[SLOWLOG GET](https://redis.io/docs/latest/commands/slowlog-get/)
- [MySQL系统统计](https://dev.mysql.com/doc/refman/8.0/en/performance-schema-status-variable-tables.html)
- [Oracle Thin初始化与支持版本](https://node-oracledb.readthedocs.io/en/stable/user_guide/initialization.html)
- [达梦Node驱动](https://eco.dameng.com/document/dm/zh-cn/faq/faq-JavaScript-new.html)、[达梦审计](https://eco.dameng.com/document/dm/zh-cn/pm/audit.html)
- [金仓sys统计视图](https://bbs.kingbase.com.cn/kingbase-doc/v9.3.11/development/application-develop-guide/internal_views/system_views/statistic_views/index.html)
- [VastbaseG100统计视图](https://docs.vastdata.com.cn/zh_CN/VastbaseG100/V2.2.17%20%28DMR%29/1/5da216e219624a82b663c0ebd16aa1b2)


## 剩余交付补充（2026-11-11第二轮）

用户允许继续完成当前条件下可做的剩余项。保持既有设计和授权范围，顺序实施，不升级依赖、不触及业务库。先补Oracle完整TCPS的隔离链路：复用缓存同架构Java工具生成服务器钱包，真实Oracle只读统计连接验证可信CA、错误CA、错误主机名及账号权限；补可复验脚本和准确指南。若缓存工具不可用则记录阻碍，避免继续下载大型介质。金仓/Vastbase需真实产品介质、达梦需可严格验证TLS的合法驱动、Oracle11g需合适架构和版本的授权客户端，当前不以替代产品或关闭验证完成验收。

- [x] 核对可复用工具和真实阻碍。
- [x] Oracle完整TCPS隔离验收及必要问题修正；无需行为变化，仅完善验收脚本。
- [x] 按实际结果更新指南/验收记录，清理本轮临时资源，核对本地平台健康。


第二轮实际结果：Oracle26ai23.26.3完整TCPS通过，SG_MONITOR仅授予CREATE SESSION及五个SYS.V_$视图SELECT，取得真实连接、容量、活动、等待和事务计数。错误CA、错误主机名、错密码均拒绝；只有CREATE SESSION而无统计权限的SG_NO_STATS明确拒绝采样；负向检查后再次成功连接。指标未覆盖字段仍PARTIAL。证据：.artifacts/results/database-vendor-acceptance/tls-result.json；13项厂商回归测试通过。未修改运行采样实现、不新增平台依赖，不需要发布新Agent。

可复验入口：scripts/oracle-tcps-acceptance.cjs；要求本地已缓存gvenzl/oracle-free:23.26.3-slim及flink:1.20.3-scala_2.12-java17、API依赖已安装，并通过SG_VENDOR_ACCEPT_PKI_JAR提供官方原版oraclepki23.4.0.24.05.jar。该工具仅用于测试钱包，不加入平台或Agent。来源https://repo.maven.apache.org/maven2/com/oracle/database/security/oraclepki/23.4.0.24.05/oraclepki-23.4.0.24.05.jar，501935字节；校对同源SHA-1后另固定SHA-256为dc6eb417390097e9014129a82c36695089aff32ded3d7a77f7ac756194c1603c。许可为Oracle Free Use Terms and Conditions，允许内部开发测试；不修改或随产品分发。原OpenSSL PKCS12缺少Oracle钱包属性，已用官方wallet import_pkcs12转换到新Oracle钱包，再生成auto-login；全程保持CA及主机名验证，不使用弱TLS或关闭校验。

后续边界保持：金仓/Vastbase缺真实产品介质；DM缺可严格验证TLS且适当许可的客户端；Oracle11g缺合适版本/架构的独立客户端。只读适配、审计文件和当前可用功能保持，不将这些边界改成已验收。

参考：[Oracle钱包导入](https://docs.oracle.com/en/database/oracle/oracle-database/26/dbseg/using-the-orapki-utility-to-manage-pki-elements.html)、[Oracle官方Maven组件说明](https://www.oracle.com/database/technologies/maven-central-guide.html)、[Free Use许可](https://www.oracle.com/downloads/licenses/oracle-free-license.html)。


第二轮最终复核修正两项仅涉及验收工具的清理问题：仅记录创建成功的容器ID并按ID清理，使用每次运行唯一名称；即使Docker移除失败也必须删除临时凭据/私钥并尝试清理其他已拥有容器。两个黑盒故障回归先失败后通过。完整Oracle加密采集实现未改变；另用真实无网络空命令验证create/start/按ID移除生命周期。指南相关8测试、API类型检查、厂商13测试和前端构建通过；本地API/前端健康且能读取更新指南。Oracle专用数据库/工具容器、临时密码/私钥及下载的钱包工具在本轮结束时清理。
