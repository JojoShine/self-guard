# 数据库审计只读接入

平台以独立数据库实例授权采集主机。实例的“独立审计采集”配置来源主机、授权文件绝对路径和格式；普通审计不依赖检测规则启停。检测规则绑定同一实例和实际文件路径。普通来源的新版Agent声明 `data-security-v2`，仅上传元数据；显式原文来源需要Agent0.4.24及以上并声明 `database-statements-v1`，会通过独立加密队列传输原文；不要将审计文件再配置到包含正文的一般日志采集。

数据库开启审计、创建审计策略、设置导出任务均由有权限的数据库管理员按实际环境执行。这里的导出模板不会由Agent自动执行SQL；凭据保留在现有本地凭据管理中，不放入代码、事件或聊天。

## 格式与边界

| 格式标识 | 来源 |
| --- | --- |
| `audit-json` | 每行标准事件：timestamp（含时区）、service、user、operation、eventId；对象、来源、会话、结果、行数及TLS按实际可得字段提供。实例标识和授权路径由Agent绑定。 |
| `mysql` | MySQL认证错误日志；本次实测5.7.44、8.4.7失败认证。不是普通查询审计。 |
| `mysql-audit-json` | MySQL Enterprise Audit JSON，支持数组及多行对象。需要相应授权插件；本次Community容器未验收插件运行。 |
| `postgresql-csv` | PostgreSQL14+ CSV日志中的pgAudit记录及认证失败。正确处理CSV引号和跨行字段。 |
| `postgresql-audit-json` | PostgreSQL15+ jsonlog中的pgAudit记录及认证失败。14使用CSV；未知结果保持未知。 |
| `oracle-traditional-json` | [oracle11g.sql](oracle11g.sql)导出11g传统审计视图；实测11.2。 |
| `oracle-unified-json` | [oracle12plus.sql](oracle12plus.sql)按目标PDB导出统一审计；必须核实实际源时区并显式确认。12c+实库验收按用户要求暂缓。 |
| `sqlserver-audit-json` | [sqlserver.sql](sqlserver.sql)从授权审计文件导出每行JSON；实测2022。事件标识使用sequence_group_id+sequence_number，文件块偏移不能单独区分事件。非登录succeeded仅表示权限检查。 |
| `dm-audit-json` | 已关闭且不可变的单个DM8审计文件，由官方dmaudtool完整导出后经下述工具剔除正文。实测8.1.4.80。 |

金仓暂使用标准JSON接入；原生格式需官方介质到位后实测，不以PostgreSQL兼容性替代验证。所有引擎缺失TLS、操作结果、行数、对象或权限依据时均不臆测；只有显式导出才标EXPORT，明确停审计才标AUDIT_DISABLE。不能识别的已知事件操作保留为OTHER。

Oracle模板每次只读最近15分钟，最多5000条，超限输出覆盖缺口；需按实际流量安排导出并监控覆盖。输出应追加到Agent授权读取的JSON文件；旧导出事件允许重放，由实例+原始事件标识去重。模板不构成无限回溯或无条件无丢失保证。

## 达梦不可变快照转换

DM视图没有唯一事件序号，时间也可能只到秒。不可仅哈希用户名、时间、对象和操作，否则两次相同查询会被误去重。按照[达梦官方审计说明](https://eco.dameng.com/document/dm/zh-cn/pm/audit.html)，使用dmaudtool解析审计文件，再做元数据转换。

1. 对单个已关闭审计文件核验SHA256；只处理该文件的完整导出，不筛选、不排序、不合并其他文件。导出及重试保持原始完整行顺序，保留不可变源文件及校验值。
2. 显式设置不与内容冲突的列、行分隔符。本次使用 `C_SEP=__SGCOL_7e810a__`、`R_SEP=__SGROW_8b892c__`。导出文件含敏感正文，限本机授权人员读取。
3. 核实源数据库名称、OPTIME所在时区偏移和该版本操作代码映射，保存本地JSON映射文件。本次8.1.4.80核对：12=CREATE TABLE、103=INSERT、104=SELECT、105=DELETE、106=UPDATE、107=EXECUTE。不能未经验证用于其他版本；未映射代码保留OTHER。
4. 运行 `dm8_export.py`，必填 `--source-sha256`、`--database`、`--timezone-offset`、`--operation-map`、`--column-separator`、`--row-separator`，输出追加到授权元数据文件。偏移使用例如 `--timezone-offset=+08:00`，不要默认按客户端时区解释。

转换器只保留17列中的用户、来源、对象、操作、结果与时间；丢弃SQL_TEXT、DESCRIPTION、BIND_INFO。事件标识为原始文件SHA256+完整行序号，重复转换可重放，内容相同的不同记录仍能区分。输入超过32MiB、列数不符或尾记录不全时拒绝转换，不输出部分成功结果。不得对持续变化的活动文件重复套用该方案；连续生产采集需数据库侧轮转及快照调度。

## 本地验证

`--database-fixture` 是有界、只读的适配验证入口，供 `scripts/security-foundations-native.cjs` 使用，不连接数据库、不改变审计策略。真实元数据转换结果再由隔离接口测试导入临时schema；六引擎标准JSON样本只证明平台契约，不证明专有引擎实库兼容。

## PostgreSQL 连接生命周期（2026-11-09）

新增 `postgresql-stderr`，复用实例的独立审计来源及Agent持久队列。固定日志前缀为 `SGDB1|%n|%p|%c|%r|%e|%i|`，要求英文服务器消息，时间使用epoch毫秒；对应 `log_connections=on`、`log_disconnections=on`。PostgreSQL14可重载这三项，无需为了连接日志开启logging_collector、安装pgAudit或重启数据库。

认证通过/失败使用LOGIN，断开使用新增LOGOUT；认证通过不代表随后SQL有权限或执行成功，断开也不推断正常结束。命令标签排除应用RAISE LOG及应用自行抛出的鉴权错误码。支持密码、Peer/Ident、证书、PAM/BSD/LDAP/GSS/SSPI/RADIUS的明确用户名消息，以及HBA拒绝；缺失身份、未知格式、空端点或无法无歧义提取的标识生成采集缺口。Unix域连接明确保留`[local]`，不伪造为网络IP或明文风险。

空闲、事务内和错误事务内断开已在真实PostgreSQL14.24验收。执行中异常断开的LOG文本无法独立排除应用伪造，当前保留缺口，不作为完整断开覆盖。具有空格/引号等复杂用户名或库名时，stderr身份提取可能不支持；采用适当的结构化来源后需另验收。CSV/jsonlog同步支持连接生命周期，本轮结构化样本在UTC下回归。

不上传SQL、密码、原始消息或应用名；应用名可伪造SSL字样，因此连接日志的TLS字段保持未知。此来源不提供普通SQL正文、完整访问行为或阻断能力；与请求/响应观察独立验收。

### PostgreSQL SQL原文的显式选择

`postgresql-csv-sql` 在连接审计之外读取原生CSV执行完成与错误记录；原 `postgresql-csv` 仍仅保留元数据。需要14+的CSV日志及verbose来源位置，完成日志来自postgres.c的exec_simple_query/exec_execute_message；Parse/Bind不作为执行，应用RAISE LOG不作为完成凭据。配置log_min_duration_statement=0、log_statement=none、log_min_error_statement=error、log_error_verbosity=verbose、log_timezone=UTC，禁用绑定参数记录。logging_collector启动项变更需要业务维护窗口。

原文32KiB上限，完整CSV记录64KiB上限；超限明确报告缺口。SQL来源半行留在源文件，队列AES-GCM加密，运行时7天清除原文。平台独立加密证据表、独立权限和7天期限；普通元数据不保留SQL。预编译保留占位符，不含绑定值或返回数据；执行完成不推断最终事务提交。具体部署与容量限制见docs/PostgreSQL14试点接入方案.md。


## 多引擎原文来源（Agent0.4.24+）

旧格式的正文剔除行为保持不变。只有显式选下列原文格式才保留正文，普通事件、告警和列表仍不携带原文；32KiB原文和64KiB记录上限、半行不写游标、加密队列、事件发生时间起7天到期规则适用于这些来源。来源受实例类型、主机与授权路径约束。`AUDIT`仅代表审计来源；执行结果、耗时、SQLSTATE不存在时不补值，不承诺事务提交。

| 来源 | 准备与边界 |
| --- | --- |
| `audit-sql-json` | 标准事件增加`execution:{protocol:"AUDIT",sql:"原始语句"}`；Redis使用`COMMAND`。原始事件ID、UTC发生时间、service、user、operation由可信导出提供；未知账号显式`user:"[unknown]",userKnown:false`。没有这些字段不能猜测 |
| `mysql-audit-sql-json` | Enterprise Audit原生JSON的general_data.query；连接记录不附SQL。需要已授权启用插件；Community不自动有此审计能力 |
| `oracle-traditional-sql-json` | [oracle11g-sql.sql](oracle11g-sql.sql)显式导出SQL_TEXT；审计本身未保存文本时只有元数据 |
| `oracle-unified-sql-json` | [oracle12plus-sql.sql](oracle12plus-sql.sql)显式读取SQL_TEXT；需核对源时区。模板对超过4000字符的CLOB拒绝转换，绝不截断伪装完整。此新原文模板尚未在真实统一审计源验收 |
| `dm-audit-sql-json` | 原不可变快照转换加`--include-statement`。只加SQL_TEXT，仍不导出BIND_INFO/DESCRIPTION，旧默认不变 |
| `kingbase-audit-sql-json` / `vastbase-audit-sql-json` | 标准原文事件，service分别kingbase/vastbase。需要真实厂商审计受控转换，尚无该产品介质验收，不能直接套PG日志格式 |
| `redis-command-json` | 标准命令事件。可用[redis_slowlog_export.py](redis_slowlog_export.py)转换`redis-cli --json SLOWLOG GET`快照，必填从同一Redis的INFO server核实的`--run-id`；run_id+slowlog序号用于重放去重 |

Redis SLOWLOG只覆盖由Redis记录的慢命令，Redis会截断过多或过长的参数，无法还原未记录部分，因而不能宣称全量或完整原始命令。转换器保留来源提供的参数数组文本、时间、耗时；不伪造账号、结果、SQLSTATE或数据库编号。不自动运行MONITOR、修改slowlog阈值、读取键值或开启业务记录。需要管理员选择合适的受控来源与留存策略。

所有导出先写0600私有临时文件，只有转换/SQL客户端退出成功后才原子重命名或追加到Agent授权文件；失败输出不得作为新批次接入。原始SQL文件同样敏感，部署侧需限制权限、磁盘配额、轮转和最长7天清理。外部导出调度、插件授权与数据库审计开关不由Agent自动配置。模板与转换器不构成全版本/全量覆盖保证。
