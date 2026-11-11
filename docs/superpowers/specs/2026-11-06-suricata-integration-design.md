# Suricata 旁路接入

用户已接受独立Suricata路线并要求接入。实现范围：资产绑定来源、独立只读EVE桥接器、网络告警/协议与流记录、健康与规则文件来源，完整本地验收。保持现有四项主导航，在主机与流量附近增加入口，表单沿用右侧抽屉。

## 架构与边界
- Suricata独立旁路运行；桥接器沿用主机资产归属，但使用单来源凭据，不能替其他来源/主机写入。桥接器不需要抓包权限，不读取Agent密码/令牌，也不将主Agent提权；仅核对本机Agent身份文件中的assetId。
- 来源按资产授权；管理员/运维可创建、启停、编辑和签发配置，读取仍要求资产范围和证据权限。签发/编辑检查当前权限；来源停用、归属资产归档、所有者禁用或授权失效后拒绝上传。令牌只返回一次，只存哈希。配置使用已验证的平台入口及CA；不关闭TLS校验。
- 读取显式授权的EVE JSON普通文件，剔除payload、packet、正文、认证头、Cookie、查询串等；只上传受约束元数据。保留原EVE校验摘要、64位flow ID十进制字符串，避免JS数字舍入。
- 来源与事件使用独立表，新增迁移向后安全。批次及事件幂等；告警与事件在同一事务写入，只有alert事件创建NETWORK告警，协议/flow/stats/anomaly保留记录不伪造威胁结论。
- flow关联以来源、flow ID及时间范围核对，不能将flow ID视为跨重启的全局标识。索引保存7天、每源最多50000条，限额和过期不改变已有告警历史。
- 桥接器独立持久状态、唯一写者锁和有界待确认批次。先持久化批次与后续游标，再发送；仅在核对源/批次/持久确认后推进游标。离线重试不读取无限数据，权限/协议错误不会静默吞掉记录。处理追加、半行、重启、轮转与截断，不能恢复的旧文件明确增加缺口。无原始明文队列。
- 采集器在线、最后EVE时间、最后stats时间、累计丢包、规则加载失败/规则文件指纹分别显示。登记的引擎版本不是运行证明，文件hash匹配不是引擎已加载证明。缺stats、过期、丢包、解析失败、待上传和未接入均显式标记。
- 规则管理遵循官方suricata-update，提供独立旁路部署/更新说明和本地验证配置，先校验候选配置再启用；不自动修改业务代理、不执行inline/IPS、不自动部署生产或更新全部主机。

## 稳定契约
契约以apps/api/src/network-sensor-contract.ts为准。桥接器POST /sensor-ingest/:id/batches，Bearer为来源令牌；GET /sensor-ingest/:id/config校验启用及凭据。POST批次 `{batchId,mode,events,health}`，mode=LIVE/REPLAY。响应必须 `{sensorId,batchId,persisted:true,accepted}`。事件 `{eventId,sourceSha256,occurredAt,eventType,flowId?,sourceIp?,sourcePort?,destinationIp?,destinationPort?,protocol?,appProtocol?,metadata}`。eventId及摘要均sha256，flowId为数字字符串。其他字段及限制见TS契约，禁止传原始EVE。

## 本地验收
单测覆盖授权/范围、撤销/轮换、幂等、事件类型、64位ID、字段剔除、缺口和时间/配额；桥接器覆盖中断/确认错配/游标/轮转/长行；隔离Suricata运行真实合成流量，先配置测试再验证EVE到网络告警及查询，不向外部目标发包。浏览器桌面/390px核对表单、空态、状态、过滤、flow钻取和已有导航。

官方依据：
- https://docs.suricata.io/en/suricata-8.0.6/output/eve/eve-json-format.html
- https://docs.suricata.io/en/suricata-8.0.6/appendix/eve-index.html
- https://docs.suricata.io/en/suricata-8.0.6/rule-management/suricata-update.html
