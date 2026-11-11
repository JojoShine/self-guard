# CRS正式发布与Nginx自动接入 Implementation Plan

> **For agentic workers:** Use superpowers:executing-plans inline. Preserve all preexisting changes; no commit/push requested.

**Goal:** 完成用户已授权的CRS运行验收与本地发布，以及宿主机Nginx现有/新业务的系统自动接入。
**Architecture:** 复用Agent Nginx事务、AssetRemoteJob、已保存SSH管理连接与WAF签名发布/回退。不并行重写既有实现。
**Tech Stack:** NestJS/Prisma/PostgreSQL、React/AntD、Go/PCRE2、Docker。
**Spec:** docs/superpowers/specs/2026-11-03-waf-production-nginx-design.md

## Global Constraints
保留全部原有未提交变更。规则/签名/权限/原CPU及内存预算不降级。不直接接管业务。原100RPS/30分钟/零错误/新增P95≤20ms门槛不变。私钥只留宿主/API专用进程。当前原Docker开发栈/旧VM已不在本机；适配当前本地API+15433 PostgreSQL，测试只用隔离schema及自有容器。

## Review Focus
预检后配置/凭据/站点变化；新建与已有文件竞争；证书和符号链接；连接中断未知结果；签名与回放/节点归属；性能结果不得用短测/删失败替代。

- [x] 1. Agent预检与事务：新增受限只读Nginx预检、新业务独立配置、预检指纹绑定、新建文件的事务/回退、固定镜像受控获取。先写Go失败用例，定向与完整回归。
- [x] 2. 后端自动任务：AssetRemoteJob.kind向后兼容迁移，复用事务与单主机互斥、明确管理员授权、预检/执行/回退/中断恢复，受管镜像归档下载；隔离DB与SSH夹具验证。
- [x] 3. 前端：现有同机Nginx入口补现有/新业务、预检结果、确认执行、进度、回退；复用原表单/抽屉，不叠弹窗；桌面/窄屏与边界验证。
- [ ] 4. CRS运行验收：恢复当前环境的冻结语料与独立持久负载夹具；基线复现、定位兼容/队列/耗时问题，保留失败，先红后绿；独立多节点及断网/重放/原始请求/持久事件验收。
- [ ] 5. 完整性能与开放：资源隔离，正式30分钟与持续内存/落库验证。通过后才开放签名发布，建立本地自有站点观察/阻断/回退实际证据；不向用户业务发布。
- [ ] 6. 固定制品：新Agent发行、对应架构WAF镜像及归档、准确下载；API/Web/Agent/WAF相关回归和页面验收；更新实际交付边界。

当前发现：已有发布API和界面完整，但运行开关关闭；上一轮60秒附加P95 46.065ms未过，旧30分钟也有队列拒绝，不可直接开启。现有Nginx已能由Agent安装流程接入，已有主机仍需手动下载执行计划。当前Docker总资源8CPU/约8GiB且有其他项目，不得停止其他项目来制造验收结果；正式参考资源需要明确记录实际隔离情况。

## 2026-11-04 CentOS连接与持续流量监测
现场：目标20.88.134.141的Agent0.4.14在线且上报成功，平台宿主机和API容器SSH22均超时，非Agent安装失败。已请用户核对目标SSH端口/放行平台IP20.88.127.75。
实现约定：持续监测为显式启停的独立最小权限常驻服务，普通Agent保持非特权；一个socket连续采集，以60秒聚合窗口上报（不作为总运行时长），不存正文/PCAP、不解密TLS。每窗口复用包数、字节、连接数限制并展示丢弃；断网队列有界、序号持久、恢复去重。首次启用通过已核实SSH执行专用服务安装；停止同时写入Agent可轮询的期望状态，不依赖持续SSH。历史默认24小时/每资产最多1440窗口，范围和证据权限沿用资产授权。0.4.14不可覆盖；0.4.15序号46为未发布候选，最终发布0.4.16序号47。有限临时抓包保留为排障次入口。后端、Go采集及前端在冻结报文契约后分别实现，验证并部署到主环境。

现场根因已验证：CentOS 7/kernel3.10开启tcp_tw_recycle=1，平台SYN使TcpExtPAWSPassive连续递增。备份后仅关闭该废弃参数，平台宿主与API容器原有固定主机公钥/凭据探测均成功；未更改防火墙或认证。
持续监测审查修复：正常进程退出保留RUNNING期望、SSH未执行失败与并发停止正确收敛、撤权时独立发送STOPPED且记录被丢弃队列。定向真实DB与Go撤权测试先红后绿；Linux API全套278通过/60跳过/零失败，前端138通过。
2026-11-04 已发布Agent0.4.16全架构八项下载校验，主平台备份及第37项迁移完成，API/Web新镜像上线、HTTPS健康检查通过。目标已按原profile升级0.4.16，普通执行器保持关闭；持续监测服务active/enabled，正在核对连续窗口及重启/停止恢复。

最终现场修复与版本：
- CentOS RPM 4.x 的 gpg-pubkey 伪包无 ARCH/SOURCERPM，不应作为损坏软件包；仅精确跳过合法十六进制密钥/时间戳记录，其他无架构/畸形记录仍拒绝。0.4.17仅本地构建未发布。
- 状态轮询原先给GET发送JSON null，实际平台严格JSON解析返回400；修正为无正文GET，现场对照分别400/200，回归先红后绿。最终发布0.4.18序号49，八项全架构下载摘要校验通过；目标Agent安装SUCCEEDED、批次COMPLETED、packageCollection.complete=true。
- CentOS systemd219对已启用服务的enable --now不立即启动，现场复现inactive；改为分别enable与start，服务契约回归先红后绿。API/UI最低版本统一0.4.18，构建、9项前端定向、4项真实数据库/契约测试通过。Go完整测试、vet与定向race通过。
- 2026-11-04平台最终补丁包SHA256：5fe6e3c225003cacc85fe95eea52637fd82ef0592f9800057f7a787720f42d4a。新API/Web镜像基于原镜像离线叠加已验证公共程序；保留原数据、密钥、CA、权限与旧镜像。HTTPS健康通过，平台全部服务active。
- 0.4.16仍保留，撤销建议被自动审批以未授权且影响回滚拒绝；未重试撤销，也未绕过。持续监测入口最低0.4.18避免使用已知有缺陷版本。
最终验收完成：持续监测dadae7f6-9afe-421b-8daa-56b09622aaba保持RUNNING，eth0按已授权九个端口监测。两个连续60秒窗口分别1009/923包、568/555条流量，complete=true、socketDropped=0、droppedWindows=0；API自动停止确认与重新启用通过。现场记录保存于.artifacts/results/waf-production-nginx/traffic-live-acceptance-final.json及服务器state/traffic-20261104-verified.json，最终备份完成。既有临时抓包仍保留。

2026-11-04 新机器与资产 IP 认领修复：20.88.134.142/kernel3.10.0-514 同样开启tcp_tw_recycle，API容器三次探测期间PAWSPassive从359821增至359827；备份后仅关闭并持久化该参数，真实认证接口已读到eth0/lo，Agent0.4.18保持不变。资产候选仅取外部连接，不把本机监听作为新资产；过滤本机/回环/通配/链路本地/多播/已登记及已核实平台入口地址，规范IPv6与IPv4映射表示。保留端点观察证据，展示按IP合并、IP锁串行认领，忽略合并处理当前授权范围内的该IP。无结构迁移、未删除旧证据或已有资产。9项地址/隔离DB测试、13项含流量回归、隔离HTTP数据安全全流程通过；API/Web构建及前端9项定向通过。补丁SHA256 c318688ab620ed12ae60a7a76c9128385d8c875cfb1e2bd9e39f79fca04abacb 已上线，HTTPS及实际网卡接口验收通过：91个唯一候选IP，其中64个汇总多端口；两台主机监测RUNNING，原监测序号59且上报新鲜。验收记录：.artifacts/results/waf-production-nginx/discovery-ip-live-verified.json 与服务端state/discovery-ip-20261104-verified.json。
