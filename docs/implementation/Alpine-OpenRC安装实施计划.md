# Alpine / OpenRC 安装补齐

依据已确认建设方案阶段五补齐，不把容器进程运行视作真实服务验收。采用项目内现有 Linux 签名制品、安装票据、持久身份和安装事务，增加明确的 OpenRC 服务适配，不调用第三方 Agent。

1. 固定 Alpine 3.23.4 官方 cloud-init 镜像及 Lima v2.2.1 目录中的 SHA512，ARM64 使用独立原生虚拟机；amd64 使用既有受控 QEMU 方法，分别记录功能证据。
2. 仅接受真实 PID1 与服务管理器标记一致的 systemd 或 OpenRC 主机。OpenRC 要求 cgroup v2 的 CPU、内存、进程数控制器可用；不能因资源限制不支持而静默无上限运行。安装前检查，不修改其他主机服务配置或全局 cgroup 策略。
3. systemd 生成内容及默认路径保持现有行为。OpenRC 使用 `/etc/init.d/selfguard-collector` 与独立执行器脚本、`supervise-daemon`、明确用户/组、固定配置路径、有限频率的异常重启，以及专用服务 cgroup。资源值来自已经校验的安装配置；启动后核对实际 cgroup 限制。脚本不插入业务目录、网络地址或票据。
4. 使用现有文件摘要、安装事务、恢复与卸载机制。事务固定服务管理器类型，恢复不能跨类型解释旧服务；保留旧 systemd 日志兼容。未知或被改动的已有服务文件拒绝覆盖。OpenRC 运行目录显式创建，采集器保持独立非特权账号，执行器只在用户明确启用后启动。
5. 先测试管理器识别、固定服务名称、命令参数映射、脚本和资源门槛，再实现。完整 Agent 回归后生成新的签名版本，不覆盖已发布的0.4.0同序列制品。真实主机检查首次安装、重复安装、apk/origin清单、签名修复与独立复核、异常重启、配置启动失败回滚、离线准备及卸载保留历史。
6. 实际通过后才更新安装界面支持说明、操作指南和验收矩阵。OpenRC 与 systemd 的加固机制分别记录；不能宣称所有 systemd 单元指令在 OpenRC 中等价生效。

实现依据：[OpenRC 服务脚本说明](https://github.com/OpenRC/openrc/blob/master/service-script-guide.md)、[进程监护说明](https://github.com/OpenRC/openrc/blob/master/supervise-daemon-guide.md)、[cgroup 实现](https://github.com/OpenRC/openrc/blob/master/sh/rc-cgroup.sh)。上述说明用于设计；仍须核对冻结镜像中的实际 OpenRC 版本和脚本，不能以主分支说明代替真实验收。

2026-11-01 实施进度：服务适配、安装事务、资源限制和内核禁止新增权限已实现。针对性测试及完整 Agent 竞态检查通过（`agent-openrc-targeted-green.log`、`agent-openrc-batch-regression.log`）。签名候选 `0.4.1-rc.1` 仅发布到私有安装测试环境；正式版本仍为 `0.4.0`。既有 Ubuntu 24.04 原生测试机安装候选后，原身份、完整配置、服务单元摘要保持一致，两项服务正常且收到候选版本新心跳（`native-ubuntu24-candidate-result.json`）。这些证据不代表 Alpine 实机验收已通过；冻结镜像校验和 OpenRC 安装闭环仍在进行，不重复执行未受影响的十项 systemd 全矩阵。

2026-11-01 原生闭环补充：真实安装依次定位并修正 `/proc/mounts` 符号链接与安全读取器不兼容、服务脚本覆盖 OpenRC 自带辅助命令路径、缺少 OpenRC 服务清单、`rc-status` 实际位于 `/bin`，以及执行器重启后异步拉起采集器与安装器再次重启竞争的问题。安装器在重启执行器前先停采集器，最后显式启动采集器；原 systemd 调用不变。失败命令保留具体操作和退出错误，未保留诊断输出管道。

候选 `0.4.1-rc.8` 在自有 Alpine 3.23.4 ARM64 通过在线和重复安装、原身份、新鲜227项APK（含origin/版本/架构）与64项OpenRC服务清单、非特权采集/独立root执行器、两进程NoNewPrivileges、实际cgroup限制、签名chmod及独立读取复核、实际SIGKILL后监护恢复和新心跳。受控失败形成的RC7恢复事务也已通过既有恢复入口恢复；两条旧测试PARTIAL授权在新安装验收后显式撤销。证据 `alpine-openrc-result.json` 引用原始阶段日志，保留中途失败，不把分段续验写成一次全流程成功。完整Agent竞态回归16.232秒通过（`agent-openrc-final-batch-regression.log`）。离线证据仍为RC2；最新候选离线、amd64和其余故障场景待后续验收。正式平台仍为0.4.0，未据此宣称所有OpenRC或所有修复模板支持。


2026-11-01 双架构补齐及权限纠正：RC8仅核对进程主线程不足以证明全部Go线程禁止新增权限；amd64实测暴露差异后，改由OpenRC在exec前设置`no_new_privs=yes`，程序仅检查已继承的内核标志，缺失即拒绝启动。针对性测试模拟exec并创建多条运行时线程，完整Agent竞争回归17.731秒通过。RC9在Alpine3.23.4 ARM64和amd64均通过在线/重复安装、真实APK清单、隔离与cgroup、每条存活线程NoNewPrivs、签名chmod独立验证及SIGKILL恢复新心跳（agent-openrc-rc9-arm64-native.log、agent-openrc-rc9-amd64-native.log）。amd64使用软件CPU仿真，仅作功能证明。离线部分分别复用ARM64 RC2、amd64 RC8的实际准备证据，不冒充RC9新离线全流程。RC9仅在私有测试API发布；正式平台0.4.0保持原状。内核依据：[no_new_privs继承语义](https://docs.kernel.org/userspace-api/no_new_privs.html)。


发布收尾：独立签名0.4.1序列32已作为灰度版本加入本地平台下载目录，保留稳定0.4.0默认，不创建业务主机安装或升级任务。两架构源摘要与RC9相同，制品摘要单独记录；两架构原程序与tar.gz/deb/rpm共8项准确下载通过（agent-041-publish-local.log）。0.4.1 ARM64在真实Alpine重复核心安装、修复及监护恢复通过，在代表性Ubuntu24.04保留原身份、完整配置与服务单元准确摘要并收到新心跳（agent-041-alpine-arm64.log、agent-041-systemd.log）。amd64原生核心证据复用同源RC9，不称为0.4.1整个新二进制实机复验；离线证据仍分别注明旧版本。界面与指南补充Alpine工具、版本选择、cgroup前置条件和服务状态模板边界。


开机自启动补证：复用独立WAF参考环境恢复时已经发生的真实Alpine内核开机，不额外再重启。明确核对PID1为init、发行版为Alpine，内核启动时间晚于0.4.1安装证据；两项服务自动启动、所有运行线程NoNewPrivileges、采集器CPU/内存/进程数实际限制、主机持久身份和平台原资产的新心跳均保持（alpine-041-actual-boot-result.json）。此项是ARM64实际开机证据，未据此宣称amd64已重新执行同项验收。
