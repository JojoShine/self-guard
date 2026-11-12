import {z} from 'zod';
import {remoteCaptureInput} from './asset-remote-contract';
import {trafficCaptureInput} from './traffic-capture';
export const monitorStartInput=remoteCaptureInput.pick({interface:true,protocol:true,ports:true,cidrs:true}).strict();
export function monitorCaptureConfig(input:z.infer<typeof monitorStartInput>){return {...input,durationSeconds:60,maxPackets:10000,maxBytes:1048576,snapLen:128 as const,includePayload:false as const,retentionHours:0 as const};}
const monitorSummary=trafficCaptureInput.extend({stopReason:z.enum(['BUDGET_ROLLOVER','WINDOW_ELAPSED','MONITOR_STOPPED','DURATION_ELAPSED','PACKET_LIMIT','BYTE_LIMIT','FLOW_LIMIT','EXAMINATION_LIMIT','WRITE_FAILED','CAPTURE_FAILED']),scope:trafficCaptureInput.shape.scope.extend({includePayload:z.literal(false),snapLen:z.literal(128),retentionHours:z.literal(0)})}).refine(v=>!v.payloadFile&&!v.payloadExpiresAt&&Date.parse(v.endedAt)>=Date.parse(v.startedAt),'监测窗口不能包含正文或无效时间');
export const monitorReportInput=z.object({schema:z.literal('selfguard-traffic-monitor-v1'),monitorId:z.string().uuid(),status:z.enum(['RUNNING','STOPPED','FAILED']),sequence:z.number().int().min(1).max(2147483647),updatedAt:z.string().datetime(),summary:monitorSummary.optional(),detail:z.string().max(500),droppedWindows:z.number().int().min(0).max(2147483647)}).strict();
export const monitorHistoryInput=z.object({page:z.coerce.number().int().min(1).max(100000).default(1),pageSize:z.coerce.number().int().min(1).max(100).default(20),from:z.string().datetime().optional(),to:z.string().datetime().optional()}).strict().refine(v=>!v.from||!v.to||v.from<=v.to,'起始时间不得晚于结束时间');
export function supportsTrafficMonitor(inventory:unknown){const result=z.object({agentDiagnostics:z.object({version:z.string()})}).safeParse(inventory);if(!result.success)return false;const m=/^(\d+)\.(\d+)\.(\d+)$/.exec(result.data.agentDiagnostics.version);return !!m&&(Number(m[1])>0||Number(m[2])>4||Number(m[2])===4&&Number(m[3])>=18);}
export const monitorIdentityCheckScript=`import json,os,sys
try:
 with open(sys.argv[1]) as f: request=json.load(f)
 with open(sys.argv[2]) as f: collector=json.load(f)
 with open(os.path.join(collector["StateDir"],"identity.json")) as f: identity=json.load(f)
except Exception:
 sys.stderr.write("SELFGUARD_MONITOR_FAILED:CONFIG\\n");sys.exit(40)
if not identity.get("token") or identity.get("assetId")!=request.get("assetId"):
 sys.stderr.write("SELFGUARD_MONITOR_FAILED:IDENTITY\\n");sys.exit(41)
`;
export function trafficMonitorDiagnostic(text:string):{detail:string;uncertain:boolean}|undefined{
 const code=/^SELFGUARD_MONITOR_FAILED:(CONFIG|IDENTITY|PRECHECK|SERVICE)\r?$/m.exec(text)?.[1];
 const details:Record<string,string>={CONFIG:'主机 Agent 接入配置或身份文件不可读取，未启用持续监控',IDENTITY:'主机 Agent 绑定的是其他资产或平台，请先在本平台重新接入；未启用持续监控',PRECHECK:'主机缺少启动身份核验所需的 Python 环境，未启用持续监控',SERVICE:'主机持续监控服务启动失败并已停止；请检查实际安装的 Agent 是否支持持续监控，以及主机服务日志'};
 return code?{detail:details[code],uncertain:false}:undefined;
}
export function monitorReportedState<T extends {status:string;detail:string;desiredState:string;createdAt:Date;lastReportAt:Date|null}>(monitor:T,now=Date.now()):T{
 if(monitor.status==='STARTING'&&!monitor.lastReportAt&&now-monitor.createdAt.getTime()>120000)return {...monitor,status:'UNKNOWN',detail:'启动已超过两分钟，仍未收到主机确认；请核对主机监控服务、Agent 绑定的平台及上报连接，当前不能确认正在监控'};
 return monitor;
}
export function monitorServiceCommand(){const script=`set -euo pipefail
umask 077
[ "$(id -u)" = 0 ]
[ -x /opt/selfguard-agent/current ]
base=/etc/selfguard-traffic-monitor
state=/var/lib/selfguard-traffic-monitor
[ ! -L "$base" ] && [ ! -L "$state" ]
mkdir -p "$base" "$state"
[ "$(stat -c %u "$base")" = 0 ] && [ "$(stat -c %u "$state")" = 0 ]
chmod 700 "$base" "$state"
exec 9>/run/selfguard-traffic-monitor.lock
flock -n 9
if systemctl is-active --quiet selfguard-traffic-monitor.service; then printf "Monitor already active; stop it before changing scope" >&2; exit 1; fi
config=$(mktemp "$base/config.XXXXXX")
trap "rm -f $config" EXIT
cat > "$config"
chmod 600 "$config"
python_command=$(command -v python3 || command -v python || true)
if [ -z "$python_command" ]; then printf "SELFGUARD_MONITOR_FAILED:PRECHECK\\n" >&2; exit 40; fi
"$python_command" - "$config" /etc/selfguard-agent/collector.json <<'SELFGUARD_CHECK'
${monitorIdentityCheckScript}
SELFGUARD_CHECK
mv "$config" "$base/config.json"
cat > /etc/systemd/system/selfguard-traffic-monitor.service <<UNIT
[Unit]
Description=Self Guard continuous traffic metadata monitor
After=network-online.target
Wants=network-online.target
[Service]
Type=simple
User=root
ExecStart=/opt/selfguard-agent/current --monitor-traffic /etc/selfguard-traffic-monitor/config.json
Restart=on-failure
RestartSec=10
TimeoutStopSec=90
MemoryLimit=134217728
CPUQuota=10%
Nice=10
Environment=GOMAXPROCS=1 GOMEMLIMIT=96MiB
NoNewPrivileges=true
CapabilityBoundingSet=CAP_NET_RAW CAP_DAC_READ_SEARCH
ProtectSystem=full
ReadOnlyDirectories=/
ReadWriteDirectories=/var/lib/selfguard-traffic-monitor
ProtectHome=true
PrivateTmp=true
[Install]
WantedBy=multi-user.target
UNIT
systemctl daemon-reload
systemctl enable selfguard-traffic-monitor.service >/dev/null
systemctl reset-failed selfguard-traffic-monitor.service
if ! systemctl start selfguard-traffic-monitor.service; then
 systemctl stop selfguard-traffic-monitor.service
 systemctl disable selfguard-traffic-monitor.service >/dev/null
 printf "SELFGUARD_MONITOR_FAILED:SERVICE\\n" >&2
 exit 42
fi
sleep 2
if ! systemctl is-active --quiet selfguard-traffic-monitor.service || [ "$(systemctl show selfguard-traffic-monitor.service -p NRestarts | sed -n "s/^NRestarts=//p")" != 0 ]; then
 systemctl stop selfguard-traffic-monitor.service
 systemctl disable selfguard-traffic-monitor.service >/dev/null
 printf "SELFGUARD_MONITOR_FAILED:SERVICE\\n" >&2
 exit 42
fi
printf "SELFGUARD_MONITOR_STARTED\\n"
`;return "bash -c '"+script.replace(/'/g,"'\\''")+"'";}
