import {useEffect,useState} from 'react';
import {Alert,Button,Descriptions,Spin,Typography} from 'antd';
import {api} from './api';
import {ModuleSection} from './ModuleSection';
import {formatTime} from './presentation';

export type SecurityReadinessSummary={
 checkedAt:string;windowMinutes:number;
 agents:{registered:number;recent:number;neverReported:number;stale:number};instances:number;
 traffic:{configured:number;enabled:number;reporting:number;recentWindows:number}|null;
 sensors:{configured:number;enabled:number;liveReporting:number;recentEngineStats:number;replay:number}|null;
 access:{configured:number;enabled:number;reporting:number;recentEvents:number}|null;
 nativeAudit:{recentEvents:number}|null;
 scans:{configured:number;enabled:number;recentRuns:number;failedRuns:number}|null;
 handling:{active:number;unassigned:number;verifying:number;overdue:number};
};
export function SecurityReadinessView({summary:s}:{summary:SecurityReadinessSummary}){
 const unavailable='当前权限不提供此项汇总';
 return <div className="module-stack">
  <Typography.Paragraph type="secondary">仅显示当前授权范围。近期上报不代表采集完整；没有告警不代表已经完成检查。近 {s.windowMinutes} 分钟的事件数是已保留记录，不是覆盖率。</Typography.Paragraph>
  <Descriptions bordered size="small" column={1} items={[
   {key:'agents',label:'主机 Agent',children:<>{s.agents.registered?`登记 ${s.agents.registered} 台 · 近90秒上报 ${s.agents.recent} 台 · 从未上报 ${s.agents.neverReported} 台 · 上报过期 ${s.agents.stale} 台`:'尚未接入主机'} <Button type="link" href="#enroll">接入与核对</Button></>},
   {key:'traffic',label:'连接摘要',children:<>{s.traffic?`监控任务 ${s.traffic.configured} 个 · 请求启用 ${s.traffic.enabled} 个 · 近3分钟运行上报 ${s.traffic.reporting} 个 · 近期汇总 ${s.traffic.recentWindows} 条`:unavailable}{s.traffic&&<Button type="link" href="#network-hosts">选择主机确认</Button>}</>},
   {key:'sensors',label:'旁路入侵检测',children:<>{s.sensors?`来源 ${s.sensors.configured} 个 · 已启用 ${s.sensors.enabled} 个 · 近90秒实时上报 ${s.sensors.liveReporting} 个 · 其中近3分钟引擎统计 ${s.sensors.recentEngineStats} 个 · 回放来源 ${s.sensors.replay} 个`:unavailable}{s.sensors&&<Button type="link" href="#network-sensors?view=configuration">核对规则与引擎健康</Button>}</>},
   {key:'access',label:'数据请求与响应',children:<>{s.access?(s.access.configured?`来源 ${s.access.configured} 个 · 已授权启用 ${s.access.enabled} 个 · 近3分钟上报 ${s.access.reporting} 个 · 近期访问 ${s.access.recentEvents} 条`:'尚未配置数据访问来源'):unavailable}{s.access&&<Button type="link" href="#data-access-sources">接入与核对探针</Button>}</>},
   {key:'native',label:'原生数据库审计',children:<>{s.nativeAudit?`登记实例 ${s.instances} 个 · 近期审计 ${s.nativeAudit.recentEvents} 条`:unavailable}{s.nativeAudit&&<Button type="link" href="#database-audit">核对原生审计</Button>}</>},
   {key:'scans',label:'漏洞与网络检查',children:<>{s.scans?(s.scans.configured?`计划 ${s.scans.configured} 个 · 已启用 ${s.scans.enabled} 个 · 近期发起 ${s.scans.recentRuns} 次 · 其中执行失败 ${s.scans.failedRuns} 次`:'尚未配置扫描计划'):unavailable}{s.scans&&<Button type="link" href="#scans">核对范围与运行结果</Button>}</>},
   {key:'handling',label:'问题跟进',children:<>未完成 {s.handling.active} 条 · 未分派 {s.handling.unassigned} 条 · 待复查 {s.handling.verifying} 条 · 已逾期 {s.handling.overdue} 条 <Button type="link" href="#findings">查看处理记录</Button></>},
  ]}/>
  <Typography.Text type="secondary">统计更新于 {formatTime(s.checkedAt)}。请求启用不代表主机已经执行，收到引擎统计不代表规则全部加载成功；请进入对应详情核对配置确认、规则失败、丢包和证据缺口。</Typography.Text>
 </div>;
}
export function SecurityReadiness(){
 const [summary,setSummary]=useState<SecurityReadinessSummary>(),[error,setError]=useState(''),[loading,setLoading]=useState(true),[revision,setRevision]=useState(0);
 useEffect(()=>{let active=true;setLoading(true);setError('');setSummary(undefined);api('/security-readiness').then((value:SecurityReadinessSummary)=>{if(active)setSummary(value)}).catch((e:Error)=>{if(active)setError(e.message)}).finally(()=>{if(active)setLoading(false)});return()=>{active=false}},[revision]);
 return <ModuleSection title="采集与检查覆盖" extra={<Button loading={loading} onClick={()=>setRevision(n=>n+1)}>刷新覆盖状态</Button>}>
  {error?<Alert type="error" showIcon message="无法读取采集覆盖" description={error} action={<Button onClick={()=>setRevision(n=>n+1)}>重试</Button>}/>:loading?<Spin tip="读取采集状态"><div style={{minHeight:80}}/></Spin>:summary?<SecurityReadinessView summary={summary}/>:null}
 </ModuleSection>;
}
