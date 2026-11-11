import {useEffect,useState} from 'react';
import {Alert,Button,Select,Typography} from 'antd';
import {api} from './api';
import {ModuleSection,ModuleToolbar} from './ModuleSection';
type Action='CHECK'|'INSTALL'|'STOP';
type Job={id:string;status:'QUEUED'|'RUNNING'|'SUCCEEDED'|'FAILED'|'UNKNOWN';action:Action;detail:string;createdAt:string;updatedAt:string};
type Deployment={job:Job|null;readiness:{state:'READY'|'WAITING'|'STALE'|'DISABLED'|'UNCONFIGURED'|'ERROR';message:string};interfaces?:string[]};
export function probeJobLabel(status:Job['status'],action:Action){
 if(status==='QUEUED')return '任务排队中';
 if(status==='RUNNING')return action==='CHECK'?'正在检查环境':action==='STOP'?'正在停止服务':'正在安装并启动';
 if(status==='SUCCEEDED')return action==='INSTALL'?'安装启动命令完成，等待心跳验证':action==='STOP'?'停止命令完成':'环境检查完成';
 return status==='FAILED'?'远程操作失败':'操作结果待核对';
}
export function ProbeDeploymentControls({enabled,busy,installReady=true,onAction}:{enabled:boolean;busy:boolean;installReady?:boolean;onAction:(action:Action)=>void}){return <ModuleToolbar><Button disabled={busy} onClick={()=>onAction('CHECK')}>检查环境</Button><Button type="primary" disabled={busy||!enabled||!installReady} onClick={()=>onAction('INSTALL')}>安装并启动</Button><Button danger disabled={busy} onClick={()=>onAction('STOP')}>停止服务</Button></ModuleToolbar>}
export function ProbeDeploymentPanel({kind,source,onClose}:{kind:'NETWORK'|'ACCESS';source:{id:string;name:string;assetId:string;enabled:boolean;interface?:string};onClose:()=>void}){
 const[data,setData]=useState<Deployment>(),[error,setError]=useState(''),[busy,setBusy]=useState(false),[interfaces,setInterfaces]=useState<string[]>([]),[networkInterface,setNetworkInterface]=useState<string>();
 const path='/probe-deployments?'+new URLSearchParams({kind,sourceId:source.id});
 useEffect(()=>{let active=true;const refresh=()=>{api(path).then((result:Deployment)=>{if(active){setError('');setData(result);if(result.interfaces)setInterfaces(result.interfaces)}}).catch((e:Error)=>{if(active)setError(e.message)})};refresh();const timer=setInterval(refresh,3000);return()=>{active=false;clearInterval(timer)}},[path]);
 async function action(action:Action){setBusy(true);setError('');try{const job:Job=await api('/probe-deployments',{kind,sourceId:source.id,action,...(kind==='NETWORK'&&action==='INSTALL'?{interface:networkInterface}:{})});setData(current=>({job,readiness:current?.readiness||{state:'WAITING',message:'等待远程任务与真实上报'}}))}catch(e){setError((e as Error).message)}finally{setBusy(false)}}
 async function inspectInterfaces(){setBusy(true);setError('');try{const result:{interfaces:string[]}=await api('/asset-remote/'+source.assetId+'/probe',{});setInterfaces(result.interfaces);setNetworkInterface(undefined)}catch(e){setError((e as Error).message)}finally{setBusy(false)}}
 const running=busy||data?.job?.status==='QUEUED'||data?.job?.status==='RUNNING';
 return <ModuleSection modal title={'远程探针 · '+source.name} onClose={onClose} error={error}><Alert type="info" showIcon message="使用此来源绑定主机已保存的 SSH 连接" description="先在资产管理配置远程连接，再检查环境。需要受支持的 Linux、服务管理器及安装权限；缺失依赖、运行时或进程观察条件会明确报错。不会自动扩大采集授权。"/>{!source.enabled&&<Alert type="warning" message="来源授权未启用：允许检查和停止，安装前请返回来源启用授权。"/>}{kind==='NETWORK'&&<Alert type="info" message="未配置并加载已批准的检测规则时，仅提供协议采集，不能视为入侵检测就绪。"/>}{kind==='NETWORK'&&<ModuleToolbar><Button disabled={running} onClick={()=>void inspectInterfaces()}>读取主机网卡</Button><Select aria-label="远程探针监控网卡" placeholder="选择已授权网卡" style={{minWidth:200}} value={networkInterface} onChange={setNetworkInterface} disabled={running} options={interfaces.map(value=>({value,label:value}))}/></ModuleToolbar>}{kind==='ACCESS'&&<Typography.Text>使用来源已授权的接口与业务端点；不会更改端口或进程观察范围。</Typography.Text>}<ProbeDeploymentControls enabled={source.enabled} busy={!!running} installReady={kind==='ACCESS'||!!networkInterface} onAction={next=>void action(next)}/>{data?.job&&<Alert showIcon type={data.job.status==='FAILED'?'error':'info'} message={probeJobLabel(data.job.status,data.job.action)} description={data.job.detail}/>}<Alert showIcon type={data?.readiness.state==='READY'?'success':'info'} message="真实采集状态" description={data?.readiness.message||'正在读取；远程命令完成不代表探针已验证。'}/><Typography.Text type="secondary">没有业务流量时可以没有新事件。以心跳、引擎统计或配置确认判断运行状态；访问覆盖仍需核对真实获准请求。停止服务与撤销来源授权是两个独立操作。</Typography.Text><details><summary>高级：手动接入</summary>可关闭此窗口，使用来源的下载配置入口自行部署。重新签发配置会轮换凭据，需要同步更新主机配置。</details></ModuleSection>;
}
