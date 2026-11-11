import {useEffect,useState} from 'react';
import {Alert,Button,Descriptions,Empty,Spin} from 'antd';
import {api} from './api';
import {ModuleSection,ModuleToolbar} from './ModuleSection';
import {RecordSelect} from './RecordSelect';
import {HostNetworkPanel} from './HostNetworkPanel';
import {formatTime} from './presentation';

export type TrafficHost={id:string;hostname:string;ip?:string|null;business?:string|null;lastSeen?:string|null;archivedAt?:string|null;inventory?:unknown};
export function hostTrafficHref(assetId?:string){return '#network-hosts'+(assetId?'?assetId='+encodeURIComponent(assetId):'')}
function selectedHost(){return new URLSearchParams(location.hash.split('?')[1]||'').get('assetId')||undefined}
export function HostCollectionSummary({asset}:{asset:TrafficHost}){
 return <div className="module-stack"><Descriptions size="small" column={{xs:1,md:3}} items={[
  {key:'host',label:'主机',children:asset.hostname},{key:'business',label:'所属业务',children:asset.business||'未分组'},
  {key:'agent',label:'最近 Agent 上报',children:asset.lastSeen?formatTime(asset.lastSeen):'尚未收到 Agent 上报'},
 ]}/><span className="evidence-secondary">Agent 上报只说明主机采集连接；流量采集状态以下方主机确认为准。服务端口和临时排障结果可切换标签查看。</span></div>;
}
export function HostTrafficWorkspace({canManage=false,onAsset,onConfigure}:{canManage?:boolean;onAsset?:(id:string)=>void;onConfigure?:(asset:TrafficHost)=>void}){
 const[assetId,setAssetId]=useState(selectedHost),[asset,setAsset]=useState<TrafficHost>(),[recent,setRecent]=useState<TrafficHost[]>([]),[loading,setLoading]=useState(true),[error,setError]=useState(''),[revision,setRevision]=useState(0);
 const visibleAsset=asset?.id===assetId?asset:undefined;
 useEffect(()=>{const changed=()=>{if(location.hash.split('?')[0]==='#network-hosts')setAssetId(selectedHost())};addEventListener('hashchange',changed);return()=>removeEventListener('hashchange',changed)},[]);
 useEffect(()=>{let active=true;setLoading(true);setError('');setAsset(undefined);setRecent([]);
  const request:Promise<TrafficHost|{items:TrafficHost[]}>=api(assetId?'/assets/'+encodeURIComponent(assetId):'/assets?pageSize=5&sortBy=updatedAt&order=desc');
  request.then(data=>{if(!active)return;if('items' in data)setRecent(data.items);else setAsset(data)}).catch(e=>{if(active)setError((e as Error).message)}).finally(()=>{if(active)setLoading(false)});
  return()=>{active=false};
 },[assetId,revision]);
 function choose(id?:string){setAssetId(id);location.hash=hostTrafficHref(id)}
 return <div className="module-stack">
  <ModuleSection title="选择要查看的主机" description="连接记录来自主机持续采集；协议记录用于查看 HTTP、DNS、TLS 等信息。两种来源独立标记，不重复累计流量。" extra={visibleAsset?<ModuleToolbar>{onAsset&&<Button onClick={()=>onAsset(visibleAsset.id)}>主机详情</Button>}{canManage&&onConfigure&&<Button type="primary" onClick={()=>onConfigure(visibleAsset)}>启停与采集配置</Button>}</ModuleToolbar>:<Button href="#enroll">接入主机与 Agent</Button>}>
   <RecordSelect resource="assets" value={assetId} allowArchived ariaLabel="选择流量主机" placeholder="输入主机名称，查看连接与流量" onChange={(id:string|undefined)=>choose(id)}/>
  </ModuleSection>
  {error?<Alert type="error" showIcon message="读取主机信息失败" description={error} action={<Button onClick={()=>setRevision(value=>value+1)}>重试</Button>}/>:loading?<Spin tip="读取主机信息"><div className="module-stack" style={{minHeight:80}}/></Spin>:visibleAsset?<>
   <HostCollectionSummary asset={visibleAsset}/>
   <HostNetworkPanel key={visibleAsset.id} assetId={visibleAsset.id} inventory={visibleAsset.inventory} onConfigure={canManage&&onConfigure?()=>onConfigure(visibleAsset):undefined}/>
  </>:<ModuleSection title="先确认采集，再查看结果" description="登记资产不会自动开始抓取流量。已安装 Agent 的主机，还需在采集配置中启用持续监控。">
   <div className="module-stack">
    {recent.length?<div className="module-stack"><span>选择已有主机继续：</span><div className="module-toolbar traffic-host-choices">{recent.map(host=><Button key={host.id} onClick={()=>choose(host.id)}>{host.hostname}{host.ip&&!host.hostname.includes(host.ip)?' · '+host.ip:''}</Button>)}</div></div>:<Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description="当前范围没有主机，请先接入资产。"/>}
    <ModuleToolbar><Button href="#enroll">接入主机与 Agent</Button><Button href="#data-access">查看接口与数据库访问</Button></ModuleToolbar>
   </div>
  </ModuleSection>}
 </div>;
}
