import {SecurityReadiness} from './SecurityReadiness';
import {CloudServerOutlined,FileSearchOutlined,DatabaseOutlined,ArrowRightOutlined} from '@ant-design/icons';
import {Button,Empty,Table} from 'antd';
import {SeverityTag} from './ModuleSection';
import {displaySource,formatTime,securityDomainLabels} from './presentation';
import './dashboard.css';

type Finding={id:string;title?:string;kind?:string;severity?:string;status?:string;source?:string;updatedAt?:string;securityDomain?:string};
type ListResult={total:number;items:Finding[]};
export type CoreOverview={assets:number;instances:number;networkRisks:number;networkAlerts:number;dataAlerts:number;accesses:number;recent:Finding[];updatedAt:string};
export async function loadCoreOverview(request:(path:string)=>Promise<ListResult>):Promise<CoreOverview>{
 const [assets,instances,risks,network,data,access]=await Promise.all([
  request('/assets?pageSize=1'),request('/database-instances?pageSize=1'),
  request('/findings?securityDomain=NETWORK&kind=RISK&status=OPEN&pageSize=4&sortBy=updatedAt&order=desc'),
  request('/findings?securityDomain=NETWORK&kind=ALERT&status=OPEN&pageSize=4&sortBy=updatedAt&order=desc'),
  request('/findings?securityDomain=DATA&kind=ALERT&status=OPEN&pageSize=4&sortBy=updatedAt&order=desc'),
  request('/access-observations?pageSize=1'),
 ]);
 const recent=[...new Map([...risks.items,...network.items,...data.items].map(row=>[row.id,row])).values()].sort((a,b)=>(b.updatedAt||'').localeCompare(a.updatedAt||'')).slice(0,8);
 return {assets:assets.total,instances:instances.total,networkRisks:risks.total,networkAlerts:network.total,dataAlerts:data.total,accesses:access.total,recent,updatedAt:new Date().toISOString()};
}
const metrics=[['networkRisks','待确认漏洞与配置风险','overviewNetworkRisks'],['networkAlerts','待确认网络告警','overviewNetworkAlerts'],['dataAlerts','待确认数据告警','overviewDataAlerts']] as const;
export function Dashboard({overview,onOpen,onMetric,demo=false}:{demo?:boolean;overview:CoreOverview;onOpen:(record:Finding,resource:string)=>void;onMetric:(group:string,title:string)=>void}){
 return <div className="dash-root core-dashboard">
  <SecurityReadiness/>
  <section className="core-entry-section" aria-label="需要关注"><h2>需要关注</h2><div className="dash-metrics core-attention-metrics">{metrics.map(([key,label,group])=><Button key={key} type="text" className="dash-metric dash-metric--neutral" onClick={()=>onMetric(group,label)} aria-label={label+' 进入对应模块'}><span className="dash-metric-copy"><span className="dash-metric-label">{label}</span><strong>{overview[key].toLocaleString('zh-CN')}</strong></span></Button>)}</div></section>
  <section className="dash-card dash-recent" aria-label="待确认安全问题"><header className="dash-card-header"><h2>待确认安全问题</h2></header><Table<Finding> size="small" rowKey="id" dataSource={overview.recent} pagination={false} scroll={{x:640}} locale={{emptyText:<Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description="暂无待确认问题；没有待确认记录不代表已完成安全检查，请继续核对采集状态。"/>}} columns={[
   {title:'发现了什么',render:(_,row)=><Button type="link" className="record-title-link" onClick={()=>onOpen(row,'findings')}>{row.title||'未命名记录'}</Button>},
   {title:'领域',dataIndex:'securityDomain',render:(value:string)=>securityDomainLabels[value]||'待分域'},
   {title:'严重程度',dataIndex:'severity',render:(value:string)=><SeverityTag value={value}/>},
   {title:'检测来源',dataIndex:'source',render:displaySource},
   {title:'最近发现',dataIndex:'updatedAt',render:formatTime},
  ]}/><footer className="dash-card-footer">仅统计待确认状态，各类取最近4条、合并展示最多8条。更新于 {formatTime(overview.updatedAt)}</footer></section>
  <section className="core-entry-section" aria-label="接入后这样开始"><h2>接入后这样开始</h2><div className="core-entry-grid core-start-grid">{[
   {href:'enroll',title:'1. 接入采集',description:overview.assets?'已登记主机后，安装 Agent 并确认收到上报。':'先登记主机并安装 Agent，业务分组用于资产归类。',icon:CloudServerOutlined},
   {href:'network-hosts',title:'2. 确认收到数据',description:'选择主机查看连接；数据库和接口访问在数据安全的访问审计查看。',icon:DatabaseOutlined},
   {href:'network-alerts',title:'3. 核查安全问题',description:'从告警进入具体依据；漏洞需先在漏洞扫描创建检查计划。',icon:FileSearchOutlined},
  ].map(({href,title,description,icon:Icon})=><a key={href} className="core-entry-card" href={'#'+href}><span className="core-entry-icon" aria-hidden="true"><Icon/></span><h3>{title}</h3><p>{description}</p><ArrowRightOutlined className="core-entry-arrow" aria-hidden="true"/></a>)}</div></section>
  <section className="dash-card" aria-label="当前管理范围"><header className="dash-card-header"><h2>当前管理范围</h2></header><div className="dash-card-body"><ModuleCounts overview={overview}/><p className="evidence-secondary">登记资产、Agent 上报、流量采集和入侵检测分别确认；没有告警不能证明已经启用检测。</p></div></section>
 </div>;
}
function ModuleCounts({overview}:{overview:CoreOverview}){return <div className="module-toolbar"><Button href="#assets">主机资产 {overview.assets}</Button><Button href="#database-instances">数据实例 {overview.instances}</Button><Button href="#data-access">访问记录 {overview.accesses}</Button></div>}
