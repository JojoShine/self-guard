import {useEffect,useRef,useState} from 'react';
import {Alert,Button,Pagination,Skeleton,Tabs,Tooltip} from 'antd';
import {ArrowRightOutlined,CheckCircleOutlined,CloudServerOutlined,InfoCircleOutlined,ReloadOutlined} from '@ant-design/icons';
import {api} from './api';
import {formatTime} from './presentation';
import {BusinessBarChart,DistributionBars} from './DashboardCharts';
import './dashboard.css';
import {StatusTag} from './ModuleSection';

type WorkItem={id:string;version?:string;startedAt?:string;stats?:Record<string,number>;siteId?:string;ruleId?:string;action?:string;timestamp?:string;kind?:string;title?:string;hostname?:string;business?:string;status?:string;lastSeen?:string|null;archivedAt?:string|null;dueAt?:string|null;assetId?:string|null};
type WorkGroup={count:number;items:WorkItem[]};
type Workload={generatedAt:string;timezone:string;freshnessSeconds:number;sampleLimit:number;assets:{online:number;stale:number;neverSeen:number;archived:number};personal:{assignedFindings:WorkGroup;overdueFindings:WorkGroup;myTasks:WorkGroup;approvals:WorkGroup&{eligible:boolean}};pendingVerification:{findings:number;tasks:number};repairOutcomes:{succeeded:number;failed:number;rolledBack:number};businesses:{business:string;assets:number;openRisks:number}[]};
const tabDefinitions=[{key:'approvals',field:'approvals',label:'待我审批',resource:'tasks'},{key:'myTasks',field:'myTasks',label:'我的任务',resource:'tasks'},{key:'assigned',field:'assignedFindings',label:'分派给我',resource:'findings'},{key:'overdue',field:'overdueFindings',label:'已逾期',resource:'findings'}] as const;

export function WorkloadPanel({onOpen,onMetric,updatedAt}:{onOpen?:(record:WorkItem,resource:string)=>void;onMetric:(group:string,title:string,business?:string)=>void;updatedAt?:string}){
 const[data,setData]=useState<Workload>(),[loading,setLoading]=useState(true),[error,setError]=useState(''),[activeKey,setActiveKey]=useState('approvals'),[businessPage,setBusinessPage]=useState(1);
 const initialized=useRef(false),request=useRef(0);
 async function refresh(){const ticket=++request.current;setLoading(true);setError('');try{const next:Workload=await api('/workload');if(ticket!==request.current)return;setData(next);if(!initialized.current){setActiveKey(tabDefinitions.find(tab=>next.personal[tab.field].count>0)?.key||'approvals');initialized.current=true;}}catch(e){if(ticket===request.current)setError((e as Error).message);}finally{if(ticket===request.current)setLoading(false);}}
 useEffect(()=>{void refresh();return()=>{request.current++};},[updatedAt]);
 const open=onMetric;
 const active=tabDefinitions.find(tab=>tab.key===activeKey)||tabDefinitions[0],group=data?.personal[active.field];
 const assets=data?[
  {key:'online',label:'心跳在线',value:data.assets.online,tone:'success'},
  {key:'stale',label:'心跳超时',value:data.assets.stale,tone:'warning'},
  {key:'neverSeen',label:'从未上报',value:data.assets.neverSeen,tone:'cyan'},
  {key:'archived',label:'已归档',value:data.assets.archived,tone:'violet'},
 ]:[];
 const outcomes=data?[
  {key:'succeeded',label:'验证通过',value:data.repairOutcomes.succeeded,tone:'success'},
  {key:'failed',label:'执行失败',value:data.repairOutcomes.failed,tone:'danger'},
  {key:'rolledBack',label:'已验证回滚',value:data.repairOutcomes.rolledBack,tone:'warning'},
 ]:[];
 const currentBusinessPage=Math.min(businessPage,Math.max(1,Math.ceil((data?.businesses.length||0)/5)));
 const placeholder=<div className="dash-card-body workload-chart-body">{loading?<Skeleton active title={false} paragraph={{rows:4}}/>:<div className="workload-empty">未取得数据，请刷新重试</div>}</div>;
 return <div className="workload-root" aria-label="个人工作与资产状态">
  {error&&<Alert type="error" showIcon message={error} description={data?'当前保留上次读取结果，可刷新重试。':undefined} action={<Button size="small" onClick={()=>void refresh()}>重试</Button>}/>}
  <div className="workload-grid">
   <section className="dash-card workload-card workload-tasks" aria-label="我的工作">
    <header className="dash-card-header"><h2>我的工作 <Tooltip title={data?'按当前授权范围与审批策略统计，更新于 '+formatTime(data.generatedAt):'按当前授权范围与审批策略统计'}><InfoCircleOutlined className="dash-help-icon"/></Tooltip></h2><Tooltip title="刷新个人工作台"><Button type="text" size="small" icon={<ReloadOutlined spin={loading}/>} aria-label="刷新个人工作台" onClick={()=>void refresh()}/></Tooltip></header>
    {!data?placeholder:<>
     <Tabs className="workload-tabs" activeKey={activeKey} onChange={setActiveKey} items={tabDefinitions.map(tab=>({key:tab.key,label:<span>{tab.label}<span className={'workload-tab-count'+(tab.key==='overdue'&&data.personal[tab.field].count>0?' workload-tab-count--warning':'')}>{data.personal[tab.field].count}</span></span>}))}/>
     <div className="workload-task-list" aria-busy={loading}>
      {group?.items.length?group.items.map(item=><div className="workload-task-row" key={item.id}>
       <div className="workload-row-copy"><Button type="text" className="dash-record-title" title={item.title} disabled={!onOpen} onClick={()=>onOpen?.(item,active.resource)}>{item.title||'未命名记录'}</Button><span className="workload-row-note">{item.dueAt?'到期 '+formatTime(item.dueAt):active.resource==='tasks'?'受控修复任务':item.kind==='ALERT'?'安全告警':'风险发现'}</span></div>
       <StatusTag value={item.status}/>
      </div>):<div className="workload-empty"><CheckCircleOutlined/><span>{active.key==='approvals'&&!data.personal.approvals.eligible?'当前角色无需处理审批':'当前没有'+active.label+'的记录'}</span></div>}
     </div>
     <footer className="dash-card-footer"><span>{group?.items.length?'显示 1–'+group.items.length+' 条，共 '+group.count+' 条':'暂无待办'}</span><Button className="dash-text-action" type="text" onClick={()=>open(active.key,active.label)}>查看全部 <ArrowRightOutlined/></Button></footer>
    </>}
   </section>
   <section className="dash-card workload-card workload-health" aria-label="资产状态">
    <header className="dash-card-header"><h2><CloudServerOutlined/> 资产状态</h2><Tooltip title={'未归档资产最近'+(data?.freshnessSeconds||90)+'秒收到心跳记为在线；条形长度表示占当前授权资产的比例。'}><InfoCircleOutlined className="dash-help-icon"/></Tooltip></header>
    {!data?placeholder:<><div className="workload-chart-body"><DistributionBars items={assets} basis="total" label="资产状态数量分布" onSelect={key=>open(key,assets.find(item=>item.key===key)!.label)}/></div>
     <div className="workload-verification"><span className="workload-verification-label"><CheckCircleOutlined/> 待验证</span><div><Button type="link" onClick={()=>open('verifyFindings','待验证发现')}>发现 <strong>{data.pendingVerification.findings}</strong></Button><Button type="link" onClick={()=>open('verifyTasks','待验证任务')}>任务 <strong>{data.pendingVerification.tasks}</strong></Button></div></div>
    </>}
   </section>
   <section className="dash-card workload-card workload-business" aria-label="业务风险分布">
    <header className="dash-card-header"><h2>业务风险分布</h2><Tooltip title="仅统计未归档资产及其待处理风险，不包含已接受、已关闭和误报风险。点击柱形或数量进入对应模块。"><InfoCircleOutlined className="dash-help-icon"/></Tooltip></header>
    {!data?placeholder:<><div className="workload-chart-body"><BusinessBarChart rows={data.businesses.slice((currentBusinessPage-1)*5,currentBusinessPage*5)} onSelect={(target,business)=>open(target,business+' · '+(target==='businessAssets'?'未归档资产':'待处理风险'),business)}/></div>
     <footer className="dash-card-footer"><span>{data.businesses.length} 个授权业务分组</span><Pagination size="small" current={currentBusinessPage} pageSize={5} total={data.businesses.length} hideOnSinglePage showSizeChanger={false} onChange={setBusinessPage}/><Button type="link" className="dash-text-action" href="#business">业务管理 <ArrowRightOutlined/></Button></footer>
    </>}
   </section>
   <section className="dash-card workload-card workload-outcomes" aria-label="修复结果">
    <header className="dash-card-header"><h2>修复结果</h2><Tooltip title="按原始修复任务当前状态累计，独立读取复测与回滚子任务不重复计数；条形按数量比较。"><InfoCircleOutlined className="dash-help-icon"/></Tooltip></header>
    {!data?placeholder:<><div className="workload-chart-body"><DistributionBars items={outcomes} label="修复结果数量分布" onSelect={key=>open(key,outcomes.find(item=>item.key===key)!.label)}/></div><footer className="dash-card-footer"><span>点击柱形或数量进入任务列表</span><Button type="link" href="#tasks" className="dash-text-action">全部任务 <ArrowRightOutlined/></Button></footer></>}
   </section>
  </div>
 </div>;
}
