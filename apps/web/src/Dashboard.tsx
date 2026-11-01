import {AppstoreOutlined,ArrowRightOutlined,AuditOutlined,BellOutlined,CheckCircleOutlined,CloudServerOutlined,InfoCircleOutlined,SafetyCertificateOutlined,AlertOutlined,FileSearchOutlined,GlobalOutlined,StopOutlined} from '@ant-design/icons';
import {Button,Empty,Table,Tooltip} from 'antd';
import {WorkloadPanel} from './WorkloadPanel';
import {DashboardTrend} from './DashboardTrend';
import {StatusTag,SeverityTag} from './ModuleSection';
import {displaySource,formatTime} from './presentation';
import './dashboard.css';

type Props={overview:any;onOpen:(record:any,resource:string)=>void;onMetric:(group:string,title:string)=>void};
const metrics=[
  {key:'assets',label:'资产总数',group:'overviewAssets',icon:CloudServerOutlined,tone:'neutral'},
  {key:'risks',label:'未关闭风险',group:'overviewRisks',icon:SafetyCertificateOutlined,tone:'danger'},
  {key:'alerts',label:'待处理告警',group:'overviewAlerts',icon:BellOutlined,tone:'warning'},
  {key:'pendingTasks',label:'进行中任务',group:'overviewTasks',icon:AuditOutlined,tone:'primary'},
  {key:'criticalRisks',label:'严重风险',group:'overviewCritical',icon:AlertOutlined,tone:'danger'},
  {key:'incidents',label:'未结案调查',group:'overviewIncidents',icon:FileSearchOutlined,tone:'neutral'},
  {key:'wafEvents',label:'WAF 攻击记录',group:'wafEvents',icon:GlobalOutlined,tone:'primary'},
  {key:'wafBlocked',label:'WAF 阻断记录',group:'wafBlocked',icon:StopOutlined,tone:'warning'},
];
const number=(value:unknown)=>typeof value==='number'&&Number.isFinite(value)?value.toLocaleString('zh-CN'):'—';

export function Dashboard({overview,onOpen,onMetric}:Props){
  const traffic=overview.wafTraffic;
  return <div className="dash-root">
    <section className="dash-metrics" aria-label="安全运营核心指标">
      {metrics.map(({key,label,group,icon:Icon,tone})=><Button key={key} type="text" className={'dash-metric dash-metric--'+tone} data-metric-group={group} onClick={()=>onMetric(group,label)} aria-label={label+' 进入对应模块'}>
        <span className="dash-metric-copy"><span className="dash-metric-label">{label}</span><strong>{number(overview[key])}</strong></span><span className="dash-metric-icon"><Icon/></span>
      </Button>)}
    </section>
    <div className="dash-summary-bar"><Tooltip title="当前授权范围内的记录。风险包含已接受但未关闭的风险；WAF事件为平台已接收的攻击记录。"><span className="dash-updated"><InfoCircleOutlined/> 更新于 {formatTime(overview.updatedAt)}</span></Tooltip></div>
    <WorkloadPanel onOpen={onOpen} onMetric={onMetric} updatedAt={overview.updatedAt}/>
    <div className="dash-analytics-grid">
    <DashboardTrend updatedAt={overview.updatedAt}/>
    <section className="dash-card dash-waf" aria-label="Web防护运行统计">
      <header className="dash-card-header"><h2><SafetyCertificateOutlined/> Web 防护</h2><Tooltip title={traffic?.basis||'最近90秒内上报节点的当前进程累计计数，节点重启后重置。'}><span className="dash-caption">{number(traffic?.nodes)} 个在线节点 <InfoCircleOutlined/></span></Tooltip></header>
      <div className="dash-waf-metrics">{[['totalRequests','请求总量'],['blockedRequests','已阻断'],['observedRequests','观察命中'],['upstreamErrors','上游错误']].map(([key,label])=><Button type="text" key={key} className={'dash-waf-counter'+(key==='upstreamErrors'&&traffic?.[key]>0?' dash-text-danger':'')} onClick={()=>onMetric('wafNodes','在线 WAF 节点累计统计')} aria-label={label+' 进入节点状态'}><span>{label}</span><strong>{number(traffic?.[key])}</strong></Button>)}</div>
      <footer className="dash-card-footer"><span>当前进程累计 · 节点重启后重置</span></footer>
    </section>
    </div>
    <section className="dash-card dash-recent" aria-label="最近发现">
      <header className="dash-card-header"><h2><AppstoreOutlined/> 最近发现</h2><Button type="link" className="dash-text-action" href="#findings">查看全部 <ArrowRightOutlined/></Button></header>
      <Table size="small" rowKey="id" dataSource={overview.recent||[]} pagination={false} scroll={{x:720}} locale={{emptyText:<Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description="暂无发现记录"/>}} columns={[
        {title:'发现名称',key:'title',render:(_:unknown,row:any)=><Button type="text" className="dash-record-title" title={row.title} onClick={()=>onOpen(row,row.kind==='INCIDENT'?'incidents':'findings')}>{row.title||'未命名发现'}</Button>},
        {title:'严重程度',dataIndex:'severity',width:100,render:(value:string)=><SeverityTag value={value}/>},
        {title:'处置状态',dataIndex:'status',width:120,render:(value:string)=><StatusTag value={value}/>},
        {title:'来源',dataIndex:'source',width:120,render:displaySource},
        {title:'最近更新',dataIndex:'updatedAt',width:170,render:(value:string)=><span className="dash-cell-secondary">{formatTime(value)}</span>},
      ]}/>
      <footer className="dash-card-footer"><span>最近 {overview.recent?.length||0} 条授权记录</span><span className="dash-footer-note"><CheckCircleOutlined/> 以实际检测结果为准</span></footer>
    </section>
  </div>;
}
