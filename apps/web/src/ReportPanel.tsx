import {paginationDefaults,pageWithinTotal} from './pagination';
import {DateField} from './DateField';
import {useEffect,useRef,useState} from 'react';
import {Alert,Button,Col,Form,Row,Empty,Spin,Statistic,Table,Typography} from 'antd';
import {BusinessSelect} from './BusinessSelect';
import {api} from './api';
import {ModuleSection,ModuleToolbar} from './ModuleSection';

type Report={generatedAt:string;timezone:string;basis:string;filters:{from:string;to:string;business:string|null};totals:Record<string,number>;personal:Record<string,number>;repairOutcomes:Record<string,number>;businesses:Record<string,string|number>[];trends:Record<string,string|number>[]};
const metricNames:Record<string,string>={assetsCreated:'新建资产',risksCreated:'新建风险',alertsCreated:'新建告警',openFindings:'当前待处理发现',closedFindings:'当前已关闭 / 已解决发现',tasksCreated:'新建任务',assignedOpenFindings:'分派给我的待处理发现',overdueFindings:'我的逾期发现',myActiveTasks:'我发起的进行中任务',succeeded:'已验证修复成功',failed:'修复失败',rolledBack:'已验证回滚'};
const columns=[{title:'业务',dataIndex:'business'},{title:'新建资产',dataIndex:'assetsCreated'},{title:'新建风险',dataIndex:'risksCreated'},{title:'新建告警',dataIndex:'alertsCreated'},{title:'新建任务',dataIndex:'tasksCreated'}];
const trendColumns=[{title:'创建日期（UTC）',dataIndex:'day'},...columns.slice(1),{title:'上述发现当前已关闭 / 已解决',dataIndex:'closedFindings'}];
function filterLabel(report:Report){return `${report.filters.from} 至 ${report.filters.to}（UTC） · 业务：${report.filters.business||'全部授权业务'}`;}
function escapeHtml(value:unknown){return String(value).replace(/[&<>"']/g,char=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[char]!));}
function printHtml(report:Report){
  const table=(headers:string[],rows:unknown[][])=>`<table><thead><tr>${headers.map(h=>`<th>${escapeHtml(h)}</th>`).join('')}</tr></thead><tbody>${rows.map(row=>`<tr>${row.map(cell=>`<td>${escapeHtml(cell)}</td>`).join('')}</tr>`).join('')}</tbody></table>`;
  const metrics=Object.entries({...report.totals,...report.personal,...report.repairOutcomes}).map(([key,value])=>[metricNames[key]||key,value]);
  return `<!doctype html><html lang="zh-CN"><meta charset="utf-8"><title>安全运营报告</title><style>body{font:14px/1.6 system-ui,sans-serif;max-width:1100px;margin:40px auto;color:#171717}h1{font-size:28px}h2{margin-top:28px;font-size:18px}table{width:100%;border-collapse:collapse;margin:12px 0}th,td{text-align:left;padding:7px 10px;border:1px solid #ddd}th{background:#f6f6f6}p{color:#555}@media print{body{margin:0;max-width:none;font-size:10pt}thead{display:table-header-group}tr{break-inside:avoid}h2{break-after:avoid}}</style><body><h1>安全运营报告</h1><p>${escapeHtml(filterLabel(report))}</p><p>生成时间：${escapeHtml(report.generatedAt)}（UTC） · 仅当前授权范围</p><p>${escapeHtml(report.basis)}</p><h2>统计与个人工作</h2>${table(['指标','数量'],metrics)}<h2>业务分布</h2>${table(columns.map(c=>c.title),report.businesses.map(row=>columns.map(c=>row[c.dataIndex])))}<h2>创建日期趋势</h2>${table(trendColumns.map(c=>c.title),report.trends.map(row=>trendColumns.map(c=>row[c.dataIndex])))}</body></html>`;
}
function csv(report:Report){
  const rows:unknown[][]=[['section','business','day','metric','count','from_utc','to_utc','business_filter','generated_at_utc']];
  const add=(section:string,business:string,day:string,metric:string,count:unknown)=>rows.push([section,business,day,metric,count,report.filters.from,report.filters.to,report.filters.business||'',report.generatedAt]);
  for(const section of ['totals','personal','repairOutcomes'] as const)for(const [metric,count]of Object.entries(report[section]))add(section,'','',metric,count);
  for(const row of report.businesses)for(const metric of ['assetsCreated','risksCreated','alertsCreated','tasksCreated'])add('businesses',String(row.business),'',metric,row[metric]);
  for(const row of report.trends)for(const metric of ['assetsCreated','risksCreated','alertsCreated','tasksCreated','closedFindings'])add('trends','',String(row.day),metric,row[metric]);
  const cell=(value:unknown)=>{let text=String(value??'');if(/^[=+\-@\t\r]/.test(text))text="'"+text;return '"'+text.replace(/"/g,'""')+'"';};
  return '\uFEFF'+rows.map(row=>row.map(cell).join(',')).join('\r\n');
}
function download(report:Report,format:'json'|'csv'|'html'){
  const content=format==='json'?JSON.stringify(report,null,2):format==='csv'?csv(report):printHtml(report);
  const type=format==='json'?'application/json':format==='csv'?'text/csv;charset=utf-8':'text/html;charset=utf-8';
  const url=URL.createObjectURL(new Blob([content],{type}));const link=document.createElement('a');link.href=url;link.download=`selfguard-report-${report.filters.from}-${report.filters.to}.${format}`;link.click();setTimeout(()=>URL.revokeObjectURL(url),1000);
}

export function ReportPanel(){
  const[form]=Form.useForm();const[data,setData]=useState<Report>(),[loading,setLoading]=useState(false),[error,setError]=useState('');
  const request=useRef(0),appliedFilters=useRef('');
  const[businessPage,setBusinessPage]=useState({current:1,pageSize:paginationDefaults.defaultPageSize}),[trendPage,setTrendPage]=useState({current:1,pageSize:paginationDefaults.defaultPageSize});
  const today=new Date().toISOString().slice(0,10),defaults={from:new Date(Date.parse(today)-29*86400000).toISOString().slice(0,10),to:today,business:undefined};
  async function generate(values:{from:string;to:string;business?:string}){
    const ticket=++request.current;setLoading(true);setError('');
    try{
      const query=new URLSearchParams({from:values.from,to:values.to,...(values.business?{business:values.business}:{})});
      const filters=JSON.stringify([values.from,values.to,values.business||'']);
      const result=await api('/reports/detailed?'+query);if(ticket!==request.current)return;
      const changed=filters!==appliedFilters.current;
      setBusinessPage(previous=>({...previous,current:changed?1:pageWithinTotal(previous.current,result.businesses.length,previous.pageSize)}));
      setTrendPage(previous=>({...previous,current:changed?1:pageWithinTotal(previous.current,result.trends.length,previous.pageSize)}));
      appliedFilters.current=filters;
      setData(result);
    }catch(e){if(ticket===request.current)setError((e as Error).message);}finally{if(ticket===request.current)setLoading(false);}
  }
  useEffect(()=>{void generate(defaults);return()=>{request.current++;};},[]);
  return <div className="module-stack" aria-label="筛选与导出安全报告">
    <ModuleSection title="报告筛选" description="按日期与业务生成当前授权范围的安全运营报告。">
    <Form form={form} layout="vertical" className="module-form-grid" initialValues={defaults} onFinish={values=>void generate(values)}>
      <Form.Item name="from" label="开始日期（UTC）" rules={[{required:true}]} extra="统计从所选日期的 UTC 零时开始；与结束日期共同定义报告数据范围。"><DateField/></Form.Item>
      <Form.Item name="to" label="结束日期（UTC）" rules={[{required:true}]} extra="统计包含所选日期的 UTC 当天，需不早于开始日期。"><DateField/></Form.Item>
      <Form.Item name="business" label="业务名称" extra="查找并选择已有业务分组；清空后统计全部授权业务。选择业务不会扩大账号权限，修改后需重新生成报告。"><BusinessSelect/></Form.Item>
      <Form.Item label=" "><Button type="primary" htmlType="submit" loading={loading}>生成筛选报告</Button></Form.Item>
    </Form>
    </ModuleSection>
    {error&&<Alert type="error" showIcon message={error} description={data?'下方仍为上次成功生成的报告；导出与打印使用下方已应用的筛选。':undefined} />}
    <Spin spinning={loading}><div className="module-stack">{!data&&!loading&&<Empty description="暂无已生成报告，请选择筛选后生成"/>}{data&&<>
      <ModuleSection title="已生成报告" description="导出与打印使用以下已应用条件。">
      <Typography.Paragraph strong>已应用：{filterLabel(data)}</Typography.Paragraph>
      <Typography.Paragraph type="secondary">生成时间：{new Date(data.generatedAt).toLocaleString()}（{Intl.DateTimeFormat().resolvedOptions().timeZone}；接口时间为{data.timezone}）。编辑筛选后请重新生成，下载与打印始终使用这份已生成报告。</Typography.Paragraph>
      <Alert type="info" message={data.basis} style={{marginBottom:16}}/>
      <ModuleToolbar><Button disabled={loading} onClick={()=>download(data,'csv')}>下载筛选报告 CSV</Button><Button disabled={loading} onClick={()=>download(data,'json')}>下载筛选报告 JSON</Button><Button disabled={loading} onClick={()=>download(data,'html')}>下载可打印 HTML</Button><Button disabled={loading} onClick={()=>{const windowRef=window.open('','_blank','width=1100,height=800');if(!windowRef){setError('请允许打开报告窗口后重试打印');return;}windowRef.opener=null;windowRef.document.write(printHtml(data));windowRef.document.close();windowRef.focus();windowRef.print();}}>打印 / 保存为 PDF</Button></ModuleToolbar>
      </ModuleSection>
      <ModuleSection title="安全运营统计">
      <Row gutter={[20,24]}>{Object.entries(data.totals).map(([metric,value])=><Col xs={24} sm={12} lg={8} xxl={4} key={metric}><Statistic title={metricNames[metric]||metric} value={value}/></Col>)}</Row>
      </ModuleSection>
      <ModuleSection title="个人工作与修复结果" description="所选范围内的个人待办与已验证修复结果。">
      <Row gutter={[20,24]}>{Object.entries({...data.personal,...data.repairOutcomes}).map(([metric,value])=><Col xs={24} sm={12} lg={8} xxl={4} key={metric}><Statistic title={metricNames[metric]||metric} value={value}/></Col>)}</Row>
      </ModuleSection>
      <ModuleSection title="业务分布"><Table scroll={{x:700}} locale={{emptyText:"所选范围暂无业务数据"}} rowKey="business" dataSource={data.businesses} columns={columns} pagination={{...paginationDefaults,...businessPage,current:pageWithinTotal(businessPage.current,data.businesses.length,businessPage.pageSize),onChange:(next,size)=>setBusinessPage(previous=>({current:size===previous.pageSize?next:1,pageSize:size}))}}/></ModuleSection>
      <ModuleSection title="创建日期趋势（UTC）"><Table scroll={{x:1000}} locale={{emptyText:"所选范围暂无趋势数据"}} rowKey="day" dataSource={data.trends} columns={trendColumns} pagination={{...paginationDefaults,...trendPage,current:pageWithinTotal(trendPage.current,data.trends.length,trendPage.pageSize),onChange:(next,size)=>setTrendPage(previous=>({current:size===previous.pageSize?next:1,pageSize:size}))}}/></ModuleSection>
    </>}</div></Spin>
  </div>;
}
