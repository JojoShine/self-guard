import {useEffect,useState} from 'react';
import {Alert,Button,Skeleton} from 'antd';
import {LineChartOutlined,ReloadOutlined} from '@ant-design/icons';
import {api} from './api';
import {TrendPlot,type TrendRow} from './DashboardCharts';

export function DashboardTrend({updatedAt}:{updatedAt?:string}){
 const[data,setData]=useState<{items:TrendRow[];timezone:string}>(),[loading,setLoading]=useState(true),[error,setError]=useState(''),[revision,setRevision]=useState(0);
 useEffect(()=>{let active=true;setLoading(true);setError('');api('/operations/trends').then(result=>{if(active)setData(result)}).catch(e=>{if(active)setError(e.message)}).finally(()=>{if(active)setLoading(false)});return()=>{active=false};},[updatedAt,revision]);
 return <section className="dash-card dash-trend" aria-label="安全运营趋势">
  <header className="dash-card-header"><h2><LineChartOutlined/> 安全运营趋势</h2><div className="dash-trend-controls"><span className="dash-caption">最近30天 · {data?.timezone||'UTC'}</span><Button type="text" size="small" icon={<ReloadOutlined spin={loading}/>} aria-label="刷新趋势" onClick={()=>setRevision(value=>value+1)}/></div></header>
  <div className="dash-card-body" aria-busy={loading}>{error&&<Alert className="dash-trend-feedback" type="error" showIcon message={error} description={data?'当前保留上次成功读取的趋势，可刷新重试。':undefined}/>}{data?<TrendPlot rows={data.items}/>:loading?<Skeleton active paragraph={{rows:5}} title={false}/>:null}</div>
  <footer className="dash-card-footer"><span>按创建日期统计新增数量，仅包含当前授权数据。</span><Button type="link" href="#trends" className="dash-text-action">查看趋势数据</Button></footer>
 </section>;
}
