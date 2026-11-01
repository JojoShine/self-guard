import {paginationDefaults} from './pagination';
import {Button,Empty,Table} from 'antd';

export type TrendRow={day:string;findings:number;tasks:number;events:number};
const series=[{key:'findings',label:'新建发现',tone:'primary',dash:undefined},{key:'tasks',label:'新建修复任务',tone:'success',dash:'7 4'},{key:'events',label:'WAF 攻击记录',tone:'warning',dash:'2 4'}] as const;
function valid(value:unknown):value is number{return typeof value==='number'&&Number.isFinite(value)&&value>=0;}
function upperBound(values:number[]){const max=Math.max(0,...values);if(max===0)return 4;const raw=max/4,magnitude=10**Math.floor(Math.log10(raw));return Math.max(1,Math.ceil(raw/magnitude)*magnitude)*4;}
const fmt=(value:number)=>value.toLocaleString('zh-CN');

export function TrendPlot({rows}:{rows:TrendRow[]}){
 const values=rows.flatMap(row=>series.map(s=>row[s.key])).filter(valid);
 if(!rows.length||!values.length)return <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description="暂无有效趋势数据"/>;
 const max=upperBound(values),width=900,height=200;
 const x=(index:number)=>rows.length===1?width/2:index*width/(rows.length-1);
 const y=(value:number)=>height-value/max*height;
 const tickIndices=[...new Set([0,Math.floor((rows.length-1)/3),Math.floor((rows.length-1)*2/3),rows.length-1])];
 return <div className="dash-trend-plot">
  <div className="dash-chart-legend">{series.map(s=><span key={s.key}><i className={'chart-swatch chart-swatch--'+s.tone}/>{s.label}</span>)}</div>
  <div className="dash-line-frame"><div className="dash-chart-yaxis">{[max,max*.75,max*.5,max*.25,0].map((n,i)=><span key={i}>{Number(n.toFixed(2))}</span>)}</div><div className="dash-line-content">
   <svg className="dash-line-svg" viewBox={`0 0 ${width} ${height}`} preserveAspectRatio="none" role="img" aria-label="最近30天新增发现、修复任务与WAF攻击记录趋势">
    <title>按创建日期统计，日期为UTC；数据仅含当前授权范围。</title>
    {[0,50,100,150,200].map(n=><line key={n} x1="0" x2={width} y1={n} y2={n} className="dash-chart-gridline" vectorEffect="non-scaling-stroke"/>)}
    {series.map(s=>{let previous=false;const path=rows.map((row,i)=>{const value=row[s.key];if(!valid(value)){previous=false;return '';}const segment=`${previous?'L':'M'}${x(i).toFixed(2)},${y(value).toFixed(2)}`;previous=true;return segment;}).join(' ');return <g key={s.key} className={'dash-line-series chart-tone--'+s.tone}>
     <path d={path} fill="none" stroke="currentColor" strokeWidth="2" strokeDasharray={s.dash} vectorEffect="non-scaling-stroke"/>
     {rows.map((row,i)=>valid(row[s.key])?<circle key={row.day} cx={x(i)} cy={y(row[s.key])} r="3" fill="currentColor"><title>{`${row.day} · ${s.label} ${fmt(row[s.key])}`}</title></circle>:null)}
    </g>;})}
   </svg><div className="dash-chart-xaxis">{tickIndices.map(i=><span key={i}>{rows[i].day.slice(5)}</span>)}</div>
  </div></div>
  <details className="dash-chart-data"><summary>查看每日数据</summary><Table<TrendRow> size="small" rowKey="day" pagination={paginationDefaults} scroll={{x:480}} dataSource={rows} columns={[{title:'日期（UTC）',dataIndex:'day',width:140},...series.map(s=>({title:s.label,dataIndex:s.key,align:'right' as const,render:(value:number)=>valid(value)?fmt(value):'—'}))]}/></details>
 </div>;
}

export type DistributionItem={key:string;label:string;value:number;tone:string};
export function DistributionBars({items,label,onSelect,basis='maximum'}:{items:DistributionItem[];label:string;onSelect:(key:string)=>void;basis?:'maximum'|'total'}){
 const values=items.map(item=>item.value).filter(valid);
 const max=basis==='total'?Math.max(1,values.reduce((sum,value)=>sum+value,0)):Math.max(1,...values);
 return <div className="dash-distribution" role="group" aria-label={label}>{items.map(item=><Button className="dash-bar-row" type="text" key={item.key} aria-label={item.label+' '+fmt(item.value)+' 进入对应模块'} onClick={()=>onSelect(item.key)}>
  <span className="dash-bar-label">{item.label}<strong>{fmt(item.value)}</strong></span><span className="dash-bar-track"><span className={'dash-bar-fill chart-background--'+item.tone} style={{width:(valid(item.value)?Math.min(100,item.value/max*100):0)+'%'}}/></span>
 </Button>)}</div>;
}

export type BusinessRow={business:string;assets:number;openRisks:number};
export function BusinessBarChart({rows,onSelect}:{rows:BusinessRow[];onSelect:(group:string,business:string)=>void}){
 if(!rows.length)return <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description="暂无业务资产"/>;
 const max=upperBound(rows.flatMap(row=>[row.assets,row.openRisks]).filter(valid));
 return <div className="dash-business-chart">
  <div className="dash-chart-legend"><span><i className="chart-swatch chart-swatch--primary"/>未归档资产</span><span><i className="chart-swatch chart-swatch--warning"/>待处理风险</span></div>
  <div className="dash-column-frame"><div className="dash-chart-yaxis">{[max,max*.75,max*.5,max*.25,0].map((n,i)=><span key={i}>{Number(n.toFixed(2))}</span>)}</div><div className="dash-column-plot">
   <div className="dash-column-grid" aria-hidden>{[0,1,2,3,4].map(i=><span key={i}/>)}</div>
   <div className="dash-column-groups" style={{gridTemplateColumns:`repeat(${rows.length},minmax(0,1fr))`}}>{rows.map(row=><div className="dash-column-category" key={row.business}>
    <div className="dash-column-pair">{[{key:'assets',group:'businessAssets',label:'未归档资产',tone:'primary',value:row.assets},{key:'risks',group:'businessRisks',label:'待处理风险',tone:'warning',value:row.openRisks}].map(item=><Button className="dash-column-button" type="text" key={item.key} onClick={()=>onSelect(item.group,row.business)} aria-label={row.business+' · '+item.label+' '+fmt(item.value)+' 进入对应模块'} title={row.business+' · '+item.label+' '+fmt(item.value)}><span className={'dash-column-bar chart-background--'+item.tone} style={{height:(valid(item.value)?Math.min(100,item.value/max*100):0)+'%'}}><span className="dash-column-value">{fmt(item.value)}</span></span></Button>)}</div>
    <span className="dash-column-name" title={row.business}>{row.business}</span>
   </div>)}</div>
  </div></div>
 </div>;
}
