import {describe,it,expect} from 'vitest';
import {renderToStaticMarkup} from 'react-dom/server';
import {BusinessBarChart,DistributionBars,TrendPlot} from './DashboardCharts';

describe('dashboard charts use actual counts',()=>{
 it('renders real daily values with accessible data and separates missing observations',()=>{
  const html=renderToStaticMarkup(<TrendPlot rows={[{day:'2026-10-29',findings:8,tasks:4,events:0},{day:'2026-10-30',findings:NaN,tasks:2,events:1},{day:'2026-10-31',findings:0,tasks:0,events:0}]}/>);
  expect(html).toContain('查看每日数据');
  expect(html).toContain('2026-10-29 · 新建发现 8');
  expect(html).toContain('M0.00,0.00  M900.00,200.00');
  expect(html).not.toContain('NaN');expect(html).not.toContain('Infinity');
 });
 it('keeps zero-valued data on the baseline and does not invent readings for an empty response',()=>{
  const zero=renderToStaticMarkup(<TrendPlot rows={[{day:'2026-10-31',findings:0,tasks:0,events:0}]}/>);
  expect(zero).toContain('M450.00,200.00');
  expect(zero).toContain('新建发现 0');
  expect(renderToStaticMarkup(<TrendPlot rows={[]}/>)).toContain('暂无有效趋势数据');
 });
 it('keeps zero bars empty and preserves exact category names and drilldown labels',()=>{
  const business=renderToStaticMarkup(<BusinessBarChart rows={[{business:'业务 <A>',assets:0,openRisks:12}]} onSelect={()=>{}}/>);
  expect(business).toContain('业务 &lt;A&gt; · 待处理风险 12 进入对应模块');
  expect(business).toContain('height:0%');
  const distribution=renderToStaticMarkup(<DistributionBars label="资产状态" basis="total" items={[{key:'online',label:'心跳在线',value:0,tone:'success'},{key:'stale',label:'心跳超时',value:40,tone:'warning'}]} onSelect={()=>{}}/>);
  expect(distribution).toContain('width:0%');expect(distribution).toContain('width:100%');
  expect(distribution).toContain('心跳超时 40 进入对应模块');
 });
});
