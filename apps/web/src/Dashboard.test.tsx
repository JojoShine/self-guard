import {describe,it,expect,vi} from 'vitest';
import React from 'react';
import {renderToStaticMarkup} from 'react-dom/server';
vi.stubGlobal('sessionStorage',{getItem:()=>null,setItem:vi.fn(),removeItem:vi.fn()});
const {Dashboard}=await import('./Dashboard');
const overview={assets:129,risks:157,alerts:20,pendingTasks:27,criticalRisks:2,incidents:23,wafEvents:6,wafBlocked:4,updatedAt:'2026-10-31T00:00:00Z',wafTraffic:{nodes:2,totalRequests:1200,blockedRequests:4,observedRequests:8,upstreamErrors:1,basis:'真实节点进程累计统计'},recent:[{id:'fixture',title:'配置权限待核对',severity:'HIGH',status:'UNKNOWN',source:'correlation',updatedAt:'2026-10-31T00:00:00Z',evidence:'PRIVATE-DASHBOARD-EVIDENCE',parameters:{private:'PRIVATE-DASHBOARD-PARAMETERS'}}]};
describe('compact security dashboard',()=>{
 it('retains the eight exact metric groups and real WAF node counter links',()=>{
  const html=renderToStaticMarkup(<Dashboard overview={overview} onOpen={()=>{}} onMetric={()=>{}}/>);
  for(const group of ['overviewAssets','overviewRisks','overviewAlerts','overviewTasks','overviewCritical','overviewIncidents','wafEvents','wafBlocked'])expect(html).toContain('data-metric-group="'+group+'"');
  expect((html.match(/data-metric-group=/g)||[]).length).toBe(8);
  expect((html.match(/dash-card workload-card /g)||[]).length).toBe(4);
  for(const label of ['安全运营趋势','业务风险分布','修复结果','我的工作','资产状态','最近发现','请求总量','观察命中','上游错误','结果待确认','关联检测'])expect(html).toContain(label);
  expect(html).toContain('href="#findings"');expect(html).not.toContain('href="#discoveries"');
  expect(html).toContain('1,200');expect(html).not.toContain('PRIVATE-DASHBOARD');
 });
 it('escapes source titles and renders only the recent-record metadata',()=>{
  const html=renderToStaticMarkup(<Dashboard overview={{...overview,recent:[{...overview.recent[0],title:'<img src=x onerror=alert(1)>'}]}} onOpen={()=>{}} onMetric={()=>{}}/>);
  expect(html).toContain('&lt;img src=x onerror=alert(1)&gt;');expect(html).not.toContain('<img src=x');expect(html).not.toContain('PRIVATE-DASHBOARD');
 });
 it('keeps an empty recent feed compact and does not invent missing WAF readings',()=>{
  const html=renderToStaticMarkup(<Dashboard overview={{...overview,recent:[],wafTraffic:undefined}} onOpen={()=>{}} onMetric={()=>{}}/>);
  expect(html).toContain('暂无发现记录');expect(html).toContain('最近 0 条授权记录');
  expect(html).toContain('请求总量</span><strong>—</strong>');
 });
});
