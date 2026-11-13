import {describe,it,expect,vi} from 'vitest';
vi.mock('./api',()=>({api:vi.fn()}));
import {renderToStaticMarkup} from 'react-dom/server';
import {Dashboard,loadCoreOverview} from './Dashboard';
const overview={assets:12,instances:3,networkRisks:4,networkAlerts:5,dataAlerts:6,accesses:7,updatedAt:'2026-11-06T00:00:00Z',recent:[{id:'one',kind:'RISK',title:'<img src=x onerror=alert(1)>',severity:'HIGH',status:'OPEN',securityDomain:'NETWORK',source:'vulnerability',updatedAt:'2026-11-06T00:00:00Z',evidence:'PRIVATE-DASHBOARD'}]};
describe('core security dashboard',()=>{
 it('shows the core metrics and no workflow or WAF operations',()=>{const html=renderToStaticMarkup(<Dashboard overview={overview} onOpen={()=>{}} onMetric={()=>{}}/>);for(const label of ['主机资产','数据实例','漏洞与配置风险','网络告警','数据告警','访问记录'])expect(html).toContain(label);for(const label of ['WAF','待我审批','修复结果','我的任务','未结案调查'])expect(html).not.toContain(label);expect(html).not.toContain('PRIVATE-DASHBOARD');expect(html).toContain('&lt;img');expect(html).not.toContain('<img src=x');});
 it('offers a short path from collection to evidence and keeps asset totals secondary',()=>{const html=renderToStaticMarkup(<Dashboard overview={overview} onOpen={()=>{}} onMetric={()=>{}}/>);expect((html.match(/class="core-entry-card"/g)||[])).toHaveLength(3);for(const route of ['enroll','network-hosts','network-alerts'])expect(html).toContain('href="#'+route+'"');expect(html.indexOf('需要关注')).toBeLessThan(html.indexOf('当前管理范围'));});
 it('queries scoped lists without querying legacy WAF or workflow summaries',async()=>{const request=vi.fn(async(path:string)=>({total:2,items:path.includes('/findings?')?[overview.recent[0]]:[]}));const result=await loadCoreOverview(request);expect(result.instances).toBe(2);expect(result.recent).toHaveLength(1);const paths=request.mock.calls.map(([path])=>path);expect(paths).toHaveLength(6);expect(paths.some(path=>path.includes('securityDomain=NETWORK')&&path.includes('kind=ALERT'))).toBe(true);expect(paths.some(path=>path.includes('securityDomain=DATA')&&path.includes('kind=ALERT'))).toBe(true);expect(paths.some(path=>/waf|overview|workload|tasks/.test(path))).toBe(false);});
 it('fails visibly rather than inventing zero readings',async()=>{await expect(loadCoreOverview(async()=>{throw Error('授权已失效')})).rejects.toThrow('授权已失效');const html=renderToStaticMarkup(<Dashboard overview={{...overview,recent:[]}} onOpen={()=>{}} onMetric={()=>{}}/>);expect(html).toContain('暂无待确认问题');});
});

it('counts only unconfirmed records and links to exactly that state',async()=>{
 const paths:string[]=[];
 await loadCoreOverview(async path=>{paths.push(path);return {total:2,items:[]}});
 const problems=paths.filter(path=>path.startsWith('/findings?'));
 expect(problems).toHaveLength(3);
 for(const path of problems)expect(new URLSearchParams(path.split('?')[1]).get('status')).toBe('OPEN');
 const html=renderToStaticMarkup(<Dashboard overview={{...overview,assets:0,instances:0,recent:[]}} onOpen={()=>{}} onMetric={()=>{}}/>);
 expect(html).toContain('href="#enroll"');
 expect(html).toContain('没有待确认记录不代表已完成安全检查');
 expect(html.indexOf('待确认')).toBeLessThan(html.indexOf('主机资产'));
});

it('shows collection readiness for public browsing as well',()=>{const html=renderToStaticMarkup(<Dashboard demo overview={overview} onOpen={()=>{}} onMetric={()=>{}}/>);expect(html).toContain('采集');expect(html).toContain('核查');expect(html).toContain('采集与检查覆盖');});
