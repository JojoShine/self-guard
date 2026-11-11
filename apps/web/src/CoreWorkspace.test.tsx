import {describe,it,expect,vi} from 'vitest';
import {renderToStaticMarkup} from 'react-dom/server';
import {TopNavigation} from './TopNavigation';
import {CoreModuleTools,RetiredModule,coreWorkspaceHref} from './CoreWorkspace';
describe('core workspaces',()=>{
 it('renders four primary choices and a separate settings control',()=>{const html=renderToStaticMarkup(<TopNavigation page="scans" onNavigate={()=>{}}/>);for(const label of ['概览','资产','网络安全','数据安全','设置'])expect(html).toContain(label);for(const label of ['策略中心','修复中心','报告中心','Web 防护','风险与调查'])expect(html).not.toContain(label);expect(html).not.toContain('section-navigation-row');expect(html).not.toContain('navigation-context');});
 it('makes vulnerability sources and results direct and configuration secondary',()=>{const html=renderToStaticMarkup(<CoreModuleTools page="scans"/>);expect(html).toContain('检查结果');expect(html).toContain('扫描计划');expect(html).toContain('扫描配置');expect(html).not.toContain('waf-rules');});
 it('preserves only applicable observation scope when switching audit views',()=>{const hash='#data-access?instanceId=instance&assetId=host&sourceId=source&recordId=private-record';expect(coreWorkspaceHref('database-audit',hash)).toBe('#database-audit?instanceId=instance');expect(coreWorkspaceHref('data-access-sources',hash)).toBe('#data-access-sources?assetId=host');expect(coreWorkspaceHref('data-access',hash)).toBe('#data-access?assetId=host&instanceId=instance&sourceId=source');});
 it('uses current selected scope instead of an old deep link, including clear',()=>{const hash='#data-access?instanceId=A&assetId=old';expect(coreWorkspaceHref('database-audit',hash,{instanceId:'B'})).toBe('#database-audit?instanceId=B');expect(coreWorkspaceHref('data-access',hash,{})).toBe('#data-access');});
 it('retired modules expose only current destinations',()=>{const html=renderToStaticMarkup(<RetiredModule page="sites"/>);expect(html).toContain('不承担网站实时拦截');expect(html).toContain('#scans');expect(html).not.toContain('创建站点');expect(html).not.toContain('#policies');});
});

it('keeps the selected host when switching connection and protocol evidence',()=>{
 expect(coreWorkspaceHref('network-hosts','#network-sensors?assetId=host&sensorId=engine&flowId=123&view=configuration&recordId=event')).toBe('#network-hosts?assetId=host');
 expect(coreWorkspaceHref('network-sensors','#network-hosts?assetId=host')).toBe('#network-sensors?assetId=host');
 expect(coreWorkspaceHref('network-sensors','#network-hosts?assetId=old',{assetId:'current'})).toBe('#network-sensors?assetId=current');
});
