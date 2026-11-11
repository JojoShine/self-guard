import {it,expect,vi} from 'vitest';vi.mock('./api',()=>({api:vi.fn()}));import {renderToStaticMarkup} from 'react-dom/server';import {ScanPanel,ScanResultContent} from './ScanPanel';
it('explains frozen inventory and actual source evidence without claiming active exploitation',()=>{
 const html=renderToStaticMarkup(<ScanResultContent target={{hostname:'payment-api',assetId:'asset',status:'COMPLETED',inventoryAt:'2026-10-31T10:00:00Z',result:{coverage:{status:'COMPLETED',components:1,notes:[],meaning:'未命中不代表没有其他风险'},findingIds:['finding'],findings:[{identity:'CVE-2026-12345',title:'实际组件漏洞',severity:null,status:'CONFIRMED',evidence:{component:{name:'example',version:'1.0-1',ecosystem:'Debian:12'},actual:'1.0-1',applicability:[{fixed:'2.0-1',actual:'1.0-1',package:'example'}],sources:[{provider:'OSV',externalId:'GHSA-fixture'}],knownExploited:false}}]}}}/>);
 for(const value of ['payment-api','CVE-2026-12345','实际组件漏洞','1.0-1','2.0-1','GHSA-fixture','未评级','本次不发送主动攻击请求'])expect(html).toContain(value);expect(html).not.toContain('成功利用漏洞');
});

it('opens authorized endpoints and replaces brand navigation with the generic rule library',()=>{
 const html=renderToStaticMarkup(<ScanPanel section="settings"/>);expect(html).toContain('检测规则库');expect(html).not.toContain('常用中间件检测');expect(html).toContain('aria-selected="true"');expect(html).toMatch(/aria-selected="true"[^>]*>.*?授权网络目标/);
});
