import {it,expect,vi} from 'vitest';
vi.mock('./api',()=>({api:vi.fn()}));
import {renderToStaticMarkup} from 'react-dom/server';
import {LibraryBulkApprovalButton,LibraryCoverage,ruleLibraryQuery} from './ProbeRuleLibraryPanel';
it('separates official catalog completeness, unsupported rules, runtime readiness and actual findings',()=>{
 const html=renderToStaticMarkup(<LibraryCoverage data={{items:[],total:0,counts:{total:10000,compatible:3000,unsupported:7000},snapshot:{version:'v9',sha256:'snapshot-proof',sourceUrl:'https://github.com/projectdiscovery/nuclei-templates',license:'MIT',licenseSha256:'license-proof'},engine:{ready:false,reason:'引擎不可用'},sync:{status:'FAILED',error:'未完整同步'},canManage:true}}/>);
 for(const text of ['10000','3000','7000','snapshot-proof','license-proof','引擎不可用','未完整同步','不会改变旧计划或自动扫描目标'])expect(html).toContain(text);
 expect(html).not.toContain('全部漏洞检测完成');
});

it('omits unselected strict enum filters from catalog requests',()=>{
 const query=new URLSearchParams(ruleLibraryQuery(2,15,'CVE-2026 & test','',''));
 expect(query.get('q')).toBe('CVE-2026 & test');expect(query.has('status')).toBe(false);expect(query.has('classification')).toBe(false);expect(query.get('page')).toBe('2');
 const filtered=new URLSearchParams(ruleLibraryQuery(1,15,'','compatible','cve'));expect(filtered.get('status')).toBe('compatible');expect(filtered.get('classification')).toBe('cve');
});

it('keeps the verified cached version usable while warning that the latest-version check failed',()=>{
 const html=renderToStaticMarkup(<LibraryCoverage data={{items:[],total:0,counts:{total:10000,compatible:1954,unsupported:8046},snapshot:{version:'v10.5.1',sha256:'verified-archive',sourceUrl:'https://github.com/projectdiscovery/nuclei-templates',license:'MIT',licenseSha256:'verified-license'},engine:{ready:true,version:'3.11.1'},sync:{status:'SUCCEEDED',sourceMode:'VERIFIED_CACHE',usedCachedSource:true,latestCheckFailed:true,refreshError:'OFFICIAL_HTTP_403',refreshAttemptedAt:'2026-11-10T12:00:00Z'},canManage:true}}/>);
 for(const text of ['最新版本检查未完成；当前使用已完整校验的既有目录','v10.5.1','原生响应判断引擎已准备','频率限制'])expect(html).toContain(text);
 for(const text of ['规则同步未完成','已更新至最新版本'])expect(html).not.toContain(text);
});

it('offers one explicit administrator action for the whole compatible catalog',()=>{
 const html=renderToStaticMarkup(<LibraryBulkApprovalButton canManage ready snapshotAvailable count={1954} busy={false} onClick={()=>{}}/>);
 expect(html).toContain('编译并批准全部兼容规则（1954）');expect(html).not.toContain('disabled');
 expect(renderToStaticMarkup(<LibraryBulkApprovalButton canManage={false} ready snapshotAvailable count={1954} busy={false} onClick={()=>{}}/>)).toBe('');
 expect(renderToStaticMarkup(<LibraryBulkApprovalButton canManage ready={false} snapshotAvailable count={1954} busy={false} onClick={()=>{}}/>)).toContain('disabled');
});
