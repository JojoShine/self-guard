import type {ReactNode} from 'react';
import {Button,Dropdown,Result,Tabs} from 'antd';
import {ModuleToolbar} from './ModuleSection';
import {names,resolveNavigation,retiredModule} from './navigation';

export function RetiredModule({page}:{page:string}){
 return <Result status="info" title="此模块已退出本期功能" subTitle={retiredModule(page)} extra={<ModuleToolbar><Button type="primary" href="#scans">漏洞扫描</Button><Button href="#network-hosts">主机与流量</Button><Button href="#data-access">数据访问审计</Button></ModuleToolbar>}/>;
}
export type AuditScope={assetId?:string;instanceId?:string;sourceId?:string};
export function coreWorkspaceHref(page:string,hash:string,scope?:AuditScope){
 const query=new URLSearchParams(hash.split('?')[1]||''),next=new URLSearchParams();
 const keys:(keyof AuditScope)[]=page==='data-access'?['assetId','instanceId','sourceId']:page==='database-audit'?['instanceId']:['data-access-sources','network-hosts','network-sensors'].includes(page)?['assetId']:[];
 for(const key of keys){const value=scope===undefined?query.get(key):scope[key];if(value)next.set(key,value)}
 return '#'+page+(next.size?'?'+next:'');
}
export function CoreModuleTools({page,scope}:{page:string;scope?:AuditScope}){
 const active=resolveNavigation(page).activePage;
 const link=(key:string,label=names[key])=><Button key={key} type={page===key?'primary':'default'} href={coreWorkspaceHref(key,typeof location==='undefined'?'':location.hash,scope)} aria-current={page===key?'page':undefined}>{label}</Button>;
 const tabs=(items:[string,string][],extra?:ReactNode)=><Tabs activeKey={page} onChange={key=>{location.hash=coreWorkspaceHref(key,location.hash,scope)}} tabBarExtraContent={extra} items={items.map(([key,label])=>({key,label}))}/>;
 if(active==='network-hosts')return tabs([['network-hosts','连接记录'],['network-sensors','协议记录']]);
 if(active==='scans')return tabs([['scans','扫描计划'],['network-risks','检查结果']],<Dropdown trigger={['click']} menu={{items:['sources','rule-sources-status','rules','baseline','rule-scope','rule-test','detection'].map(key=>({key,label:<a href={'#'+key}>{names[key]}</a>}))}}><Button>扫描配置</Button></Dropdown>);
 if(active==='assets')return <ModuleToolbar>{link('assets')}{link('asset-candidates')}{link('enroll')}</ModuleToolbar>;
 if(active==='data-access')return page==='data-access-sources'?<ModuleToolbar>{link('data-access','返回访问审计')}</ModuleToolbar>:tabs([['data-access','请求与响应'],['database-audit','数据库审计']],link('data-access-sources','采集配置'));
 if(active==='data-alerts')return <ModuleToolbar>{page!=='data-alerts'&&link('data-alerts','返回安全告警')}<Dropdown trigger={['click']} menu={{items:[{key:'risks',label:<a href="#data-risks">配置检查结果</a>},{key:'rules',label:<a href="#data-security">准入与行为规则</a>}]}}><Button>检测配置</Button></Dropdown></ModuleToolbar>;
 if(active==='operations')return <ModuleToolbar>{link('operations')}{link('rollouts','Agent 维护')}{link('credentials')}</ModuleToolbar>;
 if(active==='webhook')return <ModuleToolbar>{link('webhook')}{link('deliveries')}</ModuleToolbar>;
 return null;
}
