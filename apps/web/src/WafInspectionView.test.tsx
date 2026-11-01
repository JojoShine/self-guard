import {describe,it,expect,vi} from 'vitest';vi.mock('./api',()=>({api:vi.fn()}));import {renderToStaticMarkup} from 'react-dom/server';import {WafInspectionView} from './WafInspectionView';
describe('实际 WAF 依据',()=>{
 it('explains actual rule field and distinguishes configured upstream from observed attack path',()=>{
  const html=renderToStaticMarkup(<WafInspectionView record={{remoteIp:'198.51.100.7',action:'BLOCK',inspection:{complete:true,nodeId:'edge-1',siteVersion:3,bundleId:'bundle-1',bundleSha256:'a'.repeat(64),score:5,decisionStatus:451,siteHostname:'business.test',configuredUpstreamOrigin:'https://app.test',evidence:[{ruleId:'120001',variable:'ARGS:q',messageTemplate:'实际命中说明',valueSha256:'b'.repeat(64),valueBytes:12}]}}}/>);
  for(const text of ['198.51.100.7','business.test','https://app.test','本次未转发','ARGS:q','实际命中说明','451','没有推断后续利用'])expect(html).toContain(text);
  expect(html).not.toContain('ant-modal');
 });
 it('does not invent evidence for legacy or incomplete results',()=>{
  expect(renderToStaticMarkup(<WafInspectionView record={{}}/>)).toContain('不能据此还原请求内容或攻击链');
  expect(renderToStaticMarkup(<WafInspectionView record={{inspection:{complete:false,evidence:[]}}}/>)).toContain('本次检查未完成');
  expect(renderToStaticMarkup(<WafInspectionView record={{inspection:'[已隐藏]'}}/>)).toContain('已隐藏');
 });
});
it('explains the actual incomplete-inspection cause without inventing a vulnerability',()=>{
 const html=renderToStaticMarkup(<WafInspectionView record={{inspection:{complete:false,failureKind:'QUEUE_CAPACITY',evidence:[]}}}/>);
 expect(html).toContain('检查队列已满');expect(html).toContain('检查失败原因');expect(html).not.toContain('secret submitted content');
});
it('keeps actual legacy event content visible when full rule evidence was not retained',()=>{
 const html=renderToStaticMarkup(<WafInspectionView record={{method:'POST',action:'BLOCK',ruleId:'owned-legacy-rule',path:'/legacy-request',remoteIp:'192.0.2.48',timestamp:'2026-11-01T00:00:00Z'}}/>);
 for(const text of ['POST','阻断','owned-legacy-rule','/legacy-request','192.0.2.48','请求时间','未保存完整规则依据'])expect(html).toContain(text);
 expect(html).not.toContain('ARGS:q');
});
