import {describe,it,expect,vi} from 'vitest';
import {renderToStaticMarkup} from 'react-dom/server';
vi.mock('./api',()=>({api:vi.fn()}));
import {AccessObservationsPanel,pinnedAccessFilters,AccessObservationDetails,AccessRiskSummary,evidencePreview,exportableEvidenceParts} from './AccessObservationsPanel';
import {resolveNavigation} from './navigation';
describe('effective access evidence',()=>{
 it('explains ordinary sensitive access separately from rule-based alert grading',()=>{
  const classification={status:'CLASSIFIED',definitions:[],objectResolution:{basis:'REGISTERED_HTTP_ROUTE',status:'RESOLVED',unresolved:0,configurationVersion:2}};
  const ordinary=renderToStaticMarkup(<AccessRiskSummary classification={classification} assessment={{status:'ORDINARY',policyVersion:3,sourceVersion:2,rules:[]}}/>);expect(ordinary).toContain('普通访问');expect(ordinary).toContain('未命中检测规则');expect(ordinary).toContain('接口登记关联');
  const alert=renderToStaticMarkup(<AccessRiskSummary classification={classification} assessment={{status:'ALERT',policyVersion:3,sourceVersion:2,rules:[{ruleId:'r',name:'敏感超量读取',category:'BEHAVIOR',detector:'SENSITIVE_READ',sourceVersion:2,baseSeverity:'MEDIUM',classificationFloor:'CRITICAL',finalSeverity:'CRITICAL',minimumBytes:1000,minimumLevel:3,operations:[]}]}}/>);
  for(const label of ['敏感超量读取','规则原等级','数据映射最低等级','最终告警等级','1,000'])expect(alert).toContain(label);
 });
 it('places ordinary access and source coverage in data security',()=>{for(const page of ['data-access','data-access-sources'])expect(resolveNavigation(page).group?.[0]).toBe('数据安全');});
 it('keeps payload hidden until independently authorized and requested',()=>{
  const html=renderToStaticMarkup(<AccessObservationDetails value={{id:'id',sourceId:'source',eventId:'event',startedAt:new Date().toISOString(),endedAt:new Date().toISOString(),operation:'GET',route:'/orders',sessionId:'session',result:'SUCCESS',completeness:'PARTIAL',requestBytes:8,responseBytes:16,source:{name:'HTTP',protocol:'HTTP',assetId:'host',address:'127.0.0.1',port:80},metadata:{gaps:['BODY_NOT_CAPTURED']},classification:{status:'UNCLASSIFIED',definitions:[]},chunks:[{id:'chunk',direction:'RESPONSE',sequence:0,bytes:16,sha256:'a'.repeat(64),capturedAt:new Date().toISOString(),expiresAt:new Date().toISOString(),available:true}],findingIds:[],canReadRaw:false,canExportRaw:false}} onRefresh={()=>{}}/>);
  expect(html).toContain('原始证据读取需要独立权限');expect(html).toContain('正文未采集');expect(html).not.toContain('<textarea');expect(html).not.toContain('data:application');
 });
 it('only offers a whole-message download when all ordered parts are present and live',()=>{const part={id:'one',direction:'RESPONSE',sequence:0,bytes:4,sha256:'a'.repeat(64),capturedAt:new Date().toISOString(),expiresAt:new Date(Date.now()+60000).toISOString(),available:true};expect(exportableEvidenceParts([part],4,'RESPONSE')).toHaveLength(1);for(const invalid of [[{...part,sequence:1}],[{...part,available:false}],[{...part,bytes:3}],[]])expect(exportableEvidenceParts(invalid,4,'RESPONSE')).toHaveLength(0);});
 it('renders binary and long evidence with explicit display limits',()=>{expect(evidencePreview('AP8B').mode).toBe('HEX');expect(evidencePreview(btoa('hello')).text).toBe('hello');const result=evidencePreview(btoa('a'.repeat(70000)));expect(result.truncated).toBe(true);expect(result.text.length).toBeLessThan(70000);});
});

it('keeps an embedded instance when clearing or replacing URL filters',()=>{
 expect(pinnedAccessFilters({},'fixed')).toEqual({instanceId:'fixed'});
 expect(pinnedAccessFilters({instanceId:'other',sourceId:'source'},'fixed')).toEqual({instanceId:'fixed',sourceId:'source'});
 expect(pinnedAccessFilters({instanceId:'other'})).toEqual({instanceId:'other'});
 vi.stubGlobal('location',{hash:'#data-access?instanceId=other&recordId=foreign'});
 try{const html=renderToStaticMarkup(<AccessObservationsPanel instanceId="fixed"/>);expect(html).toContain('fixed');expect(html).not.toContain('foreign');expect(html).toContain('不能关闭数据库TLS');expect(html).toContain('配置采集覆盖与探针')}finally{vi.unstubAllGlobals()}
});
