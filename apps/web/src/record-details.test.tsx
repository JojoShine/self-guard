import {describe,it,expect} from 'vitest';
import {renderToStaticMarkup} from 'react-dom/server';
import {EvidenceView,parseEvidence} from './EvidenceView';
import {RecordSummary} from './RecordSummary';

describe('readable evidence',()=>{
 it('parses at most two JSON encodings and keeps ordinary text intact',()=>{
  const value={eventCount:3,conditions:[{field:'type',operator:'eq',value:'LOGIN_FAILED',threshold:2}]};
  expect(parseEvidence(JSON.stringify(JSON.stringify(value)))).toEqual(value);
  expect(typeof parseEvidence(JSON.stringify(JSON.stringify(JSON.stringify(value))))).toBe('string');
  expect(parseEvidence('plain observation')).toBe('plain observation');
  expect(parseEvidence('[已隐藏]')).toBe('[已隐藏]');
 });
 it('leads with correlation fields and keeps unknown technical values visible in the complete field table',()=>{
  const html=renderToStaticMarkup(<EvidenceView value={JSON.stringify(JSON.stringify({eventCount:3,from:'2026-10-30T10:00:00Z',to:'2026-10-30T10:05:00Z',ruleId:'rule-opaque-id',conditions:[{field:'type',operator:'eq',value:'LOGIN_FAILED',threshold:2}],vendorField:{value:'custom-proof'}}))}/>);
  expect(html).toContain('窗口内日志');expect(html).toContain('3');expect(html).toContain('事件类型');expect(html).toContain('至少 2 次');
  expect(html).toContain('完整留存字段');expect(html).toContain('<table');expect(html).not.toMatch(/<details[^>]*\sopen(?:\s|>)/);expect(html).toContain('custom-proof');
  expect(html.indexOf('窗口内日志')).toBeLessThan(html.indexOf('rule-opaque-id'));
 });
 it('preserves hidden content and treats malicious-looking evidence only as literal text',()=>{
  const html=renderToStaticMarkup(<EvidenceView value={{actual:'[已隐藏]',message:'<img src=x onerror="alert(1)"><script>alert(2)</script>',unexpected:'<iframe src=evil>'}}/>);
  expect(html).toContain('[已隐藏]');expect(html).toContain('&lt;img');expect(html).not.toContain('<img');expect(html).not.toContain('<script>');expect(html).not.toContain('<iframe');
  expect(renderToStaticMarkup(<EvidenceView value="[已隐藏]"/>)).not.toContain('<details');
 });
 it('shows real baseline values, arrays, zero and false without inventing missing fields',()=>{
  const html=renderToStaticMarkup(<EvidenceView value={[{path:'/fixture',actual:'0644',expected:'0600',status:'checked'},{count:0,complete:false}]}/>);
  expect(html).toContain('实际值');expect(html).toContain('期望值');expect(html).toContain('/fixture');expect(html).toContain('0644');expect(html).toContain('0600');expect(html).toContain('0');expect(html).toContain('否');
  expect(renderToStaticMarkup(<EvidenceView value={null}/>)).toContain('暂无证据');
 });
});
describe('record summary',()=>{
 it('places readable semantic badges ahead of a secondary, copyable full ID',()=>{
  const html=renderToStaticMarkup(<RecordSummary resource="findings" record={{id:'full-record-identifier',kind:'ALERT',status:'UNKNOWN',severity:'HIGH',source:'correlation',owner:'值班人员',business:'支付业务',createdAt:'2026-10-30T10:00:00Z'}}/>);
  expect(html).toContain('关联检测');expect(html).toContain('高');expect(html).toContain('ant-tag-warning');expect(html).toContain('值班人员');expect(html).toContain('支付业务');expect(html).toContain('记录标识');expect(html.indexOf('关联检测')).toBeLessThan(html.indexOf('full-record-identifier'));
 });
 it('never interprets supplied metadata as HTML or invents severity/status',()=>{
  const html=renderToStaticMarkup(<RecordSummary resource="assets" record={{hostname:'<script>bad</script>',owner:'<img src=x>',id:'asset-id'}}/>);
  expect(html).not.toContain('<img');expect(html).not.toContain('<script>');expect(html).not.toContain('严重程度：高');expect(html).not.toContain('处置状态：待确认');
 });
});

it('treats prototype-like labels as ordinary supplied text',()=>{
 const evidence=renderToStaticMarkup(<EvidenceView value={{status:'__proto__',source:'constructor',conditions:[{field:'__proto__',operator:'constructor',value:'literal'}]}}/>);
 expect(evidence).toContain('__proto__');expect(evidence).toContain('constructor');
 const summary=renderToStaticMarkup(<RecordSummary resource="findings" record={{kind:'__proto__',status:'constructor',severity:'__proto__',source:'constructor'}}/>);
 expect(summary).toContain('__proto__');expect(summary).toContain('constructor');
});
it('explains real database behavior and keeps the complete retained fields visible',()=>{
 const html=renderToStaticMarkup(<EvidenceView value={{type:'DATABASE_AUTH',sourceIp:'192.0.2.8',service:'postgresql',count:5,action:'DETECT_ONLY',observations:[{user:'app_user',database:'orders',sourcePort:52000}]}}/>);
 expect(html).toContain('真实行为说明');expect(html).toContain('疑似口令爆破');expect(html).toContain('未自动封禁');expect(html).toContain('app_user');expect(html).toContain('完整留存字段');
});
