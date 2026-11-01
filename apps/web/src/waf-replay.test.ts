import {describe,it,expect} from 'vitest';
import {wafReplayOutcome,wafEventTitle,wafAccessTitle} from './waf-replay';
describe('WAF sample outcome',()=>{
 it('shows incomplete evidence before a benign or blocked decision',()=>{for(const blocked of [false,true]){const result=wafReplayOutcome({blocked,incomplete:['malformed-percent-encoding']});expect(result.type).toBe('warning');expect(result.title).toContain('不完整');}});
 it('distinguishes completed decisions',()=>{expect(wafReplayOutcome({blocked:false}).type).toBe('success');expect(wafReplayOutcome({blocked:true}).title).toContain('阻断');});
});
it('uses actual WAF rule descriptions and readable access results instead of opaque identifiers',()=>{
 expect(wafEventTitle({ruleId:'f9135d76-dcf7-40aa-81de-c7a519eb3ef8',inspection:{siteHostname:'payment.test',evidence:[{messageTemplate:'请求包含脚本标签'}]}})).toBe('请求包含脚本标签 · payment.test');
 expect(wafEventTitle({ruleId:'f9135d76-dcf7-40aa-81de-c7a519eb3ef8'})).not.toContain('f9135d76');
 expect(wafEventTitle({ruleId:'constructor'})).not.toContain('function');
 expect(wafAccessTitle({id:'node:session:7',method:'GET',path:'[redacted]',status:200})).toBe('GET 访问记录 · HTTP 200');
 expect(wafAccessTitle({method:'POST',path:'/login',status:403})).toBe('POST /login · HTTP 403');
});
