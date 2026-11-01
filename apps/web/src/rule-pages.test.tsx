import {describe,it,expect,vi} from 'vitest';
vi.mock('./api',()=>({api:vi.fn()}));
import {renderToStaticMarkup} from 'react-dom/server';
import {RuleToolsPanel} from './RuleToolsPanel';
describe('separate rule workflows',()=>{
 it('explains scope maintenance independently of sample verification',()=>{
 const html=renderToStaticMarkup(<RuleToolsPanel mode="scope"/>);
 expect(html).toContain('选择适用规则');expect(html).toContain('适用范围与基线豁免');
 expect(html).not.toContain('数据安全基础规则');expect(html).not.toContain('运行只读样本测试');
 });
 it('explains sample verification independently of scope editing',()=>{
 const html=renderToStaticMarkup(<RuleToolsPanel mode="test"/>);
 expect(html).toContain('选择验证规则');expect(html).toContain('不修改规则适用范围');
 expect(html).not.toContain('数据安全基础规则');expect(html).not.toContain('保存适用范围与豁免');
 });
});
