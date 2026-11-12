import {it,expect,vi} from 'vitest';
import {renderToStaticMarkup} from 'react-dom/server';
vi.mock('./api',()=>({api:vi.fn()}));
import {DatabaseAuditEmptyState} from './DatabaseAuditPanel';
it('distinguishes collected runtime samples from missing SQL audit setup',()=>{
 const html=renderToStaticMarkup(<DatabaseAuditEmptyState sources={0} runtimeConnected onOverview={()=>{}} onConfigure={()=>{}}/>);
 for(const text of ['运行指标已接入，SQL审计尚未接入','不代表数据库没有执行SQL','接入与验收','配置审计来源'])expect(html).toContain(text);
});
it('directs configured sources with no matching records to collection diagnostics',()=>{
 const html=renderToStaticMarkup(<DatabaseAuditEmptyState sources={1} runtimeConnected/>);
 expect(html).toContain('已配置审计来源，当前条件下尚无记录');expect(html).toContain('日志路径');expect(html).not.toContain('SQL审计尚未接入');
});
it('does not assume missing source setup when coverage is unknown',()=>{
 const html=renderToStaticMarkup(<DatabaseAuditEmptyState/>);
 expect(html).toContain('采集接入状态尚未确认');expect(html).not.toContain('SQL审计尚未接入');
});
