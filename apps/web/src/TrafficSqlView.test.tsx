import {expect,it,vi} from 'vitest';import {renderToStaticMarkup} from 'react-dom/server';
vi.mock('./api',()=>({api:vi.fn()}));
import {TrafficSqlView,TrafficSqlResult,visibleTrafficSql} from './TrafficSqlView';
const result={state:'PARTIAL' as const,statements:[{sql:'select $1',stage:'PREPARE' as const},{sql:'select $1',stage:'EXECUTE' as const}],reasons:['TLS_NO_PLAINTEXT'],protocol:'POSTGRESQL',source:'PACKET_REQUEST' as const,observedAt:new Date().toISOString()};
it('keeps SQL hidden by default and explains independent permissions',()=>{expect(renderToStaticMarkup(<TrafficSqlView recordId="a" allowed timestamp={result.observedAt}/>)).toContain('查看报文SQL');expect(renderToStaticMarkup(<TrafficSqlView recordId="a" allowed={false} timestamp={result.observedAt}/>)).toContain('访问证据与SQL原文');});
it('distinguishes preparation, execution requests and encrypted gaps',()=>{const html=renderToStaticMarkup(<TrafficSqlResult value={result}/>);for(const value of ['准备语句','执行请求','观测到的SQL请求','流量已加密，当前没有可用明文观察点','不证明执行成功或事务提交'])expect(html).toContain(value)});
it('never exposes stale record or expired SQL',()=>{const raw={id:'a',value:result};expect(visibleTrafficSql(raw,'b',true,Date.now()+10000)).toBeUndefined();expect(visibleTrafficSql(raw,'a',true,0)).toBeUndefined();expect(visibleTrafficSql(raw,'a',false,Date.now()+10000)).toBeUndefined()});
it('renders every parser gap in Chinese',()=>{
 const codes=['TLS_NO_PLAINTEXT','PROTOCOL_UNSUPPORTED','BODY_NOT_CAPTURED','EVIDENCE_EXPIRED','INCOMPLETE_EVIDENCE','REQUEST_TOO_LARGE','INVALID_FRAME','INVALID_ENCODING','SQL_TOO_LARGE','STATEMENT_LIMIT','PREPARED_CONTEXT_MISSING','NO_SQL_MESSAGE','AUTHENTICATION_MESSAGE','CAPTURE_LOSS','MIDSTREAM','CORRELATION_UNKNOWN'];
 const html=renderToStaticMarkup(<TrafficSqlResult value={{...result,statements:[],reasons:codes}}/>);
 for(const code of codes)expect(html).not.toContain(code);
 expect(html).toContain('不代表数据库没有执行SQL');
});
