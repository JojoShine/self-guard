import {it,expect,vi} from 'vitest';
import {renderToStaticMarkup} from 'react-dom/server';
vi.mock('./api',()=>({api:vi.fn()}));
import {api} from './api';
import {DatabaseSqlView} from './DatabaseSqlView';
it('offers explicit SQL viewing only to authorized readers before expiration',()=>{
 const timestamp=new Date().toISOString();
 const allowed=renderToStaticMarkup(<DatabaseSqlView auditId="one" allowed={true} timestamp={timestamp}/>);
 expect(allowed).toContain('查看SQL原文');expect(allowed).toContain('7天');expect(api).not.toHaveBeenCalled();
 expect(renderToStaticMarkup(<DatabaseSqlView auditId="one" allowed={false} timestamp={timestamp}/>)).not.toContain('<button');
 expect(renderToStaticMarkup(<DatabaseSqlView auditId="one" allowed={true} timestamp="2020-01-01T00:00:00Z"/>)).toContain('已到期');
});
it('uses command wording for Redis while preserving protected raw evidence',()=>{const html=renderToStaticMarkup(<DatabaseSqlView auditId="redis-event" allowed timestamp={new Date().toISOString()} kind="COMMAND"/>);expect(html).toContain('查看命令原文');expect(html).toContain('7天');expect(html).not.toContain('查看SQL原文');expect(html).not.toContain('事务最终提交');});
