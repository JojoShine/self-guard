import {expect,it,vi} from 'vitest';
import {renderToStaticMarkup} from 'react-dom/server';
vi.mock('./api',()=>({api:vi.fn()}));
import {CompletionPanel} from './CompletionPanel';
it('keeps backup status and refresh available without write controls for public viewers',()=>{
 const html=renderToStaticMarkup(<CompletionPanel section="backup" readOnly/>);
 expect(html).toContain('定期备份');
 expect(html).toContain('刷新');
 expect(html).not.toContain('编辑配置');
});
