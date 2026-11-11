import {it,expect,vi} from 'vitest';
import {renderToStaticMarkup} from 'react-dom/server';
vi.mock('./api',()=>({api:vi.fn()}));
import {FindingTriageView} from './FindingTriagePanel';
it('keeps independent conclusions distinct from closure and hides modification from viewers',()=>{
 const base={findingId:'source',kind:'RISK',updatedAt:'2026-11-10T00:00:00Z',onChanged:()=>{}};
 const html=renderToStaticMarkup(<FindingTriageView {...base} canEdit value={{conclusion:'DUPLICATE',reason:'同一条实际风险',duplicate:{id:'original',title:'原问题'}}}/>);
 expect(html).toContain('重复问题');expect(html).toContain('原问题');expect(html).toContain('保留原处理状态');expect(html).toContain('记录核查结论');
 const readOnly=renderToStaticMarkup(<FindingTriageView {...base} canEdit={false} value={{conclusion:'INSUFFICIENT_EVIDENCE',reason:'缺少审计证据',duplicate:null}}/>);expect(readOnly).toContain('证据不足');expect(readOnly).not.toContain('记录核查结论');
});
