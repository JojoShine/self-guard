import {expect,it,vi} from 'vitest';
import {renderToStaticMarkup} from 'react-dom/server';
vi.mock('./api',()=>({api:vi.fn()}));
import {DemoAccountPanel} from './LoginView';
it('does not expose disabled demo credentials',()=>{
 expect(renderToStaticMarkup(<DemoAccountPanel account={{enabled:false}} busy={false} onSelect={()=>{}}/>)).toBe('');
});
it('offers the dedicated demo credentials with read-only full platform scope and normal login instructions',()=>{
 const html=renderToStaticMarkup(<DemoAccountPanel account={{enabled:true,email:'demo@example.test',password:'public-demo'}} busy={false} onSelect={()=>{}}/>);
 for(const text of ['全功能浏览账号','现有数据','不能新增','修改','删除','执行','敏感原文隐藏','填入体验账号','demo@example.test','public-demo'])expect(html).toContain(text);
});
it('prevents replacing credentials while sign-in is pending',()=>{
 const html=renderToStaticMarkup(<DemoAccountPanel account={{enabled:true,email:'demo@example.test',password:'public-demo'}} busy onSelect={()=>{}}/>);
 expect(html).toContain('disabled=""');
});
