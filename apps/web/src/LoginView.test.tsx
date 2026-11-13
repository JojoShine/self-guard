import {expect,it,vi} from 'vitest';
import {renderToStaticMarkup} from 'react-dom/server';
vi.mock('./api',()=>({api:vi.fn()}));
import {DemoAccountPanel} from './LoginView';
it('does not expose disabled demo credentials',()=>{
 expect(renderToStaticMarkup(<DemoAccountPanel account={{enabled:false}} busy={false} onSelect={()=>{}}/>)).toBe('');
});
it('offers the dedicated demo credentials with interactive sample scope and normal login instructions',()=>{
 const html=renderToStaticMarkup(<DemoAccountPanel account={{enabled:true,email:'demo@example.test',password:'public-demo'}} busy={false} onSelect={()=>{}}/>);
 for(const text of ['体验账号','可操作体验','会话独立','8 小时','不访问真实主机','填入体验账号','demo@example.test','public-demo'])expect(html).toContain(text);
});
it('prevents replacing credentials while sign-in is pending',()=>{
 const html=renderToStaticMarkup(<DemoAccountPanel account={{enabled:true,email:'demo@example.test',password:'public-demo'}} busy onSelect={()=>{}}/>);
 expect(html).toContain('disabled=""');
});
