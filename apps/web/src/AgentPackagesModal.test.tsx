import type {ReactNode} from 'react';
import {expect,it,vi} from 'vitest';
import {renderToStaticMarkup} from 'react-dom/server';
vi.mock('./api',()=>({api:vi.fn(),useSession:{getState:()=>({token:''})}}));
vi.mock('./FormDrawer',()=>({FormDrawer:({children}:{children:ReactNode})=><section>{children}</section>}));
import {AgentPackagesModal} from './AgentPackagesModal';
it('renders package metadata when the public DTO omits its digest',()=>{
 const html=renderToStaticMarkup(<AgentPackagesModal release={{id:'release',version:'1',architecture:'amd64',packages:[{id:'package',format:'deb',status:'PUBLISHED',size:1024}]}} admin={false} onClose={()=>{}} onChange={async()=>{}}/>);
 expect(html).toContain('已隐藏');
 expect(html).toContain('deb');
});
