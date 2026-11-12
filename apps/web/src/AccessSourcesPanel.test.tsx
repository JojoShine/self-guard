import {expect,it,vi} from 'vitest';import {renderToStaticMarkup} from 'react-dom/server';
vi.mock('./api',()=>({api:vi.fn()}));
import {AccessSourcesPanel,sourceInstanceScope,sourceCreationScope} from './AccessSourcesPanel';
it('retains explicit instance binding while global creation stays unchanged',()=>{
 expect(sourceInstanceScope('#data-access-sources?instanceId=fixed')).toBe('fixed');
 expect(sourceInstanceScope('#data-access-sources')).toBeUndefined();
 expect(sourceCreationScope({instanceId:'other',protocol:'POSTGRESQL'},'fixed')).toEqual({instanceId:'fixed',protocol:'POSTGRESQL'});
 expect(sourceCreationScope({protocol:'HTTP'})).toEqual({protocol:'HTTP'});
});
it('shows the current instance restriction and scopes return navigation',()=>{
 vi.stubGlobal('location',{hash:'#data-access-sources?instanceId=fixed'});
 try{const html=renderToStaticMarkup(<AccessSourcesPanel/>);expect(html).toContain('当前实例范围');expect(html).toContain('#data-access?instanceId=fixed')}finally{vi.unstubAllGlobals()}
});
