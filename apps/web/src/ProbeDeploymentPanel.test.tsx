import {expect,it,vi} from 'vitest';
import {renderToStaticMarkup} from 'react-dom/server';
vi.mock('./api',()=>({api:vi.fn()}));
import {ProbeDeploymentControls,probeJobLabel} from './ProbeDeploymentPanel';
it('distinguishes remote command completion from verified collection',()=>{
 expect(probeJobLabel('SUCCEEDED','INSTALL')).toContain('等待心跳');
 expect(probeJobLabel('RUNNING','CHECK')).toContain('检查');
 expect(probeJobLabel('QUEUED','INSTALL')).toContain('排队');
});
it('allows stopping a disabled source without authorizing installation',()=>{
 const html=renderToStaticMarkup(<ProbeDeploymentControls enabled={false} busy={false} onAction={()=>{}}/>);
 expect(html).toMatch(/disabled=""[^>]*><span>安装并启动/);
 expect(html).toMatch(/<button(?![^>]*disabled)[^>]*><span>停止服务/);
});
