import {it,expect} from 'vitest';
import {renderToStaticMarkup} from 'react-dom/server';
import {TopNavigation} from './TopNavigation';
it('offers the same complete navigation for public browsing',()=>{const html=renderToStaticMarkup(<TopNavigation demo page="overview" onNavigate={()=>{}}/>);for(const label of ['概览','资产','网络安全','数据安全','设置'])expect(html).toContain(label);expect(html).not.toContain('演示资产');expect(html).not.toContain('体验导航');});
