import {it,expect} from 'vitest';
import {renderToStaticMarkup} from 'react-dom/server';
import {TopNavigation} from './TopNavigation';
it('offers only demo navigation without administrative settings',()=>{const html=renderToStaticMarkup(<TopNavigation demo page="overview" onNavigate={()=>{}}/>);for(const label of ['概览','演示资产','演示问题'])expect(html).toContain(label);expect(html).not.toContain('设置');expect(html).not.toContain('策略');});
