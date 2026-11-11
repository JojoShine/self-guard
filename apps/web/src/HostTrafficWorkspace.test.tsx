import {it,expect,vi,afterEach} from 'vitest';
import {renderToStaticMarkup} from 'react-dom/server';
vi.mock('./api',()=>({api:vi.fn()}));
import {HostTrafficWorkspace,HostCollectionSummary,hostTrafficHref} from './HostTrafficWorkspace';
afterEach(()=>vi.unstubAllGlobals());
it('starts with choosing a host and a usable collection entry, without another editable asset table',()=>{
 vi.stubGlobal('location',{hash:'#network-hosts'});
 const html=renderToStaticMarkup(<HostTrafficWorkspace/>);
 expect(html).toContain('选择要查看的主机');expect(html).toContain('href="#enroll"');expect(html).not.toContain('添加资产');expect(html).not.toContain('漏洞数据源');
 expect(hostTrafficHref('host/one')).toBe('#network-hosts?assetId=host%2Fone');expect(hostTrafficHref()).toBe('#network-hosts');
});
it('does not mistake an asset registration or agent report for confirmed flow collection',()=>{
 const html=renderToStaticMarkup(<HostCollectionSummary asset={{id:'a',hostname:'主机',lastSeen:null}}/>);
 expect(html).toContain('尚未收到 Agent 上报');expect(html).not.toContain('监控正常');
 const reported=renderToStaticMarkup(<HostCollectionSummary asset={{id:'a',hostname:'主机',lastSeen:'2026-11-06T00:00:00Z'}}/>);
 expect(reported).toContain('最近 Agent 上报');expect(reported).toContain('流量采集状态以下方主机确认为准');
});
