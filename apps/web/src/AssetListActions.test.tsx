import {it,expect,vi} from 'vitest';import {renderToStaticMarkup} from 'react-dom/server';
vi.mock('./api',()=>({api:vi.fn()}));
import {AssetListActions} from './AssetListActions';import {HostNetworkPanel} from './HostNetworkPanel';
const record={id:'owned-asset',hostname:'验收主机',os:'linux'};
it('asset rows expose direct editing and traffic details with capture in advanced actions',()=>{const html=renderToStaticMarkup(<AssetListActions record={record} role="ADMIN" evidenceAllowed onEdit={()=>{}} onOpen={()=>{}}/>);expect(html).toContain('编辑配置');expect(html).toContain('流量详情');expect(html).not.toContain('执行器结果验签');expect(html).toContain('更多操作');});
it('read-only rows expose network results without modification controls',()=>{const html=renderToStaticMarkup(<AssetListActions record={record} role="VIEWER" evidenceAllowed onEdit={()=>{}} onOpen={()=>{}}/>);expect(html).toContain('网络结果');expect(html).not.toContain('编辑配置');expect(html).not.toContain('流量捕获');});
it('rows without evidence access do not expose network result actions',()=>{const html=renderToStaticMarkup(<AssetListActions record={record} role="VIEWER" evidenceAllowed={false} onEdit={()=>{}} onOpen={()=>{}}/>);expect(html).not.toContain('<button');});
it('asset details only show the network report and cannot spawn a capture drawer',()=>{const html=renderToStaticMarkup(<HostNetworkPanel assetId={record.id}/>);expect(html).toContain('刷新监控状态');expect(html).not.toContain('配置一次流量捕获');});
