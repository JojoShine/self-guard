import {expect,it,vi} from 'vitest';
vi.mock('./api',()=>({api:vi.fn()}));
import {renderToStaticMarkup} from 'react-dom/server';
import {FindingHandlingGuide} from './FindingHandlingGuide';
import {AccessCollectionGuide} from './AccessCollectionGuide';
import {SourceCollectionEvidence,type Source} from './AccessSourcesPanel';
it('offers source-specific verification without inventing compromise or executing changes',()=>{
 const vulnerability=renderToStaticMarkup(<FindingHandlingGuide source="vulnerability"/>);
 expect(vulnerability).toContain('软件包修订');expect(vulnerability).toContain('#scans');
 const ids=renderToStaticMarkup(<FindingHandlingGuide source="suricata"/>);
 expect(ids).toContain('采集主机不一定是受攻击目标');expect(ids).toContain('#network-sensors');
 const data=renderToStaticMarkup(<FindingHandlingGuide source="access-observation"/>);
 expect(data).toContain('完整性');expect(data).toContain('最终业务用户可能未知');expect(data).toContain('#data-access');
 const unknown=renderToStaticMarkup(<FindingHandlingGuide source="unknown"/>);
 expect(unknown).toContain('当前依据不足时继续核查');expect(unknown).not.toContain('确认发生泄露');
});
it('gives the next action for uninstalled, unconfirmed and online-but-empty collection',()=>{
 const collection={state:'AWAITING_PROBE',probeVersion:null,reportedConfigurationVersion:null,expectedConfigurationVersion:2};
 const source:Source={id:'source',name:'source',assetId:'host',protocol:'POSTGRESQL',mode:'PLAINTEXT_EVENTS',interface:'process',address:'127.0.0.1',port:5432,enabled:true,version:2,rules:[],health:{},collection};
 const waiting=renderToStaticMarkup(<SourceCollectionEvidence source={source}/>);expect(waiting).toContain('检查对应主机上的独立探针服务');
 const unconfirmed=renderToStaticMarkup(<SourceCollectionEvidence source={{...source,collection:{...collection,state:'CONFIG_MISMATCH'}}}/>);expect(unconfirmed).toContain('核对主机确认的配置版本');
 const online=renderToStaticMarkup(<SourceCollectionEvidence source={{...source,collection:{...collection,state:'RUNNING'}}}/>);expect(online).toContain('尚未收到有效访问');expect(online).toContain('发起获准用例');
});
it('describes database access boundaries and installation checks without treating metadata as full plaintext',()=>{
 const html=renderToStaticMarkup(<AccessCollectionGuide/>);
 for(const text of ['确认授权范围','安装独立探针','核对配置确认','验证有效请求与响应','HTTP/1.1','HTTP/2','OpenSSL','七天','不等于'])expect(html).toContain(text);
 expect(html).toContain('原生审计');expect(html).toContain('逐组合验收');
});
