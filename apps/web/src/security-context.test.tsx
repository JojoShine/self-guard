import {expect,it,vi} from 'vitest';
vi.mock('./api',()=>({api:vi.fn()}));import {renderToStaticMarkup} from 'react-dom/server';import {SecurityContextContent} from './SecurityContext';
const base={resource:'findings',evidence:{assets:[],description:'真实业务异常',findings:[{id:'f',title:'文件权限过宽',severity:'HIGH',status:'OPEN',source:'agent',evidence:JSON.stringify({path:'/etc/app.conf',actual:'0666',expected:'0600'})}],network:{relations:[],missing:['缺少跨主机会话证据。']}}};
it('shows actual findings, affected values and missing network evidence rather than inventing paths',()=>{const html=renderToStaticMarkup(<SecurityContextContent context={base} record={{source:'agent'}} onOpen={()=>{}}/>);for(const text of ['文件权限过宽','0666','0600','/etc/app.conf','当前没有足够证据','建议处理路径'])expect(html).toContain(text);expect(html).not.toContain('已确认攻击链');});
it('labels configuration relationships and escapes supplied values',()=>{const context={...base,evidence:{...base.evidence,network:{relations:[{kind:'CONFIGURED_ROUTING',from:'shop.example',to:'<script>bad</script>',basis:'当前配置，不证明实际经过'}],missing:[]}}};const html=renderToStaticMarkup(<SecurityContextContent context={context} record={{}} onOpen={()=>{}}/>);expect(html).toContain('上游配置');expect(html).toContain('不证明');expect(html).toContain('&lt;script&gt;');expect(html).not.toContain('<script>');});
it('explains evidence permissions without claiming the record has no evidence',()=>{const html=renderToStaticMarkup(<SecurityContextContent context={{evidence:'[已隐藏]'}} record={{}} onOpen={()=>{}}/>);expect(html).toContain('没有读取详细证据的权限');expect(html).not.toContain('暂无证据');});
it('does not crash when public metadata omits evidence or returns an incomplete context',()=>{
 for(const context of [undefined,null,{}, {resource:'findings',total:1},{evidence:{}},{evidence:{findings:[],assets:[]}}]){
  const html=renderToStaticMarkup(<SecurityContextContent context={context} record={{}} onOpen={()=>{}}/>);
  expect(html).toContain('详细证据');expect(html).not.toContain('暂无证据');
 }
});
it('shows actual WAF field explanations inside findings and labels historical routing',()=>{
 const inspection={complete:true,nodeId:'edge-1',siteVersion:2,bundleId:'selfguard-builtin-v1',bundleSha256:'a'.repeat(64),score:0,decisionStatus:403,evidence:[{ruleId:'SQLI',variable:'ARGS:q',messageTemplate:'输入命中SQL查询组合',valueSha256:'b'.repeat(64),valueBytes:12}]};
 const context={...base,evidence:{...base.evidence,findings:[{id:'waf-alert',title:'SQL注入特征',source:'waf',evidence:JSON.stringify({action:'BLOCK',inspection})}],network:{relations:[{kind:'CONFIGURED_ROUTING_SNAPSHOT',from:'past.example',to:'https://past-backend.example',basis:'当时策略；本次未转发'}],missing:[]}}};
 const html=renderToStaticMarkup(<SecurityContextContent context={context} record={{source:'waf'}} onOpen={()=>{}}/>);for(const text of ['ARGS:q','输入命中SQL查询组合','内置基础防护规则','当时上游配置','past.example'])expect(html).toContain(text);expect(html).not.toContain('请求涉及的网络上下文');
});
it('explains frozen listening context without asserting vulnerability exposure or public reachability',()=>{
 const snapshot={assetId:'asset',hostname:'payment-api',inventoryAt:'2026-10-31T00:00:00Z',ports:[{protocol:'tcp',address:'0.0.0.0',port:443,state:'LISTEN'}],totalPorts:1,complete:true,omitted:0};
 const context={...base,evidence:{...base.evidence,findings:[{...base.evidence.findings[0],source:'vulnerability',evidence:{description:'Full vulnerability evidence',hostNetworkSnapshot:snapshot}}]}};
 const html=renderToStaticMarkup(<SecurityContextContent context={context} record={{source:'vulnerability'}} onOpen={()=>{}}/>);for(const text of ['扫描时的主机监听环境','payment-api','0.0.0.0','443','不证明漏洞通过这些端口暴露'])expect(html).toContain(text);
 const imported={...context,evidence:{...context.evidence,findings:[{...context.evidence.findings[0],source:'import',evidence:JSON.stringify({hostNetworkSnapshot:snapshot})}]}};expect(renderToStaticMarkup(<SecurityContextContent context={imported} record={{}} onOpen={()=>{}}/>)).not.toContain('扫描时的主机监听环境');
});
it('uses bound network proof for service findings while raw imported JSON cannot become an actual socket view',()=>{
 const evidence={proofType:'ACTIVE_NETWORK_CHECK',outcome:'CONFIRMED',description:'实际服务返回旧版本',remediation:'升级服务后复查',endpoint:{hostname:'owned.fixture.test',protocol:'tcp',port:8091},check:{kind:'NETWORK',rule:{kind:'TCP_BANNER',value:'legacy-service'}},networkProof:{checkKind:'TCP_BANNER',bannerPreview:'owned legacy-service 1.0',bannerBytes:24,bannerSha256:'a'.repeat(64),connections:[{source:'172.20.0.2:49152',destination:'172.20.0.3:8091',transport:'TCP'}]}};
 const finding={id:'bound-network',title:'实际服务特征',severity:'LOW',status:'OPEN',source:'active-scan',evidence},context={...base,evidence:{...base.evidence,findings:[finding]}};const render=(value:any)=>renderToStaticMarkup(<SecurityContextContent context={value} record={{source:'active-scan'}} onOpen={()=>{}}/>);const html=render(context);for(const text of ['实际网络检查依据','owned legacy-service 1.0','172.20.0.3:8091','不代表攻击者流量'])expect(html).toContain(text);expect(render({...context,evidence:{...context.evidence,findings:[{...finding,evidence:JSON.stringify(evidence)}]}})).not.toContain('实际网络检查依据');
});

it('labels Suricata asset links as collection hosts rather than confirmed affected targets',()=>{const html=renderToStaticMarkup(<SecurityContextContent context={base} record={{source:'suricata'}} onOpen={()=>{}}/>);expect(html).toContain('采集主机');expect(html).not.toContain('<h3>受影响对象</h3>');expect(html).toContain('目标归属仍需核对');});
it('explains inventory-only risk does not require a network relationship and offers scoped investigation',()=>{
 const context={...base,evidence:{...base.evidence,assets:[{id:'host-one',hostname:'demo-host',ip:'192.0.2.10'}],findings:[{...base.evidence.findings[0],source:'vulnerability',evidence:{proofType:'INVENTORY_VERSION_MATCH',component:{name:'library'}}}]}};
 const html=renderToStaticMarkup(<SecurityContextContent context={context} record={{source:'vulnerability'}} onOpen={()=>{}}/>);
 for(const text of ['不适用','版本匹配','不等于流量采集故障','#network-hosts?assetId=host-one','来源与目的 IP','获准请求'])expect(html).toContain(text);
});
it('distinguishes missing HTTP connection evidence and points to approved checks without claiming capture failure',()=>{
 const context={...base,evidence:{...base.evidence,findings:[{...base.evidence.findings[0],source:'active-scan',evidence:{proofType:'ACTIVE_HTTP_CHECK'}}]}};
 const html=renderToStaticMarkup(<SecurityContextContent context={context} record={{source:'active-scan'}} onOpen={()=>{}}/>);
 for(const text of ['HTTP 检查','扫描节点','授权入口','#scans?view=active','无法仅凭此处判断采集是否缺失'])expect(html).toContain(text);
 expect(html).not.toContain('网络关系不适用');
});
