import {Alert,Descriptions} from 'antd';
const outcomes:Record<string,string>={NOT_FORWARDED:'未回源',BLOCKED_BY_WAF:'WAF已阻断本次请求',UPSTREAM_RESPONSE:'已回源并取得响应',UPSTREAM_ERROR:'回源失败'};
export function RequestTraceView({trace}:{trace:any}){
 if(!trace)return <Alert showIcon type="info" message="历史记录未留存完整链路" description="未保存的来源、回源地址或处置过程无法事后还原。"/>;
 return <section className="record-subsection"><h3>来源、网络链路与处置结果</h3>
 <Descriptions bordered column={{xs:1,sm:2}} items={[
 {key:'request',label:'请求关联编号',children:trace.requestId},
 {key:'peer',label:'直连对端',children:[trace.peerIp,trace.peerPort].filter(Boolean).join(':')||'未留存'},
 {key:'client',label:'识别来源',children:trace.clientIp||'未留存'},
 {key:'basis',label:'来源依据',children:trace.sourceBasis==='TRUSTED_PROXY_CHAIN'?'已配置可信代理链':'直连连接地址（未信任转发声明）'},
 {key:'tls',label:'客户端到防护节点',children:trace.incomingTls?'TLS加密连接':'HTTP未加密连接'},
 {key:'configured',label:'当时配置的上游',children:trace.configuredUpstream||'未选择站点'},
 {key:'actual',label:'实际回源地址',children:trace.upstreamAddress||'未观察到回源连接'},
 {key:'upstreamTls',label:'防护节点到上游',children:typeof trace.upstreamTls==='boolean'?(trace.upstreamTls?'TLS加密连接':'HTTP未加密连接'):'未观察到，不能推断'},
 {key:'result',label:'实际处理结果',children:outcomes[trace.outcome]||trace.outcome},
 {key:'ban',label:'处罚范围',children:trace.action==='BLOCK'?'阻断本次请求；未创建持续封禁':'未执行持续封禁'},
 {key:'query',label:'查询参数名',children:(trace.queryKeys||[]).join('、')||'无'},
 {key:'retention',label:'内容留存说明',children:'路径脱敏保留；查询参数值、凭据、请求正文不留存。完整请求目标保留摘要供核对。'},
 ]}/>
 </section>
}
