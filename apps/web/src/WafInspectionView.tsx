import {useState} from 'react';
import {Button} from 'antd';
import {api} from './api';
import {WafAccessView} from './WafAccessView';
import {RequestTraceView} from './RequestTraceView';
import {RecordFieldsTable} from './RecordFieldsTable';
import {Alert,Descriptions,Space,Typography} from 'antd';
import {EvidenceView} from './EvidenceView';
import {StatusTag} from './ModuleSection';
import {formatTime} from './presentation';

const failureLabels:Record<string,string>={QUEUE_CAPACITY:'检查队列已满，请检查请求并发量与节点负载',QUEUE_TIMEOUT:'等待检查资源超时，请检查节点负载',WORKER_DEADLINE:'规则进程执行超时，请检查规则复杂度和节点负载',WORKER_UNAVAILABLE:'隔离规则进程不可用或提前退出，请检查节点运行状态',WORKER_PROTOCOL:'隔离规则进程返回异常，请检查节点版本与运行日志',REQUEST_INCOMPLETE:'请求解析或规则检查未完成，请核对请求格式与规则兼容情况',REQUEST_INVALID:'请求超出检查格式或容量限制',CANCELLED:'请求已取消，本次检查没有完成',INSPECTION_INCOMPLETE_OR_UNAVAILABLE:'历史记录未细分失败原因，请结合节点日志排查'};

export function WafInspectionView({record,showNetwork=true}:{record:any;showNetwork?:boolean}){
 const [access,setAccess]=useState<any>(),[loading,setLoading]=useState(false),[error,setError]=useState('');
 async function openAccess(){setLoading(true);setError('');try{setAccess(await api('/waf-access/'+encodeURIComponent(record.context.requestId)))}catch(e){setError((e as Error).message)}finally{setLoading(false)}}
 if(access)return <div className="module-stack"><Button onClick={()=>setAccess(undefined)}>返回攻击记录</Button><WafAccessView record={access}/><RecordFieldsTable value={access}/></div>;
 const proof=record.inspection;
 const metadata=<><Descriptions bordered size="small" column={{xs:1,sm:2}} style={{overflowWrap:'anywhere'}} items={[
  {key:'method',label:'请求方法',children:record.method||'未留存'},
  {key:'action',label:'防护动作',children:record.action?<StatusTag value={record.action}/>:'未留存'},
  {key:'rule',label:'命中规则标识',children:record.ruleId||'未留存'},
  {key:'time',label:'请求时间',children:formatTime(record.timestamp)},
  {key:'path',label:'请求路径',children:record.path==='[redacted]'?'路径已脱敏':record.path||'未留存'},
  {key:'client',label:'节点识别的客户端',children:record.remoteIp||'未留存'},
 ]}/>
 <RequestTraceView trace={record.context}/>
 {error&&<Alert type="error" message={error}/>}
 {record.context?.requestId&&<Button type="link" className="record-title-link" loading={loading} onClick={()=>void openAccess()}>查看同一请求的访问结果</Button>}
 </>;
 if(typeof proof==='string')return <div className="module-stack">{metadata}<EvidenceView value={proof} title="检测依据与网络上下文"/></div>;
 if(!proof||typeof proof!=='object'||Array.isArray(proof)||typeof proof.complete!=='boolean')return <div className="module-stack">{metadata}<Alert type="info" showIcon message="当前记录未保存完整规则依据" description="当前记录仅保留规则编号、请求方法和客户端等基础信息，不能据此还原请求内容或攻击链。新规则事件会保存实际命中字段及内容摘要。"/></div>;
 return <div className="module-stack">
  {metadata}
  <Alert type={proof.complete?'info':'warning'} showIcon message={proof.complete?'实际规则检查依据':'本次检查未完成，节点已拒绝转发'} description={proof.complete?'以下内容来自节点实际规则执行；命中表示检测条件成立，仍需结合业务判断是否存在可利用漏洞。':'正文无法完整解析、执行超时或规则进程不可用均不能当成安全结果。请检查节点状态和请求格式后复验。'}/>
  <Descriptions bordered size="small" column={{xs:1,sm:2}} items={[
   {key:'version',label:'站点策略版本',children:proof.siteVersion},{key:'node',label:'实际检查节点',children:proof.nodeId},
   {key:'bundle',label:'规则包标识',children:proof.bundleId==='selfguard-builtin-v1'?'内置基础防护规则':proof.bundleId},{key:'sha',label:'固定规则摘要',children:<Typography.Text copyable>{proof.bundleSha256}</Typography.Text>},
   ...(!proof.complete?[{key:'failure',label:'检查失败原因',children:failureLabels[proof.failureKind]||'未记录具体原因，请结合节点日志排查'}]:[]),
   {key:'score',label:'异常评分',children:proof.score},{key:'status',label:'规则决策响应码',children:proof.decisionStatus||'未触发规则阻断'},
  ]}/>
  {showNetwork&&<section className="record-subsection"><h3>请求涉及的网络上下文</h3><Descriptions bordered size="small" column={1} items={[
   {key:'client',label:'节点识别的客户端',children:record.remoteIp||'未提供'},
   {key:'site',label:'本次防护站点',children:proof.siteHostname||'未提供'},
   {key:'upstream',label:record.action==='BLOCK'?'配置上游（本次未转发）':'配置上游（计划转发目标）',children:proof.configuredUpstreamOrigin||'未提供'},
  ]}/><Typography.Paragraph type="secondary">客户端与防护站点来自本次请求记录；上游是当时策略配置的目标。此处没有推断后续利用或横向移动，实际访问结果需结合访问记录核对。</Typography.Paragraph></section>}
  <EvidenceView value={proof.evidence} title="实际命中字段与规则说明"/>
  {proof.omittedEvidence>0&&<Space><Typography.Text type="secondary">另有 {proof.omittedEvidence} 项命中依据超过单条事件留存预算。</Typography.Text></Space>}
 </div>;
}
