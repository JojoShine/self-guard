import {RequestTraceView} from './RequestTraceView';
import {Alert,Descriptions} from 'antd';
import {formatTime} from './presentation';

export function WafAccessView({record}:{record:any}){
 return <div className="module-stack">
  <Alert type="info" showIcon message="实际访问记录" description="响应状态表示这次请求的处理结果，不等于已证明请求安全。此处只展示节点实际留存的脱敏字段，不还原未保存的请求头、正文或客户端链路。"/>
  <Descriptions bordered column={{xs:1,sm:2}} items={[
   {key:'method',label:'请求方法',children:record.method||'未留存'},
   {key:'status',label:'响应状态',children:record.status===undefined?'未留存':`HTTP ${record.status}`},
   {key:'path',label:'请求路径',children:record.path==='[redacted]'?'路径已脱敏':record.path||'未留存'},
   {key:'time',label:'请求时间',children:formatTime(record.timestamp)},
   {key:'duration',label:'处理耗时',children:typeof record.durationMicros==='number'?`${record.durationMicros/1000} ms`:'未留存'},
   {key:'node',label:'采集节点',children:record.nodeId||'未留存'},
   {key:'site',label:'站点标识',children:record.siteId||'未留存'},
  ]}/>
  <RequestTraceView trace={record.context}/>
 </div>;
}
