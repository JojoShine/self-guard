import {useMemo} from 'react';
import {Table,Typography} from 'antd';
import {paginationDefaults} from './pagination';

const names:Record<string,string>={osDistribution:'登记发行版',osVersion:'登记系统版本',sourceIp:'来源IP',sourcePort:'来源端口',clientIp:'识别来源IP',peerPort:'直连对端端口',sourceBasis:'来源识别依据',incomingTls:'入站连接已加密',requestTargetSha256:'原始请求目标摘要',pathRetention:'路径留存方式',queryKeys:'查询参数名',queryKeysOmitted:'其余未留存参数名数量',configuredUpstream:'配置上游',upstreamAddress:'实际回源地址',upstreamTls:'回源连接已加密',forwarded:'已尝试回源',outcome:'实际处理结果',banState:'持续封禁状态',user:'尝试账号',tls:'连接已加密',id:'记录标识',requestId:'请求关联标识',source:'来源',sourceKey:'来源节点',externalId:'来源记录标识',assetId:'资产标识',siteId:'站点标识',nodeId:'采集节点',type:'记录类型',kind:'分类',name:'名称',title:'标题',status:'状态',action:'处置动作',reason:'原因',evidence:'依据',inspection:'检查依据',context:'关联上下文',createdAt:'创建时间',updatedAt:'更新时间',timestamp:'事件时间',occurredAt:'发生时间',receivedAt:'接收时间',expiresAt:'保留到期时间',method:'请求方法',path:'访问或文件路径',remoteIp:'来源地址',peerIp:'直连对端地址',hostname:'主机或站点',username:'账号',database:'数据库',protocol:'协议',ruleId:'规则标识',ruleName:'规则名称',durationMicros:'耗时（微秒）',complete:'采集完整性',actual:'实际值',expected:'期望值',enabled:'启用状态',count:'数量',message:'说明',version:'版本',sha256:'内容摘要'};
export type RecordFieldRow={id:string;path:string;field:string;value:unknown;kind:'value'|'empty-array'|'empty-object'};
function structuredText(value:unknown):unknown{
 if(typeof value!=='string')return value;
 let parsed:unknown=value;
 for(let depth=0;depth<2&&typeof parsed==='string'&&/^[\s]*[\[{\"]/.test(parsed);depth++){
  try{parsed=JSON.parse(parsed)}catch{break}
 }
 return parsed!==null&&typeof parsed==='object'?parsed:value;
}
function fieldPath(parent:string,key:string|number){
 if(typeof key==='number')return parent+'['+key+']';
 if(/^[A-Za-z_$][\w$]*$/.test(key))return parent?parent+'.'+key:key;
 return parent+'['+JSON.stringify(key)+']';
}
export function recordFieldRows(value:unknown):RecordFieldRow[]{
 const rows:RecordFieldRow[]=[],pending:Array<{value:unknown;path:string;segments:Array<string|number>;field:string}>=[{value,path:'',segments:[],field:'原始值'}];
 while(pending.length){
  const item=pending.pop()!,current=structuredText(item.value);
  if(current!==null&&typeof current==='object'){
   const entries=Array.isArray(current)?current.map((entry,index)=>[index,entry] as const):Object.entries(current);
   if(entries.length){for(let index=entries.length-1;index>=0;index--){const[key,entry]=entries[index];pending.push({value:entry,path:fieldPath(item.path,key),segments:[...item.segments,key],field:typeof key==='number'?'数组项 '+(key+1):key})}continue;}
   rows.push({id:JSON.stringify(item.segments),path:item.path||'原始值',field:item.field,value:current,kind:Array.isArray(current)?'empty-array':'empty-object'});
  }else rows.push({id:JSON.stringify(item.segments),path:item.path||'原始值',field:item.field,value:current,kind:'value'});
 }
 return rows;
}
function fieldValue(row:RecordFieldRow){
 if(row.kind==='empty-array')return '空数组（0项）';if(row.kind==='empty-object')return '空对象（0字段）';
 if(row.value===null)return '空值（null）';if(row.value===undefined)return '未提供';if(row.value==='')return '空字符串';if(typeof row.value==='boolean')return row.value?'是（true）':'否（false）';return String(row.value);
}
export function RecordFieldsTable({value,title='完整留存字段',labels={}}:{value:unknown;title?:string;labels?:Record<string,string>}){
 const rows=useMemo(()=>recordFieldRows(value),[value]),dictionary={...names,...labels};
 return <section className="record-fields" aria-label={title}><div className="module-toolbar"><Typography.Title level={5}>{title}</Typography.Title><Typography.Text copyable={{text:JSON.stringify(value,null,2)??String(value)}}>复制原始 JSON</Typography.Text></div>
 <Table<RecordFieldRow> rowKey="id" size="small" dataSource={rows} pagination={paginationDefaults} scroll={{x:540}} columns={[
  {title:'字段',key:'field',width:220,render:(_,row)=><div><span>{Object.hasOwn(dictionary,row.field)?dictionary[row.field]:row.field}</span><div className="evidence-secondary record-field-path">{row.path}</div></div>},
  {title:'实际留存内容',key:'value',render:(_,row)=><span className="record-field-value">{fieldValue(row)}</span>},
 ]}/></section>;
}
