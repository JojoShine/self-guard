import {useEffect,useState} from 'react';
import {Alert,Descriptions} from 'antd';
import {api} from './api';
export type DatabaseCapability={engine:string;name:string;runtime:{supported:boolean;requirements:string[];message:string;validation?:string};rawStatement:{supported:boolean;kind:'SQL'|'COMMAND';formats:string[];message:string};auditFormats:{value:string;label:string;kind:'CONNECTION'|'OPERATIONS'|'STATEMENT';notes:string}[];notes:string[]};
export function useDatabaseCapabilities(){
 const[items,setItems]=useState<DatabaseCapability[]>([]),[error,setError]=useState(''),[loading,setLoading]=useState(true);
 useEffect(()=>{let active=true;api('/database-instances/capabilities').then((r:{items:DatabaseCapability[]})=>{if(active)setItems(r.items)}).catch((e:Error)=>{if(active)setError(e.message)}).finally(()=>{if(active)setLoading(false)});return()=>{active=false}},[]);
 return{items,error,loading};
}
export function DatabaseCapabilityView({value}:{value:DatabaseCapability}){return <div className="module-stack"><Alert showIcon type={value.runtime.supported?'info':'warning'} message={value.name+' · 接入能力'} description="能力说明是接入前提，实际版本和权限以本实例只读检查及入库记录验收。"/><Descriptions column={1} size="small" items={[
 {key:'runtime',label:'运行指标',children:value.runtime.message},
 {key:'requirements',label:'连接前提',children:value.runtime.requirements.join('；')||'请核对版本与只读权限'},
 {key:'validation',label:'版本验收',children:value.runtime.validation==='ADAPTER_PROFILE'?'已有采样适配，当前实例版本待实测':value.runtime.validation==='VERIFIED_PROFILE'?'已有适配验证，当前实例仍需检查版本和权限':value.runtime.validation||'等待本实例实测'},
 {key:'statement',label:value.rawStatement.kind==='COMMAND'?'命令原文':'SQL原文',children:value.rawStatement.message},
 {key:'notes',label:'审计注意事项',children:value.notes.join('；')||'需显式配置来源，并核对实际入库'},
 ]}/></div>}
