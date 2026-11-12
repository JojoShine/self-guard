import {DatabaseCapabilityView} from './DatabaseCapabilities';
import type {DatabaseCapability} from './DatabaseCapabilities';
import {MonitoringSummary} from './OperationalMonitoring';
import {ModuleToolbar} from './ModuleSection';
import {useEffect,useState} from 'react';
import {Alert,Button,Descriptions} from 'antd';
import {api} from './api';
import {formatTime} from './presentation';

export type DatabaseCollectionEvidence={checkedAt:string;windowMinutes:number;sources:number;hosts:{authorized:number;reporting:number};recentEvents:number;latestEventAt:string|null;capabilities?:DatabaseCapability;connections?:{recentEvents:number;latestEventAt:string|null};statements?:{collectors?:{required:number;ready:number};sources:number;recentEvents:number;latestEventAt:string|null;retainedTextRecords:number};operations?:{recentEvents:number}};
export function DatabaseCollectionEvidenceView({value,engine}:{value:DatabaseCollectionEvidence;engine?:string}){
 const message=!value.sources?'未配置日志来源':!value.hosts.reporting?'等待采集主机上报':!value.recentEvents?'等待日志入库':'近期收到审计记录';
 return <><Alert showIcon type={value.sources&&value.hosts.reporting&&value.recentEvents?'info':'warning'} message={message} description="实例登记和来源配置不代表完整覆盖；近期记录只证明收到相应日志。连接日志与请求响应正文分别接入和验收。"/><Descriptions size="small" column={1} items={[
  {key:'sources',label:'当前范围日志来源',children:value.sources+' 个'},
  {key:'hosts',label:'采集主机',children:value.hosts.authorized+' 个 · 90秒内上报 '+value.hosts.reporting+' 个'},
  {key:'events',label:'近'+value.windowMinutes+'分钟采集入库',children:value.recentEvents+' 条'},
  {key:'latest',label:'最近采集事件',children:value.latestEventAt?formatTime(value.latestEventAt):'尚无采集记录'},
 ]}/>{value.connections&&<Descriptions column={1} items={[{key:'connections',label:'连接审计',children:value.connections.recentEvents+' 条 · '+(value.connections.latestEventAt?formatTime(value.connections.latestEventAt):'尚无连接记录')},{key:'operations',label:'操作元数据',children:value.operations?value.operations.recentEvents+' 条':'未取得'}]}/>}<h3>{engine==='redis'?'命令原文验收':'SQL原文验收'}</h3>{value.statements?.collectors&&value.statements.collectors.required>value.statements.collectors.ready&&<Alert type="warning" message="原文采集器能力待确认" description={'新格式来源主机 '+value.statements.collectors.required+' 个，已确认支持 '+value.statements.collectors.ready+' 个；请安装Agent0.4.24或更新版本并等待能力上报。主机在线不代表支持此日志格式。'}/> }<Alert type="info" message={!value.statements?'语句入库状态未取得':!value.statements.sources?'未配置原文来源':!value.statements.recentEvents?(engine==='redis'?'等待命令入库':'等待语句入库'):(engine==='redis'?'近期收到命令记录':'近期收到语句记录')} description={value.statements?'原文来源 '+value.statements.sources+' 个 · 近期'+(engine==='redis'?'命令 ':'语句 ')+value.statements.recentEvents+' 条 · 保留原文 '+value.statements.retainedTextRecords+' 条；收到记录不代表执行成功或完整覆盖。':'服务端尚未返回独立语句验收数据，不能用连接事件推断。'}/></>;
}
export function DatabaseCollectionStatus({instanceId,engine,onConfigure,onRuntime,onRecords,onOnboarding}:{instanceId:string;engine?:string;onOnboarding?:()=>void;onConfigure?:()=>void;onRuntime?:()=>void;onRecords?:()=>void}){
 const[value,setValue]=useState<DatabaseCollectionEvidence>(),[error,setError]=useState(''),[revision,setRevision]=useState(0),[runtime,setRuntime]=useState<{state:string;monitor:{lastSuccessAt?:string|null;lastError?:string|null}|null}>(),[runtimeError,setRuntimeError]=useState('');
 useEffect(()=>{let active=true;setValue(undefined);setError('');api('/database-instances/'+instanceId+'/collection').then((v:DatabaseCollectionEvidence)=>{if(active)setValue(v)}).catch((e:Error)=>{if(active)setError(e.message)});return()=>{active=false}},[instanceId,revision]);
 useEffect(()=>{let active=true;setRuntime(undefined);setRuntimeError('');api('/database-instances/'+instanceId+'/runtime-monitor').then(r=>{if(active)setRuntime(r)}).catch((e:Error)=>{if(active)setRuntimeError(e.message)});return()=>{active=false}},[instanceId,revision]);
 return <div className="module-stack"><Alert showIcon type="info" message="实例已登记，等待逐项验收" description="保存身份、入口或密码不代表连接成功。运行样本、连接审计与语句原文分别核对。"/><ModuleToolbar>{onOnboarding&&<Button type="primary" onClick={onOnboarding}>自动接入</Button>}{onConfigure&&<Button onClick={onConfigure}>配置入口与审计来源</Button>}{onRuntime&&<Button onClick={onRuntime}>配置并验证运行连接</Button>}{onRecords&&<Button onClick={onRecords}>{engine==='redis'?'查看此实例连接与命令':'查看此实例连接与SQL'}</Button>}</ModuleToolbar><h3>运行连接验收</h3>{runtimeError?<Alert type="error" message="运行验收状态读取失败" description={runtimeError}/>:runtime?<MonitoringSummary state={runtime.state} lastSuccessAt={runtime.monitor?.lastSuccessAt} lastError={runtime.monitor?.lastError}/>:<p>正在核对运行样本…</p>}{value?.capabilities&&<DatabaseCapabilityView value={value.capabilities}/>}<h3>审计入库验收</h3>{error?<Alert type="error" showIcon message="采集状态读取失败" description={error}/>:value?<DatabaseCollectionEvidenceView value={value} engine={engine}/>:<p>正在核对采集状态…</p>}<Button onClick={()=>setRevision(x=>x+1)}>刷新采集状态</Button></div>;
}
