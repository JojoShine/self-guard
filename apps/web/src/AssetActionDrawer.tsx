import {DetailPanel} from './DetailWorkspace';
import {AssetRemoteDrawer} from './AssetRemoteDrawer';
import {useEffect,useState} from 'react';import {Alert,Button,Spin} from 'antd';
import {api} from './api';import {HostNetworkPanel,TrafficCaptureDrawer} from './HostNetworkPanel';import {ExecutorKeyEditor} from './CompletionPanel';import {WorkflowTools} from './WorkflowTools';import type {AssetActionMode} from './AssetListActions';
type Props={role?:string;record:any;mode:AssetActionMode;onClose:()=>void;onChanged:()=>void};
export function AssetActionDrawer(props:Props){
 const[modes,setModes]=useState<AssetActionMode[]>([props.mode]);
 return <>{modes.map((mode,index)=><AssetActionContent key={mode} {...props} mode={mode} onClose={()=>{if(index===0)props.onClose();else setModes(current=>current.slice(0,index))}} onModeChange={next=>setModes(current=>{const existing=current.indexOf(next);return existing>=0?current.slice(0,existing+1):[...current.slice(0,index+1),next]})}/>)}</>;
}
function AssetActionContent({record,mode,onClose,onChanged,onModeChange,role}:Props&{onModeChange:(mode:AssetActionMode)=>void}){
 const[current,setCurrent]=useState<any>(),[loading,setLoading]=useState(false),[error,setError]=useState(''),[busy,setBusy]=useState(false),[retry,setRetry]=useState(0);
 useEffect(()=>{if(['capture','network','connection','install'].includes(mode))return;let active=true;setLoading(true);setCurrent(undefined);setError('');api('/assets/'+record.id).then(value=>{if(active)setCurrent(value)}).catch(e=>{if(active)setError(e.message)}).finally(()=>{if(active)setLoading(false)});return()=>{active=false}},[record.id,mode,retry]);
 if(mode==='connection'||mode==='install')return <AssetRemoteDrawer record={record} mode={mode} onClose={onClose} onCapture={()=>onModeChange?.('capture')}/>;
 if(mode==='capture')return <TrafficCaptureDrawer record={record} onClose={onClose} onConfigure={()=>onModeChange?.('connection')} remoteAllowed={['ADMIN','OPERATOR'].includes(role||'')}/>;
 const title=mode==='network'?'网络结果':mode==='executor'?'执行器结果验签':(current||record).archivedAt?'恢复资产':'归档资产';
 return <DetailPanel open placement="right" className="record-drawer" width="min(800px, calc(100vw - 24px))" title={title+' · '+record.hostname} closable={!busy} maskClosable={!busy} onClose={()=>{if(!busy)onClose()}}><div className="module-stack">
 {mode==='network'?<HostNetworkPanel assetId={record.id}/>:loading?<Spin tip="读取最新资产信息"><div style={{minHeight:120}}/></Spin>:error?<Alert type="error" showIcon message={error} action={<Button onClick={()=>setRetry(value=>value+1)}>重试</Button>}/>:current&&(mode==='executor'?<ExecutorKeyEditor record={current} initialOpen onClose={onClose} onBusyChange={setBusy} onChanged={onChanged}/>:<WorkflowTools resource="assets" record={current} initialMode="archive" onClose={onClose} onBusyChange={setBusy} onChanged={onChanged}/>)}
 </div></DetailPanel>;
}
