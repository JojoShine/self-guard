import {useId,useState} from 'react';
import {Alert,App,Button,Input,Space,Typography} from 'antd';
import {api} from './api';
import {RecordSelect} from './RecordSelect';

export function BusinessSelect({id,ariaLabel,value,onChange,onBusyChange,canCreate=false}:{id?:string;ariaLabel?:string;value?:string;onChange?:(value:string|undefined)=>void;onBusyChange?:(value:boolean)=>void;canCreate?:boolean}){
 const generated=useId(),nameId=(id||generated)+'-business-name';
 const [editing,setEditing]=useState(false),[name,setName]=useState(''),[busy,setBusy]=useState(false),[error,setError]=useState('');const {message}=App.useApp();
 async function create(){const trimmed=name.trim();if(!trimmed){setError('请填写便于团队识别的业务名称');return}setBusy(true);onBusyChange?.(true);setError('');try{const result=await api('/record-options/businesses',{name:trimmed});onChange?.(result.name);setEditing(false);setName('');message.success('业务分组已创建，提交当前操作后应用业务归属')}catch(e){setError((e as Error).message)}finally{setBusy(false);onBusyChange?.(false)}}
 return <div className="business-select">
  <RecordSelect id={id} ariaLabel={ariaLabel} resource="businesses" value={value} onChange={onChange} disabled={busy?true:undefined} placeholder="按名称查找已有业务分组"/>
  {canCreate&&!editing&&<Button className="record-title-link" type="link" onClick={()=>{setEditing(true);setError('')}}>创建业务分组</Button>}
  {canCreate&&editing&&<section className="business-select-editor" aria-label="创建业务分组">
   <label htmlFor={nameId}>新业务名称</label><Input id={nameId} value={name} maxLength={200} disabled={busy?true:undefined} onChange={event=>setName(event.target.value)} placeholder="例如 支付服务"/>
   <Typography.Paragraph type="secondary">登记业务名称，供资产归属和扫描范围选择。创建分组不会移动现有资产，仍需提交当前表单才会应用业务归属。</Typography.Paragraph>
   {error&&<Alert type="error" showIcon message={error}/>}
   <Space wrap size={8}><Button type="primary" aria-label="创建并选择业务" aria-busy={busy} loading={busy} onClick={()=>void create()}>创建并选择业务</Button><Button disabled={busy?true:undefined} onClick={()=>setEditing(false)}>取消创建</Button></Space>
  </section>}
 </div>;
}
