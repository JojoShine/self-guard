import {useEffect,useState} from 'react';
import {Alert,Button,Descriptions,Form,Input,Select,Space} from 'antd';
import {api} from './api';
import {RecordSelect} from './RecordSelect';

type Triage={conclusion:string;reason:string;duplicate:{id:string;title:string}|null;duplicateUnavailable?:boolean};
type Props={findingId:string;kind:string;updatedAt?:string;canEdit:boolean;onChanged:(updatedAt:string)=>void;onOpenFinding?:(id:string)=>void};
type Values={conclusion:string;duplicateOfId?:string;reason:string};
export function FindingTriageView({findingId,kind,updatedAt,canEdit,onChanged,onOpenFinding,value}:{value:Triage|null}&Props){
 const[editing,setEditing]=useState(false),[busy,setBusy]=useState(false),[error,setError]=useState(''),[form]=Form.useForm<Values>(),conclusion=Form.useWatch('conclusion',form);
 useEffect(()=>{setEditing(false);setError('')},[findingId]);
 async function save(v:Values){setError('');setBusy(true);try{const next=await api('/findings/'+findingId+'/triage',{conclusion:v.conclusion,reason:v.reason,...(v.conclusion==='DUPLICATE'?{duplicateOfId:v.duplicateOfId}:{}),expectedUpdatedAt:updatedAt});setEditing(false);onChanged(next.finding.updatedAt)}catch(e){setError((e as Error).message)}finally{setBusy(false)}}
 return <div className="module-stack" aria-label="问题核查结论"><p>重复问题、证据不足分别记录依据，保留原处理状态；后续仍需跟进和实际复查。</p>{value&&<Descriptions bordered size="small" column={1} items={[{key:'conclusion',label:'核查结论',children:value.conclusion==='DUPLICATE'?'重复问题':'证据不足'},{key:'reason',label:'判断依据',children:value.reason},...(value.conclusion==='DUPLICATE'?[{key:'duplicate',label:'关联原问题',children:value.duplicate?(onOpenFinding?<Button type="link" onClick={()=>onOpenFinding(value.duplicate!.id)}>{value.duplicate.title}</Button>:value.duplicate.title):'关联问题当前不可读'}]:[])]}/>} {error&&<Alert type="error" message={error} description="记录可能已变化，请刷新详情后再提交。"/>}
 {canEdit&&!editing&&<Button disabled={!updatedAt} onClick={()=>{form.setFieldsValue({conclusion:value?.conclusion||'INSUFFICIENT_EVIDENCE',reason:value?.reason||'',duplicateOfId:value?.duplicate?.id});setEditing(true)}}>记录核查结论</Button>}
 {canEdit&&editing&&<Form form={form} layout="vertical" disabled={busy} onFinish={v=>void save(v)}><Form.Item name="conclusion" label="核查结论" rules={[{required:true}]}><Select aria-label="核查结论" options={[{value:'DUPLICATE',label:'重复问题，关联原问题'},{value:'INSUFFICIENT_EVIDENCE',label:'证据不足，继续补充核查'},{value:'NONE',label:'撤销当前结论，重新核查'}]}/></Form.Item>{conclusion==='DUPLICATE'&&<Form.Item name="duplicateOfId" label="关联原问题" rules={[{required:true,message:'请选择同类型的原问题'}]}><RecordSelect resource="findings" kind={kind} ariaLabel="选择重复问题的原问题"/></Form.Item>}<Form.Item name="reason" label="判断依据" rules={[{required:true,whitespace:true,min:5,max:4000,message:'请填写至少5个字符的实际判断依据'}]}><Input.TextArea aria-label="判断依据" rows={3}/></Form.Item><Space><Button type="primary" htmlType="submit" loading={busy}>保存核查结论</Button><Button disabled={busy} onClick={()=>setEditing(false)}>取消</Button></Space></Form>}
 </div>
}
export function FindingTriagePanel(props:Props){
 const[state,setState]=useState<{id:string;value:Triage|null}>(),[error,setError]=useState(''),[revision,setRevision]=useState(0);
 useEffect(()=>{let active=true;setState(undefined);setError('');api('/findings/'+props.findingId+'/triage').then(v=>{if(active)setState({id:props.findingId,value:v.triage})}).catch(e=>{if(active)setError((e as Error).message)});return()=>{active=false}},[props.findingId,props.updatedAt,revision]);
 if(error)return <Alert type="warning" message="核查结论读取失败" description={error} action={<Button onClick={()=>setRevision(v=>v+1)}>重试</Button>}/>;
 return state?.id===props.findingId?<FindingTriageView key={props.findingId} {...props} value={state.value}/>:<p>正在读取核查结论…</p>;
}
