import {useState} from 'react';
import {Alert,Button,Modal,Space,Typography} from 'antd';

export function InlineRecordAction({label,title,description,confirmLabel,danger=false,onConfirm,presentation='inline'}:{label:string;title:string;description:string;confirmLabel:string;danger?:boolean;onConfirm:()=>Promise<void>;presentation?:'inline'|'modal'}){
 const [open,setOpen]=useState(false),[busy,setBusy]=useState(false),[error,setError]=useState('');
 async function submit(){setBusy(true);setError('');try{await onConfirm();setOpen(false)}catch(e){setError((e as Error).message)}finally{setBusy(false)}}
 if(presentation==='modal')return <><Button danger={danger} aria-label={label} onClick={()=>{setError('');setOpen(true)}}>{label}</Button><Modal centered className="module-modal" title={title} open={open} width="min(640px, calc(100vw - 32px))" closable={!busy} maskClosable={!busy} onCancel={()=>{if(!busy)setOpen(false)}} onOk={()=>void submit()} okText={confirmLabel} cancelText="取消操作" confirmLoading={busy} cancelButtonProps={{disabled:busy}} okButtonProps={{danger}}><Typography.Paragraph>{description}</Typography.Paragraph>{error&&<Alert type="error" showIcon message={error}/>}</Modal></>;
 return <div className={'inline-record-action'+(open?' is-open':'')}>
  {!open?<Button danger={danger} aria-label={label} onClick={()=>{setError('');setOpen(true)}}>{label}</Button>:<section className="record-inline-editor" aria-label={title}>
   <Typography.Title level={5}>{title}</Typography.Title><Typography.Paragraph>{description}</Typography.Paragraph>
   {error&&<Alert type="error" showIcon message={error}/>}
   <Space wrap size={8}><Button type="primary" danger={danger} aria-label={confirmLabel} loading={busy} onClick={()=>void submit()}>{confirmLabel}</Button><Button disabled={busy} onClick={()=>setOpen(false)}>取消操作</Button></Space>
  </section>}
 </div>;
}
