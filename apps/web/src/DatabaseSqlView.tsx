import {useEffect,useRef,useState} from 'react';
import {Alert,Button} from 'antd';
import {api} from './api';
import {formatTime} from './presentation';

export function DatabaseSqlView({auditId,allowed,timestamp,kind='SQL'}:{auditId:string;allowed:boolean;timestamp:string;kind?:'SQL'|'COMMAND'}){
 const[raw,setRaw]=useState<{id:string;sql:string;expiresAt:string}>(),[error,setError]=useState(''),[busy,setBusy]=useState(false),[expired,setExpired]=useState(false),generation=useRef(0);
 const expires=Date.parse(timestamp)+7*86400000;
 useEffect(()=>{generation.current++;setRaw(undefined);setError('');setBusy(false);setExpired(Date.now()>=expires);const timer=setTimeout(()=>{generation.current++;setRaw(undefined);setExpired(true)},Math.max(0,expires-Date.now()));return()=>{generation.current++;clearTimeout(timer)}},[auditId,allowed,expires]);
 async function load(){const current=generation.current;setError('');setBusy(true);try{const value=await api('/data-security/events/'+auditId+'/sql');if(current===generation.current&&Date.now()<Date.parse(value.expiresAt))setRaw({id:auditId,sql:value.sql,expiresAt:value.expiresAt})}catch(e){if(current===generation.current)setError((e as Error).message)}finally{if(current===generation.current)setBusy(false)}}
 const label=kind==='COMMAND'?'命令':'SQL';
 if(expired||Date.now()>=expires)return <Alert type="info" message={label+'原文已到期；审计元数据继续保留。'}/>;
 return <div className="module-stack"><p>{kind==='COMMAND'?'命令原文加密保留7天。来源若为慢日志，仅覆盖实际记录的慢命令；不能据此还原全部操作，缺失账号保持未知。':'SQL原文加密保留7天。预编译语句保留占位符，未采集绑定参数；多语句批次耗时属于整个批次，执行完成不代表事务最终提交。'}</p>{error&&<Alert type="error" message={error}/>}<div>{allowed?<Button loading={busy} onClick={()=>{if(raw)setRaw(undefined);else void load()}}>{(raw?'隐藏':'查看')+label+'原文'}</Button>:<Alert type="info" message={'查看'+label+'原文需要独立授权。'}/>}</div>{allowed&&raw?.id===auditId&&<><pre style={{whiteSpace:'pre-wrap',overflowWrap:'anywhere',maxHeight:'28rem',overflow:'auto'}}>{raw.sql}</pre><p>原文到期：{formatTime(raw.expiresAt)}</p></>}</div>
}
