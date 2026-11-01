import {paginationDefaults} from './pagination';
import {ModuleSection,ModuleToolbar,StatusTag} from './ModuleSection';
import './detection-panels.css';
import {useEffect,useState} from 'react';
import {Alert,Button,Form,Input,Modal,Space,Switch,Table,Typography} from 'antd';
import {api} from './api';
import {formatTime} from './presentation';
export function CertificatePanel(){
 const[canManage,setCanManage]=useState(false);const[form]=Form.useForm();const[rows,setRows]=useState<any[]>([]);const[loading,setLoading]=useState(false);const[error,setError]=useState('');const[open,setOpen]=useState(false);const[editing,setEditing]=useState<any>();
 async function load(){setLoading(true);setError('');try{setRows((await api('/certificates')).items);setCanManage(true)}catch(e){setCanManage(false);setError((e as Error).message)}finally{setLoading(false)}}
 useEffect(()=>{void load()},[]);
 function edit(row?:any){setEditing(row);setError('');form.resetFields();if(row)form.setFieldValue('hostname',row.hostname);setOpen(true)}
 async function save(){try{const values=await form.validateFields();setLoading(true);setError('');const body=editing?{certificate:values.certificate,privateKey:values.privateKey}:values;await api(editing?'/certificates/'+editing.id+'/rotate':'/certificates',body);setOpen(false);form.resetFields();await load()}catch(e){if(e instanceof Error)setError(e.message)}finally{setLoading(false)}}
 async function status(row:any,enabled:boolean){setLoading(true);setError('');try{await api('/certificates/'+row.id+'/status',{enabled},'PATCH');await load()}catch(e){setError((e as Error).message)}finally{setLoading(false)}}
 return <div className="module-stack detection-panel">
 {error&&<Alert type="error" message={error} showIcon closable onClose={()=>setError('')}/>}
 <ModuleSection title="站点证书" description="查看证书有效期、管理端版本与启用状态。"><details className="module-note detection-guidance"><summary>{"集中管理站点证书"}</summary><p>管理员上传匹配域名的 PEM 证书链与私钥，服务端检查有效期和密钥匹配后加密保存私钥。启用远程证书管理的 WAF 节点每 10 秒同步；节点本地证书配置优先。轮换失败保留上一份有效证书，过期证书拒绝新 TLS 握手。此处版本代表管理端版本，节点同步需结合节点运行状态确认。</p></details>
 <ModuleToolbar><Button type="primary" disabled={loading||!canManage} onClick={()=>edit()}>上传站点证书</Button><Button loading={loading} onClick={()=>void load()}>刷新证书</Button></ModuleToolbar>
 <Table<any> pagination={paginationDefaults} rowKey="id" dataSource={rows} loading={loading} locale={{emptyText:'暂无站点证书，请上传证书链与私钥'}} scroll={{x:1050}} columns={[
 {title:'域名',dataIndex:'hostname',render:v=><span className="module-record-title">{v}</span>},{title:'有效期至',dataIndex:'notAfter',render:(value:string)=>{const remaining=new Date(value).getTime()-Date.now(),expired=remaining<=0,expiring=remaining<30*86400000;return <Space direction="vertical" size={6}><span className="record-cell-time">{formatTime(value)}</span><StatusTag value={expired?'EXPIRED':expiring?'EXPIRING':'VALID'} label={expired?'已过期':expiring?'30天内到期':'有效'} tone={expired?'error':expiring?'warning':'success'}/></Space>}},{title:'版本',dataIndex:'version'},{title:'SHA-256 指纹',dataIndex:'fingerprint',render:v=><Typography.Text code style={{maxWidth:300,display:'block',overflowWrap:'anywhere'}}>{v}</Typography.Text>},{title:'启用',render:(_,row)=><Switch aria-label="启用站点证书" checkedChildren="启用" unCheckedChildren="停用" checked={row.enabled} disabled={loading||!canManage} onChange={checked=>void status(row,checked)}/>},{title:'操作',render:(_,row)=><Button disabled={loading||!canManage} onClick={()=>edit(row)}>轮换证书</Button>}
 ]}/>
 </ModuleSection>
 <Modal className="module-modal" title={editing?'轮换站点证书':'上传站点证书'} open={open} onOk={()=>void save()} confirmLoading={loading} okText={editing?'保存轮换':'保存证书'} closable={!loading} maskClosable={!loading} cancelButtonProps={{disabled:loading}} onCancel={()=>{if(!loading){setOpen(false);form.resetFields()}}} width={760}>
 {error&&<Alert type="error" message={error} style={{marginBottom:12}}/>}
 <Form form={form} layout="vertical" className="detection-form module-form-grid" disabled={loading}>
 <Form.Item className="module-field-wide" name="hostname" label="证书域名" rules={[{required:true,whitespace:true}]} extra="填写此节点服务的完整域名，例如 app.example.com；证书可以通过 SAN 或通配符覆盖该域名。"><Input disabled={!!editing} autoComplete="off" placeholder="app.example.com"/></Form.Item>
 <Form.Item name="certificate" label="证书链 PEM" rules={[{required:true,whitespace:true}]} extra="以站点证书开头，后接中间证书；不需要上传根证书。"><Input.TextArea rows={7} autoComplete="off" spellCheck={false} placeholder={'-----BEGIN CERTIFICATE-----\n…\n-----END CERTIFICATE-----'}/></Form.Item>
 <Form.Item name="privateKey" label="私钥 PEM" rules={[{required:true,whitespace:true}]} extra="使用未加口令的 PEM 私钥。保存后不会在界面返回，轮换时需重新提供。"><Input.TextArea rows={7} autoComplete="off" spellCheck={false} placeholder={'-----BEGIN PRIVATE KEY-----\n…\n-----END PRIVATE KEY-----'}/></Form.Item>
 </Form>
 </Modal>
 </div>
}
