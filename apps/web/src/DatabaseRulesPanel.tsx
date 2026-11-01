import {useEffect,useState} from 'react';
import {Alert,App,Button,Form,Input,InputNumber,Select,Spin,Table} from 'antd';
import {api} from './api';
import {ModuleSection,ModuleToolbar} from './ModuleSection';
import {paginationDefaults} from './pagination';
const formats=[{value:'mysql',label:'MySQL 原生错误日志'},{value:'postgresql',label:'PostgreSQL jsonlog'},{value:'audit-json',label:'标准连接审计 JSON'}];
export function DatabaseRulesPanel({onCreated}:{onCreated:()=>void}){
 const[items,setItems]=useState<any[]>([]),[assets,setAssets]=useState<any[]>([]),[selected,setSelected]=useState<any>(),[busy,setBusy]=useState(false),[error,setError]=useState('');const[form]=Form.useForm();
 useEffect(()=>{void api('/rule-tools/catalog/database').then(r=>setItems(r.items)).catch(e=>setError(e.message))},[]);
 async function choose(row:any){setError('');setBusy(true);try{const r=await api('/scan-plans/options');setAssets(r.assets);setSelected(row);form.resetFields();form.setFieldsValue({format:row.formats?.[0],threshold:row.type==='DATABASE_CLEARTEXT'?1:5,windowSeconds:60})}catch(e){setError((e as Error).message)}finally{setBusy(false)}}
 async function save(values:any){setBusy(true);setError('');try{const config:any={type:selected.type,path:values.path,applicability:{assetIds:values.assetIds}};if(selected.kind==='LOG')Object.assign(config,{service:values.format,threshold:selected.type==='DATABASE_CLEARTEXT'?1:values.threshold,windowSeconds:values.windowSeconds});else config.key=selected.key;await api('/rules',{name:selected.name,kind:selected.kind,severity:selected.severity,enabled:true,config});setSelected(undefined);onCreated()}catch(e){setError((e as Error).message)}finally{setBusy(false)}}
 return <ModuleSection title="数据安全基础规则" description="选择模板后明确指定资产、配置或日志路径。需要支持 data-security-v1 的 Agent；未接入日志不等于没有攻击，配置检查不等于真实连接审计。">
 <div className="module-stack">
 {error&&!selected&&<Alert showIcon type="error" message={error}/>}
 <Table rowKey="id" dataSource={items} pagination={{...paginationDefaults,total:items.length}} scroll={{x:720}} columns={[{title:'基础规则',dataIndex:'name',width:250,render:(_:any,row:any)=><Button type="link" className="record-title-link" loading={busy} onClick={()=>void choose(row)}>{row.name}</Button>},{title:'检测依据与边界',dataIndex:'description'}]}/>
 {selected&&<ModuleSection title={'配置规则 · '+selected.name} onClose={()=>setSelected(undefined)} busy={busy} error={error}>
 <Alert showIcon type="info" message={selected.description}/>
 <Form form={form} layout="vertical" onFinish={v=>void save(v)} disabled={busy}>
 <Form.Item name="assetIds" label="适用资产" rules={[{required:true}]} extra="明确选择数据库所在主机；不会自动对全部资产启用或尝试数据库口令。"><Select mode="multiple" showSearch optionFilterProp="label" options={assets.map(a=>({value:a.id,label:a.hostname}))}/></Form.Item>
 <Form.Item name="path" label={selected.kind==='LOG'?'日志文件绝对路径':'配置或凭据文件绝对路径'} rules={[{required:true},{pattern:/^\/.+/,message:'填写实际文件的绝对路径'}]} extra="选择实例实际使用的文件路径。Agent 服务账户须具有只读权限，路径须在本地允许范围内；不修改文件或扩大系统权限。"><Input maxLength={4096} placeholder={selected.kind==='LOG'?'/var/log/postgresql/postgresql.json':'/etc/mysql/my.cnf'}/></Form.Item>
 {selected.kind==='LOG'&&<><Form.Item name="format" label="日志格式" rules={[{required:true}]} extra="PostgreSQL使用jsonlog；MySQL使用带原始时间和来源IP的Access denied记录；其他数据库通过标准连接审计JSON接入，不推断缺失字段。"><Select options={formats.filter(f=>selected.formats.includes(f.value))}/></Form.Item>
 {selected.type==='DATABASE_AUTH'&&<Form.Item name="threshold" label="认证失败阈值" rules={[{required:true}]} extra="同一实例路径、同一来源IP在窗口内达到次数后报告疑似爆破，支持同源多账号尝试。"><InputNumber min={1} max={1000}/></Form.Item>}
 <Form.Item name="windowSeconds" label="检测时间窗口（秒）" rules={[{required:true}]} extra="使用日志的原始发生时间；不把历史日志集中读入当作当前攻击，重复采集去重。"><InputNumber min={1} max={86400}/></Form.Item>
 <Alert type="info" showIcon message="标准审计格式" description={'每行一个JSON对象：timestamp（带时区）、service（mysql/postgresql/mongodb/redis/sqlserver）、sourceIp、user、database、outcome（AUTH_FAILURE或CONNECTED），可选sourcePort、tls。明文告警要求outcome=CONNECTED且tls=false；不得把密码或SQL正文放入这些字段。'}/></>}
 <ModuleToolbar><Button type="primary" htmlType="submit" loading={busy}>创建并启用规则</Button><Button onClick={()=>setSelected(undefined)}>取消</Button></ModuleToolbar>
 </Form></ModuleSection>}
 </div></ModuleSection>
}

export function DatabaseRulesPage(){
 const[loading,setLoading]=useState(true),[allowed,setAllowed]=useState(false),[error,setError]=useState('');const{message}=App.useApp();
 useEffect(()=>{let active=true;void api('/auth/me').then(user=>{if(active)setAllowed(['ADMIN','ANALYST'].includes(user.role)&&!(user.role!=='ADMIN'&&(user.dataScope?.restricted||user.dataScope?.canReadEvidence===false)))}).catch(e=>{if(active)setError(e.message)}).finally(()=>{if(active)setLoading(false)});return()=>{active=false}},[]);
 if(loading)return <Spin spinning><div style={{minHeight:100}}/></Spin>;
 if(error)return <Alert type="error" showIcon message={error}/>;
 if(!allowed)return <Alert type="info" showIcon message="当前账户无数据安全规则配置权限" description="基础模板创建规则需要全局规则管理权限；已有发现仍按当前账户的数据范围查看。"/>;
 return <div className="module-stack"><DatabaseRulesPanel onCreated={()=>{void message.success('规则已创建并启用，可在检测规则中查看，并分别配置适用范围与验证样本')}}/><ModuleToolbar><Button type="link" href="#rules">查看已创建的检测规则</Button><Button type="link" href="#rule-scope">管理规则适用范围</Button><Button type="link" href="#rule-test">进行规则样本验证</Button></ModuleToolbar></div>;
}
