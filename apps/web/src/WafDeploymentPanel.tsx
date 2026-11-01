import {useEffect,useRef,useState} from 'react';
import {Alert,App,Button,Drawer,Form,Input,InputNumber,Select,Table,Typography} from 'antd';
import {api} from './api';import {ModuleSection,ModuleToolbar,StatusTag} from './ModuleSection';import {paginationDefaults,pageWithinTotal} from './pagination';import {formatTime} from './presentation';

export function WafDeploymentPanel({bundle,canManage,onClose}:{bundle?:any;canManage:boolean;onClose:()=>void}){
 const [rows,setRows]=useState<any[]>([]),[total,setTotal]=useState(0),[page,setPage]=useState(1),[size,setSize]=useState(15),[q,setQ]=useState(''),[options,setOptions]=useState<any>(),[error,setError]=useState(''),[busy,setBusy]=useState(false),[loading,setLoading]=useState(false),[change,setChange]=useState<{row:any;kind:'enforce'|'rollback'}>();
 const [form]=Form.useForm(),[reasonForm]=Form.useForm(),request=useRef(0),{message}=App.useApp();
 async function load(){const id=++request.current;setLoading(true);try{const [result,settings]=await Promise.all([api(`/waf-rule-deployments?page=${page}&pageSize=${size}&q=${encodeURIComponent(q)}`),api('/waf-rule-deployments/options')]);if(id!==request.current)return;const current=pageWithinTotal(page,result.total,size);if(current!==page){setPage(current);return;}setRows(result.items);setTotal(result.total);setOptions(settings);setError('');}catch(e){if(id===request.current)setError((e as Error).message);}finally{if(id===request.current)setLoading(false);}}
 useEffect(()=>{void load();return()=>{request.current++;};},[page,size,q,bundle?.id]);
 useEffect(()=>{if(bundle){setError('');form.resetFields();form.setFieldsValue({threshold:5,siteIds:[]});setChange(undefined);}},[bundle?.id]);
 async function observe(){try{const values=await form.validateFields();setBusy(true);await api('/waf-rule-deployments/observe/'+bundle.id,values);message.success('观察版本已签发，等待节点确认');onClose();await load();}catch(e){if(e instanceof Error)setError(e.message);}finally{setBusy(false);}}
 async function applyChange(){if(!change)return;try{const values=await reasonForm.validateFields();setBusy(true);await api(`/waf-rule-deployments/${change.row.id}/${change.kind}`,values);message.success('新版本已签发，等待节点确认');setChange(undefined);await load();}catch(e){if(e instanceof Error)setError(e.message);}finally{setBusy(false);}}
 const enabled=options?.runtimeEnabled&&options?.signingConfigured;
 return <div className="module-stack waf-panel">
  <ModuleSection title="规则发布与节点确认" description="先对选定站点观察发布，核对节点确认后切换阻断；回退会保留历史并生成新版本。" extra={<Button loading={loading} disabled={busy} onClick={()=>void load()}>刷新发布状态</Button>}>
   {error&&!bundle&&!change&&<Alert type="error" showIcon message={error}/>}
   {options&&!enabled&&<Alert type="info" showIcon message="站点规则发布正在验收" description="候选导入、兼容检查和 HTTP 样本验证可继续使用。入站、业务误报和性能验收通过后开放运行发布。"/>}
   <ModuleToolbar><Input.Search aria-label="搜索规则发布" placeholder="搜索发布说明或操作者" allowClear style={{width:320,maxWidth:'100%'}} onSearch={value=>{setQ(value);setPage(1);}}/></ModuleToolbar>
   <Table<any> rowKey="id" loading={loading} dataSource={rows} scroll={{x:1100}} pagination={{...paginationDefaults,current:page,pageSize:size,total,onChange:(p,s)=>{setPage(s===size?p:1);setSize(s);}}} columns={[
    {title:'站点',dataIndex:'siteName',width:160},{title:'策略版本',dataIndex:'siteVersion',width:100},{title:'模式',dataIndex:'mode',width:110,render:value=><StatusTag value={value}/>},
    {title:'节点确认',render:(_,row)=><div><StatusTag value={row.status} labels={{PENDING:'等待节点确认',ACKNOWLEDGED:'在线节点已确认',HISTORICAL:'历史发布'}} tone={row.status==='ACKNOWLEDGED'?'success':row.status==='PENDING'?'processing':'default'}/>{row.current&&<Typography.Paragraph type="secondary">{row.acknowledgedNodes.length} / {row.expectedOnlineNodes} 个在线节点</Typography.Paragraph>}</div>},
    {title:'发布说明',dataIndex:'reason',width:260},{title:'签发时间',dataIndex:'createdAt',render:formatTime,width:180},
    {title:'操作',width:170,render:(_,row)=>canManage&&enabled?<ModuleToolbar>{row.current&&row.mode==='OBSERVE'&&<Button disabled={busy||row.status!=='ACKNOWLEDGED'} onClick={()=>{setError('');onClose();reasonForm.resetFields();setChange({row,kind:'enforce'});}}>切换阻断</Button>}{!row.current&&<Button disabled={busy} onClick={()=>{setError('');onClose();reasonForm.resetFields();setChange({row,kind:'rollback'});}}>回退到此规则</Button>}</ModuleToolbar>:<Typography.Text type="secondary">{row.current?'当前发布':'历史记录'}</Typography.Text>},
   ]}/>
  </ModuleSection>
  {bundle&&<Drawer open placement="right" width="min(760px, calc(100vw - 24px))" className="record-drawer waf-drawer" title={'观察发布 · '+bundle.name} closable={!busy} maskClosable={!busy} onClose={()=>{if(!busy)onClose()}} extra={<Button disabled={busy} onClick={onClose}>取消发布</Button>}><Typography.Paragraph type="secondary">需要正常与攻击 HTTP 样本均符合预期，首次发布固定使用观察模式。</Typography.Paragraph>{options&&!enabled&&<Alert type="info" showIcon message="站点规则发布正在验收，当前不能签发运行版本"/>}
   {error&&<Alert type="error" showIcon message={error}/>}<Form form={form} layout="vertical" disabled={busy||!enabled}>
    <Form.Item name="siteIds" label="观察站点" rules={[{required:true,message:'请选择至少一个站点'}]} extra="只向明确选择的启用站点发布，可先选一处业务试运行；不会自动选择全部站点。"><Select mode="multiple" showSearch optionFilterProp="label" placeholder="选择业务站点" options={options?.sites?.filter((site:any)=>site.enabled).map((site:any)=>({value:site.id,label:`${site.name} · ${site.hostname}`}))}/></Form.Item>
    <Form.Item name="threshold" label="异常评分阈值" rules={[{required:true}]} extra="达到此分值时标记阻断条件；观察模式仍转发可完整检查的请求。请与样本验证使用同一阈值。"><InputNumber min={1} max={100}/></Form.Item>
    <Form.Item name="reason" label="观察计划与业务说明" rules={[{required:true,min:5,max:1000}]} extra="说明试运行业务、正常请求样本和观察安排，便于后续判断误报及回退。"><Input.TextArea rows={3} maxLength={1000} showCount placeholder="例如：先观察支付测试站点，核对登录和下单请求是否误报"/></Form.Item>
   </Form><ModuleToolbar><Button type="primary" aria-label="签发观察版本" loading={busy} disabled={busy||!enabled||!canManage} onClick={()=>void observe()}>签发观察版本</Button></ModuleToolbar>
  </Drawer>}
  {change&&<Drawer open placement="right" width="min(760px, calc(100vw - 24px))" className="record-drawer waf-drawer" title={change.kind==='enforce'?'确认切换阻断':'回退规则版本'} closable={!busy} maskClosable={!busy} onClose={()=>{if(!busy)setChange(undefined)}} extra={<Button disabled={busy} onClick={()=>setChange(undefined)}>取消操作</Button>}><Typography.Paragraph type="secondary">{change.kind==='enforce'?'在线节点已确认观察版本，请说明业务验证结论。切换后命中规则会实际拒绝请求。':'恢复所选历史规则与模式，保持当前站点地址和访问配置，并签发更高版本。'}</Typography.Paragraph>
   {error&&<Alert type="error" showIcon message={error}/>}<Form form={reasonForm} layout="vertical" disabled={busy}><Form.Item name="reason" label={change.kind==='enforce'?'业务验证与切换依据':'回退原因'} rules={[{required:true,min:5,max:1000}]} extra="填写具体业务验证结果或回退原因；操作会留存审计，不会覆盖旧发布记录。"><Input.TextArea rows={3} maxLength={1000} showCount/></Form.Item></Form>
   <ModuleToolbar><Button type="primary" aria-label={change.kind==='enforce'?'签发阻断版本':'签发回退版本'} loading={busy} disabled={busy} onClick={()=>void applyChange()}>{change.kind==='enforce'?'签发阻断版本':'签发回退版本'}</Button></ModuleToolbar>
  </Drawer>}
 </div>;
}
