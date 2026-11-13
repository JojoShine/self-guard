import {useEffect,useRef,useState} from 'react';
import {Alert,Button,Collapse,Empty,Form,Input,Layout,Popconfirm,Select,Space,Table,Tag,Typography} from 'antd';
import {api} from './api';
import {Brand} from './Brand';
import {ModuleSection,ModuleToolbar} from './ModuleSection';

type Profile='OUTDATED'|'CURRENT';
type FindingStatus='OPEN'|'CONFIRMED'|'RESOLVED';
export type DemoState={
 revision:number;expiresAt:number;
 assets:{id:string;name:string;profile:Profile}[];
 scans:{id:string;name:string;assetIds:string[];status:'READY'|'DONE';findingIds:string[]}[];
 findings:{id:string;scanId:string;assetId:string;title:string;summary:string;status:FindingStatus}[];
 sqlSamples:{id:string;label:string;statements:{sql:string;stage:'QUERY'|'PREPARE'|'EXECUTE'}[];state:string;reasons:string[]}[];
};
type DemoAction={action:'ADD_ASSET';name:string;profile:Profile}|{action:'REMOVE_ASSET';id:string}|{action:'CREATE_SCAN';name:string;assetIds:string[]}|{action:'EXECUTE_SCAN';id:string}|{action:'UPDATE_FINDING';id:string;status:FindingStatus}|{action:'PARSE_SQL';sample:'SIMPLE'|'PREPARED'|'TLS'}|{action:'RESET'};
type ContentProps={state?:DemoState;busy:boolean;error:string;onRefresh:()=>void;onAction:(action:DemoAction)=>Promise<boolean>;onLogout:()=>Promise<void>};
const findingLabels:Record<FindingStatus,string>={OPEN:'待确认',CONFIRMED:'已确认',RESOLVED:'已解决'};
const sqlStateLabels:Record<string,string>={EXTRACTED:'已提取 SQL',PARTIAL:'仅提取部分 SQL',UNAVAILABLE:'无法提取 SQL',UNSUPPORTED:'协议暂不支持'};
const sqlStageLabels={QUERY:'查询请求',PREPARE:'准备语句',EXECUTE:'执行请求'};
const sqlReasonLabels:Record<string,string>={TLS_NO_PLAINTEXT:'样例流量已加密，没有可用明文，无法提取 SQL。',PREPARED_CONTEXT_MISSING:'缺少准备语句上下文，无法可靠还原执行请求。',PROTOCOL_UNSUPPORTED:'当前协议尚不支持 SQL 提取。',REQUEST_TOO_LARGE:'样例报文超过解析大小限制。',BODY_NOT_CAPTURED:'样例报文没有请求正文。',AUTHENTICATION_MESSAGE:'这是认证消息，不作为 SQL 请求展示。',INVALID_ENCODING:'SQL 字符编码无法可靠识别。',SQL_TOO_LARGE:'SQL 超过正文大小限制，无法完整展示。',INVALID_FRAME:'样例报文结构无效，无法可靠提取 SQL。',STATEMENT_LIMIT:'样例请求超过语句数量或解析预算限制。',NO_SQL_MESSAGE:'本样例没有可提取的 SQL 请求，不代表数据库没有执行查询。'};
export function DemoSqlResult({result}:{result:DemoState['sqlSamples'][number]}){
 return <div className="module-stack"><Typography.Text type="secondary">合成报文解析结果；执行请求不证明执行成功或事务提交。准备语句保留占位符，不插值绑定参数。</Typography.Text>{result.reasons.map((reason,i)=><Alert key={i} type="info" message={sqlReasonLabels[reason]||'解析器返回了其他限制，请刷新空间后重试。'}/>)}{result.statements.length?result.statements.map((statement,i)=><div key={i}><Tag>{sqlStageLabels[statement.stage]}</Tag><pre>{statement.sql}</pre></div>):<Typography.Paragraph>未提取到可见 SQL。加密报文不等于无查询。</Typography.Paragraph>}</div>;
}


export function DemoWorkspace({onLogout}:{onLogout:()=>Promise<void>}){
 const[state,setState]=useState<DemoState>(),[busy,setBusy]=useState(false),[error,setError]=useState('');
 const active=useRef(false),pending=useRef(false),version=useRef(0);
 async function request(action?:DemoAction):Promise<boolean>{
  if(pending.current||!active.current)return false;
  if(action&&(!state||state.expiresAt<=Date.now())){setState(undefined);setError('体验空间已到期，请刷新空间重新开始。');return false;}
  pending.current=true;const current=++version.current;setBusy(true);setError('');
  try{
   const next:DemoState=await api('/demo-workspace',action?{revision:state!.revision,...action}:undefined);
   if(!active.current||current!==version.current)return false;
   if(next.expiresAt<=Date.now())throw new Error('体验空间已到期，请刷新空间重新开始。');
   setState(next);return true;
  }catch(e){
   if(active.current&&current===version.current){setState(undefined);setError(e instanceof Error?e.message:'请求失败，请刷新空间重试。');}
   return false;
  }finally{if(active.current&&current===version.current){pending.current=false;setBusy(false);}}
 }
 useEffect(()=>{active.current=true;pending.current=false;void request();return()=>{active.current=false;version.current++;pending.current=false}},[]);
 useEffect(()=>{
  if(!state)return;
  const timer=setTimeout(()=>{version.current++;pending.current=false;setBusy(false);setState(undefined);setError('体验空间已到期，请刷新空间重新开始。');},Math.max(0,state.expiresAt-Date.now()));
  return()=>clearTimeout(timer);
 },[state]);
 return <DemoWorkspaceContent state={state} busy={busy} error={error} onRefresh={()=>void request()} onAction={request} onLogout={onLogout}/>;
}

export function DemoWorkspaceContent({state,busy,error,onRefresh,onAction,onLogout}:ContentProps){
 const[assetForm]=Form.useForm<{name:string;profile:Profile}>(),[scanForm]=Form.useForm<{name:string;assetIds:string[]}>();
 const[sample,setSample]=useState<'SIMPLE'|'PREPARED'|'TLS'>('SIMPLE');
 const[logoutError,setLogoutError]=useState(''),[loggingOut,setLoggingOut]=useState(false);
 const mounted=useRef(false);
 useEffect(()=>{mounted.current=true;return()=>{mounted.current=false}},[]);
 return <Layout className="app-shell" aria-busy={busy}><Layout.Content className="page"><div className="module-stack">
  <ModuleToolbar><Brand/><Typography.Title level={2}>可操作体验空间</Typography.Title><Space wrap><Button onClick={onRefresh} disabled={busy}>刷新空间</Button><Button loading={loggingOut} onClick={async()=>{setLoggingOut(true);setLogoutError('');try{await onLogout()}catch(e){if(mounted.current)setLogoutError(e instanceof Error?e.message:'退出失败，请重试。')}finally{if(mounted.current)setLoggingOut(false)}}}>退出登录</Button></Space></ModuleToolbar>
  <Alert type="info" showIcon message="样例数据 · 非生产 · 会话独立" description="操作结果保存到服务端的本次登录空间；8 小时到期重置。版本检查仅运行预设样例规则，不访问目标，不代表真实 CVE 或网络漏洞扫描；不会远程安装、不连接生产数据库。"/>
  {(error||logoutError)&&<Alert type="error" showIcon message={error||logoutError} description="请刷新空间后重试。未成功的操作不会自动重试。"/>}
  {!state?<Empty description={busy?'正在读取体验空间…':'空间数据不可用，请刷新空间。'}/>:<>
  <ModuleToolbar><Typography.Text type="secondary">本空间到期：{new Date(state.expiresAt).toLocaleString()} · 版本 {state.revision}</Typography.Text><Popconfirm title="重置本空间？" description="将清除本次登录的资产、任务、问题和 SQL 解析结果，恢复初始样例。其他会话不受影响。" okText="确认重置" cancelText="取消" disabled={busy} onConfirm={()=>onAction({action:'RESET'})}><Button danger disabled={busy}>重置本空间</Button></Popconfirm></ModuleToolbar>
  <ModuleSection title="样例资产" description={`可添加不同版本的合成资产，不需要真实 IP 或凭据。${state.assets.length}/20 资产。`}>
   <Form form={assetForm} layout="vertical" initialValues={{profile:'OUTDATED'}} onFinish={async values=>{if(await onAction({action:'ADD_ASSET',name:values.name.trim(),profile:values.profile}))assetForm.resetFields()}}>
    <Space wrap align="start"><Form.Item name="name" label="样例资产名称" rules={[{required:true,whitespace:true,message:'请输入样例名称'}]}><Input maxLength={80} disabled={busy} placeholder="例如：测试 Web 主机"/></Form.Item><Form.Item name="profile" label="样例版本" rules={[{required:true}]}><Select disabled={busy} options={[{value:'OUTDATED',label:'旧版（会产生样例问题）'},{value:'CURRENT',label:'当前版本'}]}/></Form.Item><Form.Item label=" "><Button type="primary" htmlType="submit" disabled={busy||state.assets.length>=20}>添加样例资产</Button></Form.Item></Space>
   </Form>
   <Table rowKey="id" dataSource={state.assets} scroll={{x:500}} pagination={false} columns={[{title:'名称',dataIndex:'name'},{title:'预设版本',dataIndex:'profile',render:(value:Profile)=><Tag>{value==='OUTDATED'?'旧版样例':'当前版本样例'}</Tag>},{title:'操作',key:'action',render:(_,row)=><Popconfirm title={`删除样例资产“${row.name}”？`} description="已被任务引用的资产不能删除。" okText="删除" cancelText="取消" disabled={busy} onConfirm={()=>onAction({action:'REMOVE_ASSET',id:row.id})}><Button danger disabled={busy}>删除</Button></Popconfirm>}]}/>
  </ModuleSection>
  <ModuleSection title="样例检查任务" description={`先选资产创建任务，再明确执行样例检查；仅模拟预设版本规则。${state.scans.length}/10 任务。`}>
   <Form form={scanForm} layout="vertical" onFinish={async values=>{if(await onAction({action:'CREATE_SCAN',name:values.name.trim(),assetIds:values.assetIds}))scanForm.resetFields()}}>
    <Form.Item name="name" label="任务名称" rules={[{required:true,whitespace:true,message:'请输入任务名称'}]}><Input maxLength={80} disabled={busy}/></Form.Item><Form.Item name="assetIds" label="检查资产（可多选）" rules={[{required:true,type:'array',min:1,message:'请至少选择一个样例资产'}]}><Select mode="multiple" disabled={busy} options={state.assets.map(asset=>({value:asset.id,label:asset.name}))}/></Form.Item><Button type="primary" htmlType="submit" disabled={busy||!state.assets.length||state.scans.length>=10}>创建检查任务</Button>
   </Form>
   <Table rowKey="id" dataSource={state.scans} scroll={{x:600}} pagination={false} columns={[{title:'任务',dataIndex:'name'},{title:'资产',render:(_,row)=>row.assetIds.map(id=>state.assets.find(asset=>asset.id===id)?.name||id).join('、')},{title:'状态',dataIndex:'status',render:(value:string)=>value==='DONE'?'已完成样例检查':'待执行'},{title:'样例问题',render:(_,row)=>row.findingIds.length},{title:'操作',render:(_,row)=><Button disabled={busy||row.status!=='READY'} onClick={()=>void onAction({action:'EXECUTE_SCAN',id:row.id})}>执行样例检查</Button>}]}/>
  </ModuleSection>
  <ModuleSection title="问题处置" description="以下问题来自样例版本规则，处置状态只保存到当前体验空间。">
   <Table rowKey="id" dataSource={state.findings} scroll={{x:700}} pagination={false} locale={{emptyText:'暂无样例问题；创建并执行旧版资产的样例检查后查看。'}} columns={[{title:'样例问题',dataIndex:'title'},{title:'资产',render:(_,row)=>state.assets.find(asset=>asset.id===row.assetId)?.name||row.assetId},{title:'任务',render:(_,row)=>state.scans.find(scan=>scan.id===row.scanId)?.name||row.scanId},{title:'说明',dataIndex:'summary'},{title:'处置状态',render:(_,row)=><Select aria-label={`${row.title}处置状态`} value={row.status} disabled={busy} options={Object.entries(findingLabels).map(([value,label])=>({value,label}))} onChange={(status:FindingStatus)=>void onAction({action:'UPDATE_FINDING',id:row.id,status})}/>}]} />
  </ModuleSection>
  <ModuleSection title="SQL 样例解析" description={`使用真实报文解析器解析合成报文，不连接数据库，不读取生产数据。保留最近 5 个解析结果，当前 ${state.sqlSamples.length} 个。`}>
   <ModuleToolbar><Select aria-label="SQL 样例" value={sample} disabled={busy} onChange={setSample} options={[{value:'SIMPLE',label:'普通查询报文'},{value:'PREPARED',label:'预处理 / 执行报文'},{value:'TLS',label:'TLS 加密报文（不可见 SQL）'}]}/><Button disabled={busy} onClick={()=>void onAction({action:'PARSE_SQL',sample})}>解析合成样例</Button></ModuleToolbar>
   {state.sqlSamples.length?<Collapse items={state.sqlSamples.map(result=>({key:result.id,label:`${result.label} · ${sqlStateLabels[result.state]||'解析状态待确认'}`,children:<DemoSqlResult result={result}/>}))}/>:<Empty description="尚无解析结果"/>}
  </ModuleSection>
  </>}
 </div></Layout.Content></Layout>;
}
