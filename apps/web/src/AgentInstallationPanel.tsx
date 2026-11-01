import {apiURL} from './urls';
import {AgentPlatformConnectionPanel,AgentPlatformFields} from './AgentPlatformConnection';
import {BusinessSelect} from './BusinessSelect';
import {AgentProfileFields} from './AgentProfileFields';
import {SshInstallationPanel} from './SshInstallationPanel';
import {AgentManagedRolloutModal} from './AgentManagedRolloutModal';
import {AgentPackagesModal,downloadAgentFile} from './AgentPackagesModal';
import {useEffect,useRef,useState} from 'react';
import {Alert,App,Button,Descriptions,Dropdown,Drawer,Form,Input,Modal,Select,Space,Switch,Table,Tabs,Typography,Upload} from 'antd';
import {DownloadOutlined,UploadOutlined} from '@ant-design/icons';
import {api,useSession} from './api';
import {ModuleSection,ModuleToolbar,StatusTag} from './ModuleSection';
import {paginationDefaults,pageWithinTotal} from './pagination';
import {formatTime} from './presentation';
import {installationCommand,offlineInstallationProfile,supportsPlatformAgent} from './agent-installation';
const labels={DRAFT:'待上传 / 发布',PUBLISHED:'已发布',REVOKED:'已撤回',WAITING:'等待安装',REGISTERED:'已注册',PREFLIGHT:'预检中',INSTALLING:'安装中',SERVICE_STARTING:'等待服务验收',SUCCEEDED:'接入已验证',RECOVERING:'恢复中',RECOVERED:'已恢复原部署',PARTIAL:'部分完成',UNKNOWN:'结果待核对',FAILED:'安装失败',CANCELLED:'授权已撤销'};
const width='min(760px, calc(100vw - 32px))';
export function AgentInstallationPanel({releasesOnly=false,onViewRollouts}:{releasesOnly?:boolean;onViewRollouts?:()=>void}){
 const {message}=App.useApp();const[tab,setTab]=useState(releasesOnly?'releases':new URLSearchParams(location.hash.split('?')[1]||'').get('tab')==='connection'?'connection':new URLSearchParams(location.hash.split('?')[1]||'').get('tab')==='batch'?'batch':'installations');
 const[items,setItems]=useState<any[]>([]),[total,setTotal]=useState(0),[page,setPage]=useState(1),[pageSize,setPageSize]=useState(15),[q,setQ]=useState('');
 const[loading,setLoading]=useState(false),[busy,setBusy]=useState(false),[error,setError]=useState(''),[role,setRole]=useState(''),[root,setRoot]=useState('');
 const[available,setAvailable]=useState<any[]>([]),[open,setOpen]=useState(false),[result,setResult]=useState<any>(),[view,setView]=useState<any>();const[form]=Form.useForm();const request=useRef(0);const platformServer=Form.useWatch('server',form);
 useEffect(()=>{if(platformServer){const selected=available.find(row=>row.id===form.getFieldValue('releaseId'));if(selected&&!supportsPlatformAgent(selected.version,platformServer))form.setFieldValue('releaseId',undefined)}},[platformServer,available]);
 const offlineProfile=result?offlineInstallationProfile(result):undefined;
 const[requiresBusiness,setRequiresBusiness]=useState(false);
 const[review,setReview]=useState<{id:string;operation:'publish'|'revoke'}>();
 const[packageRelease,setPackageRelease]=useState<any>();const[rolloutRelease,setRolloutRelease]=useState<any>();
 useEffect(()=>{if(releasesOnly)return;const update=()=>{const value=new URLSearchParams(location.hash.split('?')[1]||'').get('tab');if(['connection','batch','installations','releases'].includes(value||''))setTab(value!)};window.addEventListener('hashchange',update);return()=>window.removeEventListener('hashchange',update)},[releasesOnly]);
 const path=tab==='releases'?'/agent-releases':'/agent-installations';
 async function load(){if(['batch','connection'].includes(tab))return;const version=++request.current;setLoading(true);setError('');try{
  const [data,me]=await Promise.all([api(`${path}?page=${page}&pageSize=${pageSize}&q=${encodeURIComponent(q)}`),api('/auth/me')]);if(version!==request.current)return;
  const validPage=pageWithinTotal(page,data.total,pageSize);if(validPage!==page){setPage(validPage);return;}setItems(data.items);setView((current:any)=>current?data.items.find((row:any)=>row.id===current.id)||current:undefined);setPackageRelease((current:any)=>current?data.items.find((r:any)=>r.id===current.id)||current:undefined);setTotal(data.total);setRole(me.role);if(data.trustRoot!==undefined)setRoot(data.trustRoot||'');
 }catch(e){if(version===request.current)setError((e as Error).message);}finally{if(version===request.current)setLoading(false);}}
 useEffect(()=>{void load();return()=>{request.current++;};},[tab,page,pageSize,q]);
 const reload=useRef(load);reload.current=load;
 useEffect(()=>{if(tab!=='installations'||open||busy||!items.some(row=>['WAITING','PREFLIGHT','INSTALLING','REGISTERED','SERVICE_STARTING','PARTIAL','UNKNOWN'].includes(row.status)))return;const timer=setInterval(()=>void reload.current(),5000);return()=>clearInterval(timer)},[tab,open,busy,items]);
 async function action(work:()=>Promise<unknown>){setBusy(true);setError('');try{await work();await reload.current();}catch(e){setError((e as Error).message);}finally{setBusy(false);}}
 async function showCreate(){form.resetFields();setResult(undefined);setError('');if(tab==='installations'){
  setBusy(true);try{const[data,options]=await Promise.all([api('/agent-releases?pageSize=100'),api('/agent-installations/options')]);setRequiresBusiness(options.requiresBusiness);const choices=data.items.filter((r:any)=>r.status==='PUBLISHED'&&Date.parse(r.expiresAt)>Date.now()).sort((a:any,b:any)=>Number(a.channel!=='stable')-Number(b.channel!=='stable'));setAvailable(choices);setRoot(data.trustRoot||'');form.setFieldsValue({releaseId:choices.find((r:any)=>r.channel==='stable')?.id,executorEnabled:false,tags:[]});setOpen(true);}catch(e){setError((e as Error).message);}finally{setBusy(false);}
 }else{setOpen(true);}}
 async function submit(){try{const values=await form.validateFields();setBusy(true);setError('');if(tab==='releases'){
   const data=JSON.parse(values.envelope);await api('/agent-releases',data);message.success('签名清单已登记，请上传对应制品并发布');setOpen(false);
  }else{const task=await api('/agent-installations',values);const release=available.find(x=>x.id===values.releaseId);setResult({...task,release,trustRoot:root});}
  await load();
 }catch(e){if(e instanceof Error)setError(e.message);}finally{setBusy(false);}}
 async function download(release:any,pkg?:any){await action(()=>downloadAgentFile(release,pkg));}
 async function upload(id:string,file:File){await action(async()=>{const response=await fetch(apiURL('/agent-releases/'+id+'/artifact'),{method:'POST',headers:{'Content-Type':'application/octet-stream',Authorization:'Bearer '+useSession.getState().token},body:file});if(!response.ok){const data=await response.json();throw new Error(data.message||'制品上传失败');}message.success('制品摘要校验通过');});return false;}
 const canCreate=tab==='releases'?role==='ADMIN':['ADMIN','ANALYST','OPERATOR'].includes(role);
 const reviewRow=items.find(row=>row.id===review?.id),reviewAllowed=canCreate&&reviewRow&&tab!=='batch'&&(tab==='releases'?(review?.operation==='publish'?reviewRow.status==='DRAFT':reviewRow.status==='PUBLISHED'):review?.operation==='revoke'&&!reviewRow.revokedAt);
 useEffect(()=>{setReview(undefined);},[tab,page,pageSize,q]);
 useEffect(()=>{if(review&&!reviewAllowed)setReview(undefined);},[review,reviewAllowed]);
 return <div className="module-stack">
  {error&&<Alert type="error" showIcon message={error} action={<Button onClick={()=>void load()}>重试</Button>}/>}
  {!releasesOnly&&<Tabs activeKey={tab} onChange={value=>{setTab(value);setPage(1);setItems([]);setTotal(0);setQ('');const params=new URLSearchParams(location.hash.split('?')[1]||'');params.set('tab',value);history.replaceState(null,'',location.pathname+location.search+'#enroll?'+params.toString());}} items={[{key:'installations',label:'安装与接入',disabled:open},{key:'batch',label:'SSH 批量安装',disabled:open},{key:'connection',label:'平台接入设置',disabled:open},{key:'releases',label:'可用发行版本',disabled:open}]}/>}
  {tab==='connection'?<AgentPlatformConnectionPanel/>:tab==='batch'?<SshInstallationPanel onViewInstallation={id=>{setTab('installations');setQ(id);setPage(1);}}/>:<ModuleSection title={tab==='releases'?'Agent 发行版本':'Agent 安装任务'} description={tab==='releases'?'登记签名清单、上传并验证制品后发布。已发布内容不可覆盖。':'选择固定版本与业务归属，生成短期安装票据；服务心跳验收通过后完成接入。'} extra={<ModuleToolbar><Button loading={loading} disabled={busy} onClick={()=>void load()}>刷新</Button>{canCreate&&<Button type="primary" disabled={busy||open} onClick={()=>void showCreate()}>{tab==='releases'?'登记发行版本':'创建安装任务'}</Button>}</ModuleToolbar>}>
   <ModuleToolbar><Input.Search key={tab+':'+q} defaultValue={q} allowClear placeholder={tab==='releases'?'搜索版本':'搜索任务编号或状态说明'} aria-label="搜索安装和发行记录" onSearch={value=>{setQ(value);setPage(1);}} style={{width:320,maxWidth:'100%'}}/>{tab==='releases'&&!root&&<Typography.Text type="warning">尚未配置发行签名信任根，无法登记或发布制品。</Typography.Text>}</ModuleToolbar>
   <Table<any> rowKey="id" dataSource={items} loading={loading} scroll={{x:tab==='releases'?1000:900}} pagination={{...paginationDefaults,current:page,pageSize,total,onChange:(p,s)=>{setPage(s!==pageSize?1:p);setPageSize(s);}}} columns={tab==='releases'?[
    {title:'版本',dataIndex:'version',render:(v,r)=><Button type="link" className="record-title-link" onClick={()=>setView(r)}>{v} · {r.architecture}</Button>},
    {title:'渠道',dataIndex:'channel',render:v=>v==='stable'?'稳定':'灰度'},
    {title:'状态',dataIndex:'status',render:v=><StatusTag value={v} labels={labels}/>},
    {title:'发布序列',dataIndex:'sequence'},{title:'大小',dataIndex:'size',render:v=>`${(v/1048576).toFixed(1)} MiB`},
    {title:'有效期',dataIndex:'expiresAt',render:formatTime},
    {title:'操作',render:(_,r)=><Space wrap size={8}>{r.status==='PUBLISHED'&&<><Dropdown trigger={['click']} menu={{items:[{key:'binary',label:'原始程序'},...(r.packages||[]).filter((p:any)=>p.status==='PUBLISHED').map((p:any)=>({key:p.id,label:p.format==='tar.gz'?'通用离线包（tar.gz）':`${p.format.toUpperCase()} 安装包`}))],onClick:({key})=>void download(r,(r.packages||[]).find((p:any)=>p.id===key))}}><Button icon={<DownloadOutlined/>} disabled={busy}>下载</Button></Dropdown><Button disabled={busy} onClick={()=>setPackageRelease(r)}>安装包</Button></>}{role==='ADMIN'&&<>{r.status==='PUBLISHED'&&<Button disabled={busy} onClick={()=>setRolloutRelease(r)}>创建升级计划</Button>}{r.status==='DRAFT'&&<><Upload showUploadList={false} beforeUpload={file=>upload(r.id,file)} disabled={busy}><Button icon={<UploadOutlined/>} disabled={busy}>上传制品</Button></Upload><Button disabled={busy} onClick={()=>{setError('');setReview({id:r.id,operation:'publish'});}}>发布</Button></>}{r.status==='PUBLISHED'&&<Button danger disabled={busy} onClick={()=>{setError('');setReview({id:r.id,operation:'revoke'});}}>撤回</Button>}</>}</Space>},
   ]:[
    {title:'安装任务',dataIndex:'id',render:(id,r)=><Button type="link" className="record-title-link" onClick={()=>setView(r)}>{id.slice(0,8)}</Button>},
    {title:'目标版本',render:(_,r)=>`${r.release.version} · ${r.release.architecture}`},
    {title:'业务归属',render:(_,r)=>r.profile.business||'未分组'},
    {title:'状态',dataIndex:'status',render:(v,r)=><Space direction="vertical" size={4}><StatusTag value={v} labels={labels}/>{r.status==='WAITING'&&Date.parse(r.expiresAt)<Date.now()&&<Typography.Text type="warning">首次领取已过期</Typography.Text>}</Space>},
    {title:'进度说明',dataIndex:'detail',render:v=>v||'等待目标主机执行安装'},
    {title:'创建时间',dataIndex:'createdAt',render:formatTime},
    {title:'操作',render:(_,r)=>!r.revokedAt&&canCreate?<Button danger disabled={busy} onClick={()=>{setError('');setReview({id:r.id,operation:'revoke'});}}>撤销授权</Button>:'—'},
   ]}/>
   <Modal open={!!(reviewAllowed&&review)} className="module-modal" width={width} centered title="确认操作" footer={null} closable={!busy} maskClosable={!busy} onCancel={()=>{if(!busy)setReview(undefined)}}>{reviewAllowed&&review&&<section className="module-stack" role="region" aria-label={tab==='releases'?(review.operation==='publish'?'发布发行版本确认':'撤回发行版本确认'):'撤销安装授权确认'}>
    <Alert type={review.operation==='publish'?'info':'warning'} showIcon message={tab==='releases'?`${review.operation==='publish'?'发布':'撤回'} ${reviewRow.version} · Linux ${reviewRow.architecture}`:`撤销安装授权 · ${reviewRow.id.slice(0,8)}`} description={tab==='releases'?(review.operation==='publish'?'平台将重新核验签名、有效期和完整文件摘要；发布后内容不可覆盖。':'停止该版本及其安装包的新下载和安装；保留历史记录，不会卸载运行中的组件。'):'停止后续领取与安装会话。请先确认主机没有仍在执行的安装；此操作保留资产、身份和历史，不会卸载 Agent。'}/>
    {tab==='releases'?<Space direction="vertical" size={8}><Typography.Text>有效期：{formatTime(reviewRow.expiresAt)}</Typography.Text><Typography.Text style={{overflowWrap:'anywhere'}}>SHA-256：{reviewRow.sha256}</Typography.Text></Space>:<Typography.Text>{reviewRow.release.version} · Linux {reviewRow.release.architecture} · {reviewRow.profile.business||'未分组'}</Typography.Text>}
    <ModuleToolbar><Button type="primary" danger={review.operation==='revoke'} loading={busy} onClick={()=>void action(async()=>{await api(`${path}/${reviewRow.id}/${review.operation}`,{});setReview(undefined);message.success(tab==='releases'?(review.operation==='publish'?'发行版本已发布':'发行版本已撤回'):'安装授权已撤销');})}>{tab==='releases'?(review.operation==='publish'?'确认发布版本':'确认撤回版本'):'确认撤销授权'}</Button><Button disabled={busy} onClick={()=>setReview(undefined)}>返回列表</Button></ModuleToolbar>
   </section>}</Modal>
  </ModuleSection>}
  <Drawer open={open} className="record-drawer" placement="right" width="min(960px, calc(100vw - 24px))" title={result?'安装命令与一次性票据':tab==='releases'?'登记签名发行清单':'创建 Agent 安装任务'} closable={!busy} maskClosable={!busy} onClose={()=>{if(!busy){setResult(undefined);form.resetFields();setOpen(false);setError('')}}}><div className="module-stack">

   {result?<Space direction="vertical" size={20} style={{width:'100%'}}><Alert type="warning" showIcon message="在目标 Linux 主机执行命令后，按提示输入下方票据。页面关闭后无法再次查看票据。"/><Descriptions column={1} items={[{key:'expiry',label:'首次领取有效期',children:formatTime(result.expiresAt)},{key:'version',label:'固定版本',children:`${result.release.version} · ${result.release.architecture}`},{key:'trust',label:'发行验证公钥',children:<Typography.Text copyable style={{overflowWrap:'anywhere'}}>{result.trustRoot}</Typography.Text>} ]}/><Input.Password readOnly value={result.ticket} aria-label="一次性安装票据"/><Typography.Paragraph copyable={{text:installationCommand(result)}}><pre style={{whiteSpace:'pre-wrap',overflowWrap:'anywhere',maxHeight:280,overflow:'auto'}}>{installationCommand(result)}</pre></Typography.Paragraph>{offlineProfile&&<Space direction="vertical" size={8}><Button icon={<DownloadOutlined/>} onClick={()=>{const url=URL.createObjectURL(new Blob([JSON.stringify(offlineProfile,null,2)],{type:'application/json'})),link=document.createElement('a');link.href=url;link.download='selfguard-agent-offline-profile.json';link.click();setTimeout(()=>URL.revokeObjectURL(url),1000);}}>下载离线准备配置</Button><Typography.Text type="secondary">不包含票据、身份或业务归属。与同版本通用包及上方可信公钥一起使用；只准备本地文件，联网后仍需安装授权完成接入。</Typography.Text></Space>}<Typography.Text type="secondary">目标主机需要 bash、curl、sha256sum，以及 root 或 sudo 权限。systemd 使用原安装方式；Alpine / OpenRC 请选择明确支持 OpenRC 的已发布版本（0.4.1 起），且需启用 cgroup v2 的 CPU、内存与进程数控制器。指定的 CA 随命令用于下载和后续连接；未指定时使用系统信任。</Typography.Text></Space>:<>{error&&<Alert type="error" showIcon message={error}/>}<Form form={form} disabled={busy} layout="vertical" className="module-form-grid">
    {tab==='releases'?<><Form.Item className="module-field-wide" label="导入发行清单" extra="选择构建工具生成的签名清单 JSON；只导入公开发行材料，不上传签名私钥。"><Upload accept=".json" showUploadList={false} beforeUpload={async file=>{try{const data=JSON.parse(await file.text());form.setFieldValue('envelope',JSON.stringify(data,null,2));}catch{setError('清单不是有效 JSON');}return false;}}><Button icon={<UploadOutlined/>}>选择签名清单</Button></Upload></Form.Item><Form.Item className="module-field-wide" name="envelope" label="签名清单与构建来源" rules={[{required:true}]} extra="由发行构建工具生成，包含 CycloneDX SBOM、来源摘要与许可；不得填写私钥。"><Input.TextArea rows={10}/></Form.Item></>:<>
     <Form.Item name="releaseId" label="发行版本" rules={[{required:true,message:'请选择已发布的版本'}]} extra="选择与目标主机架构对应的已发布固定版本；该选择将固定本次安装的程序摘要。子路径接入需要0.4.11或更高版本；HTTP接入需要0.4.10或更高版本。"><Select options={available.map(r=>({value:r.id,disabled:!supportsPlatformAgent(r.version,platformServer),label:`${r.version} · Linux ${r.architecture} · ${r.channel==='stable'?'稳定':'灰度'}`}))} placeholder={available.length?'选择固定发行版本':'请先登记、上传并发布发行版本'}/></Form.Item>
     <AgentPlatformFields onLeave={()=>{setOpen(false);setResult(undefined);form.resetFields()}}/>
     <Form.Item name="business" label="业务归属" extra="选择当前账户有权使用的业务分组；接入后用于资产归属和扫描范围。新业务请先在资产中心的“业务分组”创建，生成安装授权后才会应用归属。" rules={[{required:requiresBusiness,message:'请选择已授权的业务分组'}]}><BusinessSelect onBusyChange={setBusy} canCreate={false}/></Form.Item>
     <Form.Item name="tags" label="资产标签" extra="用于检索、规则适用与扫描范围；标签本身不会授予额外权限。"><Select mode="tags" tokenSeparators={[',']} placeholder="输入标签并回车"/></Form.Item>

     <AgentProfileFields/>
     <Form.Item name="executorEnabled" label="启用受控修复执行器" valuePropName="checked" extra="开启后单独部署执行器，仅执行已授权目录和服务内的受控任务；仅采集时保持关闭。"><Switch/></Form.Item>
     <Form.Item noStyle shouldUpdate={(a,b)=>a.executorEnabled!==b.executorEnabled}>{({getFieldValue})=>getFieldValue('executorEnabled')?<><Form.Item name="allowedRoot" label="允许变更目录" rules={[{required:true}]} extra="明确允许修复的目录边界，填写目标主机的绝对路径；不要把整个文件系统作为普通修复范围。"><Input placeholder="/srv/selfguard-managed"/></Form.Item><Form.Item name="allowedServices" label="允许管理的服务" extra="填写实际存在且允许启停的服务名称；未列出的服务不会获得管理授权。"><Select mode="tags"/></Form.Item></>:null}</Form.Item>
     <Alert className="module-field-wide" type="info" showIcon message="安装票据仅显示一次，默认15分钟内首次领取。同一持久身份可恢复安装；不在命令行中携带秘密。"/>
    </>}
   </Form></>}
   {!result&&<ModuleToolbar><Button type="primary" loading={busy} disabled={tab==='installations'&&!platformServer} onClick={()=>void submit()}>{tab==='releases'?'登记清单':'生成安装授权'}</Button></ModuleToolbar>}
  {result&&<Button type="primary" onClick={()=>{setResult(undefined);form.resetFields();setOpen(false)}}>已保存安装材料</Button>}</div></Drawer>
  <Modal className="module-modal" width={width} title={tab==='releases'?'发行信息':'安装详情'} open={!!view} footer={<Button onClick={()=>setView(undefined)}>关闭</Button>} onCancel={()=>setView(undefined)}>{view&&<Descriptions column={1} bordered size="small" items={tab==='releases'?[
   {key:'digest',label:'SHA-256',children:<Typography.Text copyable>{view.sha256}</Typography.Text>},{key:'source',label:'构建来源摘要',children:view.sourceDigest},{key:'license',label:'许可',children:view.license},{key:'trust',label:'发行公钥',children:root||'未配置'},{key:'manifest',label:'签名清单',children:<Typography.Text copyable>{view.manifestBytes}</Typography.Text>},
  ]:[{key:'status',label:'状态',children:<StatusTag value={view.status} labels={labels}/>},{key:'asset',label:'资产',children:view.assetId?<Button type="link" className="record-title-link" onClick={()=>{location.hash=`assets?assetId=${encodeURIComponent(view.assetId)}`;setView(undefined);}}>查看资产</Button>:'尚未注册'},{key:'server',label:'平台地址',children:view.profile.server},{key:'business',label:'业务',children:view.profile.business||'未分组'},{key:'state',label:'状态目录',children:view.profile.stateDir||'/var/lib/selfguard-agent'},{key:'proxy',label:'连接方式',children:({DIRECT:'直连',EXPLICIT:'指定代理',ENVIRONMENT:'继承服务环境代理'} as Record<string,string>)[view.profile.proxyMode]||'版本默认'},{key:'read',label:'采集目录',children:view.profile.collectionRoot||'未开启文件采集'},{key:'executor',label:'执行器',children:view.profile.executorEnabled?'已明确授权':'仅采集器'},{key:'detail',label:'进度说明',children:<Space direction="vertical" size={8}><Typography.Text>{view.detail||'等待目标主机执行'}</Typography.Text>{view.status==='PARTIAL'&&<Typography.Text type="warning">有效的未完成安装会暂停该主机领取修复和升级。先核对服务与安装进程，完成恢复或接入验证；若新任务已接入成功，确认旧安装已结束后撤销旧授权。撤销不会卸载 Agent。</Typography.Text>}</Space>}]}/>}</Modal>
  {rolloutRelease&&<AgentManagedRolloutModal release={rolloutRelease} onViewRollouts={onViewRollouts} onClose={()=>setRolloutRelease(undefined)}/>}
  {packageRelease&&<AgentPackagesModal release={packageRelease} admin={role==='ADMIN'} onClose={()=>setPackageRelease(undefined)} onChange={load}/>}
 </div>;
}
