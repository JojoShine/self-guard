import {platformURL} from './urls';
import {AgentPlatformFields} from './AgentPlatformConnection';
import {managementOptions} from './management-options';
import {useEffect,useState} from 'react';
import {Alert,Button,Descriptions,Form,InputNumber,Modal,Space,Select} from 'antd';
import {api} from './api';
export function AgentManagedRolloutModal({release,onClose,onViewRollouts}:{release:any;onClose:()=>void;onViewRollouts?:()=>void}){
 const [form]=Form.useForm(),[busy,setBusy]=useState(false),[error,setError]=useState(''),[created,setCreated]=useState(false),[assets,setAssets]=useState<any[]>([]),[loading,setLoading]=useState(true);
 const platformServer=Form.useWatch('server',form);
 useEffect(()=>{let active=true;managementOptions().then(value=>{if(active)setAssets(value.assets)}).catch(e=>{if(active)setError(e.message)}).finally(()=>{if(active)setLoading(false)});return()=>{active=false}},[]);
 async function submit(){try{const values=await form.validateFields();setBusy(true);setError('');
  const origin=new URL(values.server);if(!['http:','https:'].includes(origin.protocol)||origin.username||origin.password||origin.search||origin.hash||!platformURL(values.server))throw Error('平台接入配置无效，请先核对统一平台入口');
  const targetIds=values.targetIds;if(!targetIds?.length||new Set(targetIds).size!==targetIds.length)throw Error('请选择不重复的升级主机');
  await api('/rollouts',{managedReleaseId:release.id,manifestBytes:release.manifestBytes,signature:release.signature,artifactUrl:platformURL(values.server)+'/api/agent-releases/'+release.id+'/download',targetIds,batchSize:values.batchSize});setCreated(true);
 }catch(e){if(e instanceof Error)setError(e.message);}finally{setBusy(false);}}
 return <Modal className="module-modal" width="min(760px, calc(100vw - 32px))" title="从发行版本创建升级计划" open onCancel={()=>!busy&&onClose()} maskClosable={!busy} closable={!busy} footer={created?<Space size={12}><Button onClick={onClose}>关闭</Button><Button type="primary" aria-label="查看并审批升级计划" onClick={()=>{onClose();if(onViewRollouts)onViewRollouts();else location.hash='rollouts';}}>查看并审批升级计划</Button></Space>:<Space size={12}><Button disabled={busy} onClick={onClose}>取消</Button><Button type="primary" loading={busy} disabled={loading||!platformServer} onClick={()=>void submit()}>创建待审批计划</Button></Space>}>
  <div className="module-stack">
   {error&&<Alert type="error" showIcon message={error}/>}
   {created?<Alert type="success" showIcon message="计划已创建，审批后按金丝雀和固定批次执行" description="下载绑定此计划、目标资产和固定制品；每批等待重启后心跳验收，失败会暂停。"/>:<>
    <Descriptions column={1} size="small" items={[{key:'release',label:'固定版本',children:`${release.version} · Linux ${release.architecture}`},{key:'hash',label:'SHA-256',children:release.sha256}]}/>
    <Alert type="info" showIcon message="目标需通过新版安装器明确启用受控执行器和受管下载能力" description="目标必须匹配操作系统与架构。第一台为金丝雀；创建计划后仍需在灰度升级页面审批原始目标。平台自动使用已验证的统一接入入口，下载继续校验签名、来源及当前主机绑定。"/>
    <Form form={form} layout="vertical" initialValues={{batchSize:1}}>
     <AgentPlatformFields onLeave={onClose}/>
     <Form.Item name="targetIds" label="升级主机（第一台为金丝雀）" rules={[{required:true,type:'array',min:1,message:'请选择升级主机'}]} extra="按选择顺序推进，不会自动扩展；创建时校验每台主机的架构、执行器和受管下载能力。"><Select mode="multiple" loading={loading} showSearch optionFilterProp="label" options={assets}/></Form.Item>
     <Form.Item name="batchSize" label="金丝雀通过后每批主机数" rules={[{required:true}]} extra="第一台验证通过后，再按此数量推进后续目标；调小可缩小同时变更的范围。"><InputNumber min={1} max={100} precision={0}/></Form.Item>
    </Form>
   </>}
  </div>
 </Modal>;
}
