import {GovernancePanel} from './GovernancePanel';
import {FormDrawer} from './FormDrawer';
import {RecordSelect} from './RecordSelect';
import {managementOptions} from './management-options';
import {AgentInstallationPanel} from './AgentInstallationPanel';
import {paginationDefaults} from './pagination';
import { useEffect, useRef, useState } from 'react';
import { Alert, App, Button, Tabs, Collapse, Descriptions, Form, Input, InputNumber, Modal, Select, Space, Spin, Switch, Table } from 'antd';
import { api } from './api';
import { ModuleSection, ModuleToolbar, StatusTag } from './ModuleSection';
import { formatTime } from './presentation';

const modalWidth = 'min(720px, calc(100vw - 32px))';
const targetLabels = { PENDING: '等待升级', CLAIMED: '已领取', STAGED: '已暂存', RUNNING: '运行已验证', UNKNOWN: '结果待确认', FAILED: '升级失败' };
const deliveryLabels = { PENDING: '等待投递', SENDING: '投递中', DELIVERED: '已送达', FAILED: '投递失败', CANCELLED: '已取消' };
function TechnicalDetails({ value }: { value: unknown }) {
  return <Collapse className="technical-details" size="small" ghost items={[{ key: 'raw', label: '查看原始技术字段', children: <pre style={{ whiteSpace: 'pre-wrap', overflowWrap: 'anywhere', margin: 0 }}>{JSON.stringify(value, null, 2)}</pre> }]} />;
}

export function ScopeEditor({record,onChanged}:{record:any;onChanged:()=>void}){
 const [open,setOpen]=useState(false),[error,setError]=useState(''),[busy,setBusy]=useState(false),[choices,setChoices]=useState<any>({assets:[],businesses:[]});const [f]=Form.useForm();
 async function edit(){setError('');setBusy(true);try{const options=await managementOptions();setChoices(options);f.setFieldsValue({...record.dataScope,canReadSqlEvidence:record.dataScope?.canReadSqlEvidence===true,canReadAccessEvidence:record.dataScope?.canReadAccessEvidence===true,canExportAccessEvidence:record.dataScope?.canExportAccessEvidence===true,businesses:record.dataScope?.businesses||[],assetIds:record.dataScope?.assetIds||[],databaseInstanceIds:record.dataScope?.databaseInstanceIds||[]});setOpen(true)}catch(e){setError((e as Error).message)}finally{setBusy(false)}}
 async function save(){setError('');try{const value=await f.validateFields();setBusy(true);await api('/users/'+record.id,{dataScope:{restricted:!!value.restricted,canReadEvidence:value.canReadEvidence!==false,canReadSqlEvidence:value.canReadSqlEvidence===true,canReadAccessEvidence:value.canReadAccessEvidence===true,canExportAccessEvidence:value.canExportAccessEvidence===true,businesses:value.businesses||[],assetIds:value.assetIds||[],databaseInstanceIds:value.databaseInstanceIds||[]}},'PATCH');setOpen(false);onChanged()}catch(e){if(e instanceof Error)setError(e.message)}finally{setBusy(false)}}
 const assets=[...choices.assets,...(record.dataScope?.assetIds||[]).filter((id:string)=>!choices.assets.some((a:any)=>a.value===id)).map((id:string)=>({value:id,label:'历史授权资产 · '+id,disabled:true}))],businesses=[...choices.businesses,...(record.dataScope?.businesses||[]).filter((name:string)=>!choices.businesses.some((b:any)=>b.value===name)).map((name:string)=>({value:name,label:name+' · 历史授权',disabled:true}))];
 return <><Button loading={busy&&!open} disabled={busy} onClick={()=>void edit()}>设置数据与证据权限</Button>{error&&<Alert type="error" showIcon message={error}/>}{open&&<section className="module-subsection" aria-label="数据访问范围"><h3>数据访问范围</h3><Alert type="info" showIcon message="范围限制开启但没有选择任何业务或资产时，没有资产访问权限。管理员仍拥有完整权限。"/>
 <Form form={f} layout="vertical" className="module-form-grid" disabled={busy}>
 <Form.Item name="restricted" label="限制资产范围" valuePropName="checked" extra="开启后仅能访问明确选择的业务或资产；两类授权取并集。"><Switch/></Form.Item>
 <Form.Item name="canReadEvidence" label="允许读取证据与附件" valuePropName="checked" initialValue={true} extra="关闭后隐藏详细依据、处置内容和附件，不改变可见资产范围。"><Switch/></Form.Item>
 <Form.Item name="canReadSqlEvidence" label="允许查看数据库SQL原文" valuePropName="checked" initialValue={false} extra="独立授权7天内SQL原文，仍受数据库实例范围及证据总开关约束。"><Switch/></Form.Item>
 <Form.Item name="canReadAccessEvidence" label="允许读取原始访问正文" valuePropName="checked" initialValue={false} extra="独立授权请求与响应原文字节，仍受主机、实例范围及证据总开关约束。"><Switch/></Form.Item>
 <Form.Item name="canExportAccessEvidence" label="允许导出原始访问正文" valuePropName="checked" initialValue={false} extra="独立授权证据分段下载，每次导出均留下审计；普通元数据查看不会获得此权限。"><Switch/></Form.Item>
 <Form.Item name="businesses" label="允许的业务" extra="选择已存在的业务分组，不能通过输入新名称扩大授权。"><Select mode="multiple" showSearch optionFilterProp="label" options={businesses}/></Form.Item>
 <Form.Item name="assetIds" label="额外允许的资产" extra="选择具体主机，补充业务分组之外的授权；历史授权可以移除。"><Select mode="multiple" showSearch optionFilterProp="label" options={assets}/></Form.Item><Form.Item name="databaseInstanceIds" label="授权数据库实例"><RecordSelect resource="database-instances" mode="multiple"/></Form.Item>
 </Form><ModuleToolbar><Button type="primary" loading={busy} onClick={()=>void save()}>保存权限</Button><Button disabled={busy} onClick={()=>setOpen(false)}>取消编辑</Button></ModuleToolbar></section>}</>;
}

function LegacyCompletionPanel({ section,readOnly=false }: { section: string;readOnly?:boolean }) {
  const { message } = App.useApp();
  const [items, setItems] = useState<any[]>([]), [info, setInfo] = useState<any>(), [error, setError] = useState(''), [open, setOpen] = useState(false);
  const [loading, setLoading] = useState(true), [busy, setBusy] = useState(false);
  const [f] = Form.useForm();
  const [assetChoices,setAssetChoices]=useState<any[]>([]);
  const request = useRef(0);
  const title = section === 'rollouts' ? '灰度升级计划' : section === 'deliveries' ? '通知投递记录' : section === 'webhook' ? '外部通知渠道' : '定期备份';
  const refresh = async () => {
    const current = ++request.current;
    setLoading(true); setError('');
    try {
      const result = await api(section === 'rollouts' ? '/rollouts' : '/maintenance/' + section);
      if (current !== request.current) return;
      if (section === 'rollouts') setItems(result);
      else if (section === 'deliveries') setItems(result.items);
      else setInfo(result);
    } catch (e) { if (current === request.current) setError((e as Error).message); }
    finally { if (current === request.current) setLoading(false); }
  };
  useEffect(() => {
    setItems([]); setInfo(undefined); setOpen(false); f.resetFields(); void refresh();
    return () => { request.current++; };
  }, [section]);
  const action = async (work: () => Promise<unknown>) => {
    setBusy(true); setError('');
    try { await work(); await refresh(); }
    catch (e) { setError((e as Error).message); throw e; }
    finally { setBusy(false); }
  };
  const submit = async () => {
    setError('');
    try {
      const v = await f.validateFields();
      let payload = v;
      if (section === 'rollouts') {
        let envelope;
        try { envelope = JSON.parse(v.envelope); } catch { throw new Error('签名封装的 JSON 格式无效，请检查后重试'); }
        if (typeof envelope.manifestBytes !== 'string' || typeof envelope.signature !== 'string') throw new Error('签名封装需要 manifestBytes 和 signature');
        let signedVersion; try { signedVersion = JSON.parse(atob(envelope.manifestBytes)).version; } catch { throw new Error('签名清单无法解析'); }
        if (signedVersion !== v.version) throw new Error('目标版本与签名清单不一致');
        payload = { artifactUrl: v.artifactUrl, manifestBytes: envelope.manifestBytes, signature: envelope.signature, batchSize: v.batchSize, targetIds: v.targetIds };
      }
      await action(() => api(section === 'rollouts' ? '/rollouts' : '/maintenance/' + section, payload, section === 'rollouts' ? 'POST' : 'PATCH'));
      setOpen(false); message.success(section === 'rollouts' ? '签名升级计划已创建' : '配置已保存');
    } catch (e) { setError((e as Error).message || '请检查表单内容'); }
  };
  return <div className="module-stack">
    {error && <Alert type="error" showIcon message={error} action={<Button disabled={busy} onClick={() => void refresh()}>重新加载</Button>} />}
    <ModuleSection title={title} description={section === 'deliveries' ? '跟踪自己的外部通知投递与重试状态。' : section === 'webhook' ? '通过 HTTPS 接收自己的通知，接收端按稳定投递编号去重。' : section === 'backup' ? '配置自动备份频率与保留数量，定期演练恢复。' : '先验证金丝雀主机，再按批次推进签名升级。'} extra={<ModuleToolbar>
      <Button loading={loading} disabled={busy} onClick={() => void refresh()}>刷新{section === 'deliveries' ? '记录' : '状态'}</Button>
      {!readOnly&&section !== 'deliveries' && <Button type="primary" disabled={loading || busy || (!!error && !info)} onClick={async() => { setError('');setBusy(true);try{if(section==='rollouts')setAssetChoices((await managementOptions()).assets);f.resetFields(); f.setFieldsValue(section === 'backup' ? info?.policy : { enabled: info?.enabled, batchSize: 1,targetIds:[] }); setOpen(true)}catch(e){setError((e as Error).message)}finally{setBusy(false)} }}>{section === 'rollouts' ? '创建签名升级计划' : '编辑配置'}</Button>}
    </ModuleToolbar>}>
      {section === 'rollouts' && <>
        <Alert type="warning" showIcon message="升级需要部署者预置可信签名公钥与允许来源；先发布一台金丝雀，新版本心跳验证通过后再推进。" style={{ marginBottom: 20 }} />
        <Table<any> pagination={paginationDefaults} rowKey="id" loading={loading} dataSource={items} scroll={{ x: 900 }} locale={{ emptyText: '暂无升级计划' }} columns={[
          { title: '版本', dataIndex: 'version', render: v => <span className="module-record-title">{v}</span> },
          { title: '状态', dataIndex: 'status', render: v => <StatusTag value={v} /> },
          { title: '批次大小', dataIndex: 'batchSize' },
          { title: '目标进度', render: (_, r) => <Space wrap>{r.targets?.length ? r.targets.map((t: any) => <StatusTag key={t.id || t.assetId} value={t.status} labels={targetLabels} />) : '暂无目标'}</Space> },
          { title: '操作', render: (_, r) => <Space wrap>
            {!readOnly&&['DRAFT', 'PAUSED'].includes(r.status) && <Button disabled={busy} onClick={() => Modal.confirm({className:'module-modal', title: '批准签名升级', content: '将按计划变更选中主机的 Agent。请确认签名、目标和恢复方案。', okText: '批准升级', cancelText: '取消', onOk: () => action(() => api('/rollouts/' + r.id + '/approve', { targetIds: r.targetIds })) })}>批准 / 继续</Button>}
            {!readOnly&&r.status === 'RUNNING' && <Button loading={busy} onClick={() => void action(() => api('/rollouts/' + r.id + '/pause', {})).catch(() => {})}>暂停</Button>}
            <Button danger disabled={busy||readOnly} onClick={() => Modal.confirm({className:'module-modal', title: '取消尚未执行的发布目标', okText: '确认取消', cancelText: '返回', okButtonProps: { danger: true }, onOk: () => action(() => api('/rollouts/' + r.id + '/cancel', {})) })}>取消</Button>
          </Space> },
        ]} expandable={{ expandedRowRender: r => <TechnicalDetails value={r} /> }} />
      </>}
      {section === 'deliveries' && <Table<any> pagination={paginationDefaults} rowKey="id" loading={loading} dataSource={items} scroll={{ x: 820 }} locale={{ emptyText: '暂无通知投递记录' }} columns={[
        { title: '状态', dataIndex: 'status', render: v => <StatusTag value={v} labels={deliveryLabels} /> },
        { title: '尝试次数', dataIndex: 'attempts' },
        { title: '最近错误', dataIndex: 'lastError', render: v => v || '—' },
        { title: '重试时间', dataIndex: 'availableAt', render: formatTime },
        { title: '操作', render: (_, r) => r.status === 'FAILED'&&!readOnly ? <Button loading={busy} onClick={() => void action(() => api('/maintenance/deliveries/retry', { id: r.id })).catch(() => {})}>重试自己的投递</Button> : '—' },
      ]} />}
      {!['rollouts', 'deliveries'].includes(section) && <Spin spinning={loading}>{info ? <>
        <Descriptions bordered size="small" column={{ xs: 1, sm: 1, md: 2 }} items={section === 'webhook' ? [
          { key: 'enabled', label: '通知渠道', children: info.enabled ? '已启用' : '未启用' },
          { key: 'configured', label: '接收地址', children: info.configured ? '已配置' : '未配置' },
          { key: 'secret', label: '签名密钥', children: info.secretConfigured ? '已配置' : '未配置' },
        ] : [
          { key: 'enabled', label: '定期备份', children: info.policy?.enabled ? '已启用' : '未启用' },
          { key: 'interval', label: '备份间隔', children: `${info.policy?.intervalHours ?? '—'} 小时` },
          { key: 'keep', label: '保留备份', children: `${info.policy?.keepCount ?? '—'} 份` },
          { key: 'last', label: '最近备份结果', children: info.last ? <StatusTag value={info.last.status} labels={{ SUCCEEDED: '备份成功', FAILED: '备份失败' }} /> : '尚未执行' },
          { key: 'time', label: '最近完成时间', children: formatTime(info.last?.completedAt) },
          { key: 'file', label: '最近备份文件', children: info.last?.file || '—' },
        ]} />
        <TechnicalDetails value={info} />
      </> : <div className="module-note">{loading ? '正在加载配置…' : '配置未加载，请重新加载。'}</div>}</Spin>}
    </ModuleSection>
    <FormDrawer className="module-form-drawer" width={modalWidth} title={section === 'rollouts' ? '签名升级计划' : section === 'webhook' ? 'HTTPS 通知渠道' : '定期备份策略'} open={open} closable={!busy} maskClosable={!busy} cancelButtonProps={{disabled:busy}} onCancel={() => !busy && setOpen(false)} onOk={() => void submit()} confirmLoading={busy} okText={section === 'rollouts' ? '创建计划' : '保存配置'} cancelText="取消">
      <div className="module-stack">
        {error && <Alert type="error" showIcon message={error} />}
        <Form form={f} layout="vertical" className="module-form-grid" disabled={busy}>
          {section === 'rollouts' ? <>
            <Form.Item name="version" label="目标版本" rules={[{ required: true }]} extra="填写签名清单中的程序版本，必须与产物及签名一致；升级后需由真实心跳确认版本。"><Input /></Form.Item>
            <Form.Item name="artifactUrl" label="可信来源的 HTTPS 产物地址" rules={[{ required: true }]} extra="填写已由部署管理员允许的固定程序地址；平台与主机都要核验签名和摘要。"><Input /></Form.Item>
            <Form.Item className="module-field-wide" name="envelope" label="签名封装（manifestBytes 与 signature）" rules={[{ required: true }]} extra="粘贴构建工具生成的公开签名封装；原始清单字节不可改写，不上传签名私钥。"><Input.TextArea rows={5} /></Form.Item>
            <Form.Item className="module-field-wide" name="targetIds" label="升级主机（选择顺序中第一台为金丝雀）" rules={[{ required: true }]} extra="按执行顺序选择主机；创建时还会校验架构及受控执行能力，第一台验证通过后才推进后续批次。"><Select mode="multiple" showSearch optionFilterProp="label" options={assetChoices}/></Form.Item>
            <Form.Item name="batchSize" label="金丝雀后每批数量" rules={[{ required: true }]} extra="控制第一台验收通过后的同时推进数量，失败时应先核对原因再继续。"><InputNumber min={1} max={100} /></Form.Item>
          </> : <>
            <Form.Item className="module-field-wide" name="enabled" label="启用" valuePropName="checked" extra="控制此配置是否参与后续运行；保存后生效，停用仍保留既有历史记录。"><Switch /></Form.Item>
            {section === 'backup' ? <>
              <Form.Item name="intervalHours" label="备份间隔（小时）" rules={[{ required: true }]} extra="两次成功备份之间的最短间隔；请结合数据变更频率与可接受的恢复范围设置。"><InputNumber min={1} max={168} /></Form.Item>
              <Form.Item name="keepCount" label="保留备份数量" rules={[{ required: true }]} extra="保留最近成功备份的份数；自动清理旧备份前应确认当前恢复策略能覆盖需要的时间。"><InputNumber min={1} max={30} /></Form.Item>
              <div className="module-field-wide"><Alert type="warning" showIcon message="超过保留数量后仅清理该工作进程创建的旧备份，请定期演练恢复。" /></div>
            </> : <>
              <Form.Item className="module-field-wide" name="url" label="HTTPS 接收地址（留空保留已有地址）" extra="填写通知接收服务的受信 HTTPS 入口；留空不会清除原地址，保存后可做投递测试。"><Input /></Form.Item>
              <Form.Item className="module-field-wide" name="secret" label="签名密钥（至少 16 字符，留空保留）" extra="接收端使用同一密钥验证投递签名；留空保留原密钥，轮换时同步更新接收端。"><Input.Password autoComplete="new-password" /></Form.Item>
              <div className="module-field-wide"><Alert type="info" showIcon message="只发送自己的通知。稳定投递 ID 用于接收端去重；失败按退避重试。" /></div>
            </>}
          </>}
        </Form>
      </div>
    </FormDrawer>
  </div>;
}

export function ExecutorKeyEditor({ record, onChanged,initialOpen=false,onClose,onBusyChange }: { record: any; onChanged: () => void;initialOpen?:boolean;onClose?:()=>void;onBusyChange?:(busy:boolean)=>void }) {
  const [open, setOpen] = useState(initialOpen), [value, setValue] = useState(record.executorPublicKey||''), [error, setError] = useState(''), [busy, setBusy] = useState(false);
  const [confirmDisable, setConfirmDisable] = useState(false);
  async function save(key: string | null) {
      setError('');
      try {
        if (key !== null && !key.trim()) throw Error('请填写受信执行器导出的公钥');
        setBusy(true);onBusyChange?.(true); await api('/assets/' + record.id, { executorPublicKey: key?.trim() ?? null }, 'PATCH'); setOpen(false); onChanged();
      } catch (e) { setError((e as Error).message); }
      finally { setBusy(false);onBusyChange?.(false); }
  }
  return <>{!initialOpen&&<Button disabled={busy} onClick={() => { setError(''); setConfirmDisable(false); setValue(record.executorPublicKey || ''); setOpen(true); }}>执行器结果验签</Button>}
    {open && <section className="module-subsection executor-key-editor" aria-label="执行器结果公钥"><h3>执行器结果公钥</h3>
      <div className="module-stack">
        {error && <Alert type="error" showIcon message={error} />}
        <Alert type="info" showIcon message="绑定后，缺失或无效签名的执行结果只能记为未知，不能关闭风险。私钥保留在主机特权执行器中。" />
        <Form layout="vertical"><Form.Item htmlFor="executor-result-public-key" label="Ed25519 原始 32 字节公钥（Base64）" extra="填写执行器实际使用的公开验证材料，用于验签已保存结果；不要填写私钥或安装票据。"><Input.TextArea id="executor-result-public-key" disabled={busy} rows={3} value={value} onChange={e => setValue(e.target.value)} /></Form.Item></Form>
        {confirmDisable && <Alert type="warning" showIcon message="该资产将不再强制要求受信执行器签名。仅在明确的迁移或恢复流程中停用。" />}
        <ModuleToolbar>
          {confirmDisable ? <><Button danger aria-label="确认停用验签" aria-busy={busy} loading={busy} onClick={() => void save(null)}>确认停用验签</Button><Button disabled={busy} onClick={() => setConfirmDisable(false)}>保留验签</Button></> : <><Button type="primary" aria-label="保存公钥" aria-busy={busy} loading={busy} onClick={() => void save(value)}>保存公钥</Button>{record.executorPublicKey && <Button danger disabled={busy} onClick={() => setConfirmDisable(true)}>停用验签</Button>}</>}
          <Button disabled={busy} onClick={() => {setOpen(false);onClose?.();}}>取消编辑</Button>
        </ModuleToolbar>
      </div>
    </section>}
  </>;
}

export function CompletionPanel({section,onOpenFinding,readOnly=false}:{section:string;onOpenFinding?:(id:string)=>void;readOnly?:boolean}){const[tab,setTab]=useState('rollouts'),[revision,setRevision]=useState(0);if(section==='webhook')return <Tabs items={[{key:'inapp',label:'站内提醒',children:<GovernancePanel simpleNotifications section="notifications" onOpenFinding={onOpenFinding}/>},{key:'webhook',label:'外部通知渠道',children:<LegacyCompletionPanel readOnly={readOnly} section="webhook"/>}]}/>;return section==='rollouts'?<Tabs activeKey={tab} onChange={setTab} items={[{key:'versions',label:'发行版本',children:<AgentInstallationPanel releasesOnly onViewRollouts={()=>{setTab('rollouts');setRevision(value=>value+1);}}/>},{key:'rollouts',label:'灰度升级计划',children:<LegacyCompletionPanel readOnly={readOnly} key={revision} section={section}/>} ]}/>:<LegacyCompletionPanel readOnly={readOnly} section={section}/>;}
