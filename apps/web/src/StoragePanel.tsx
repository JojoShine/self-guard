import { useEffect, useState } from 'react';
import { Alert, App, Button, Descriptions, Form, InputNumber, Switch, Typography, Skeleton } from 'antd';
import { api } from './api';
import {canViewConfiguration} from './public-read-only';
import { ModuleSection, ModuleToolbar } from './ModuleSection';
import { formatTime } from './presentation';

export function StoragePanel() {
  const { message } = App.useApp();
  const [data, setData] = useState<any>();
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [admin, setAdmin] = useState(false);
  const [canView,setCanView] = useState(false);
  const [form] = Form.useForm();
  async function load() {
    setLoading(true); setError('');
    try {
      const me = await api('/auth/me');
      setAdmin(me.role === 'ADMIN');
      setCanView(canViewConfiguration(me));
      if (!canViewConfiguration(me)) return;
      const value = await api('/storage');
      setData(value); form.setFieldsValue(value.policy);
    } catch (e) { setError((e as Error).message); }
    finally { setLoading(false); }
  }
  useEffect(() => { void load(); }, []);
  if (loading && !data) return <ModuleSection title="存储使用情况"><Skeleton active title={false} paragraph={{rows:4}}/></ModuleSection>;
  if (!canView && !error) return null;
  return <div className="module-stack">
    {error && <Alert type="error" showIcon message={error} action={<Button onClick={() => void load()}>重新加载</Button>} />}
    {canView && <>
      <ModuleSection title="存储使用情况" description="日志类记录的当前规模与最近自动清理时间。" extra={<Button loading={loading} disabled={busy} onClick={() => void load()}>刷新存储状态</Button>}>
        {data && <Descriptions bordered column={{ xs: 1, sm: 1, md: 2, xl: 3 }} size="small" items={[
          { key: 'db', label: '数据库大小', children: (data.databaseBytes / 1048576).toFixed(1) + ' MiB' },
          { key: 'telem', label: '遥测记录', children: data.counts.telemetry },
          { key: 'waf', label: 'WAF 攻击记录', children: data.counts.wafEvents },
          { key: 'access', label: 'WAF 访问快照', children: data.counts.access },
 {key:'effectiveAccess',label:'有效访问记录',children:data.counts.effectiveAccess},
 ...(data.accessEvidence?[{key:'evidence',label:'加密请求与响应',children:(data.accessEvidence.bytes/1048576).toFixed(1)+' MiB / '+(data.accessEvidence.limitBytes/1024**3).toFixed(1)+' GiB · 正文7天'},{key:'indexRetention',label:'有效访问索引',children:data.accessEvidence.indexLimit+' 条 / '+data.accessEvidence.indexDays+' 天'}]:[]),
          { key: 'history', label: '资产变更', children: data.counts.assetChanges },
          { key: 'last', label: '最近自动清理', children: data.lastCleanup ? formatTime(data.lastCleanup.at) : '尚未执行' },
          ...(data.intelligenceArtifacts?[{key:'intelligence',label:'原始情报文件',children:(data.intelligenceArtifacts.bytes/1048576).toFixed(1)+' MiB / '+(data.intelligenceArtifacts.limitBytes/1024**3).toFixed(1)+' GiB'},{key:'intelligence-reserved',label:'同步在途预留',children:(data.intelligenceArtifacts.reservedBytes/1048576).toFixed(1)+' MiB'}]:[]),
        ]} />}
      </ModuleSection>
      <ModuleSection title="存储上限与自动清理" description="达到日志记录上限后拒收新增记录，组件保留未确认队列直到恢复。">
        <Alert showIcon type="warning" message="自动清理默认关闭；开启后每小时按已保存的保留策略清理，无法在平台内撤销。不会删除未到期记录来腾出空间。" style={{ marginBottom: 20 }} />
        <Form form={form} layout="vertical" className="module-form-grid" disabled={busy || !data || !admin} onFinish={async v => {
          setBusy(true); setError('');
          try { await api('/storage', v, 'PATCH'); message.success('存储策略已保存'); await load(); }
          catch (e) { setError((e as Error).message); }
          finally { setBusy(false); }
        }}>
          {Object.entries({ effectiveAccessLimit:'有效访问索引行数上限',effectiveAccessDays:'有效访问索引保留天数',telemetryLimit: '遥测行数上限', wafEventLimit: 'WAF 攻击记录行数上限', accessLimit: '访问快照行数上限', telemetryDays: '遥测保留天数', accessDays: '访问快照保留天数', assetChangeDays: '资产变更保留天数' }).map(([key, label]) => <Form.Item key={key} name={key} label={label} rules={[{ required: true }]} extra="设置该类原始数据的保留或容量预算；达到限制时按本页策略处理，不表示业务风险已消除。"><InputNumber precision={0} min={key.endsWith('Limit') ? 100 : key === 'assetChangeDays' ? 30 : key==='effectiveAccessDays'?7:1} max={key.endsWith('Limit') ? 10000000 : 3650} /></Form.Item>)}
          <Form.Item name="accessEvidenceQuotaGiB" label="有效访问正文空间（GiB）" rules={[{required:true}]} extra="正文始终按捕获时间滚动保留7天，到期自动拒绝读取并清理；不受索引自动清理开关影响。达到配额时由探针独立加密队列背压。运行配置固定上限时以实际显示值为准。"><InputNumber precision={0} min={1} max={1024}/></Form.Item>
 <Form.Item name="intelligenceArtifactQuotaGiB" label="原始情报文件上限（GiB）" rules={[{required:true}]} extra="保留检测所依据的原始数据包。达到空间与在途预留预算后停止新同步，保留旧快照；自动清理日志不会删除这些源文件。运行配置固定上限时，以实际显示值为准。"><InputNumber precision={0} min={1} max={1024}/></Form.Item>
          <Form.Item name="automaticCleanup" label="自动清理到期记录" valuePropName="checked" extra="开启后按保留期限清理对应原始数据；不会删除资产、风险、事件与修复任务。"><Switch checkedChildren="开启" unCheckedChildren="关闭" /></Form.Item>
          <div className="module-field-wide"><ModuleToolbar><Button type="primary" htmlType="submit" loading={busy}>保存存储策略</Button></ModuleToolbar></div>
        </Form>
        <Typography.Paragraph className="module-note" type="secondary" style={{ marginTop: 16, marginBottom: 0 }}>数据库大小含索引与空闲页；行数限制不等于磁盘硬配额。遥测天数变更作用于新入库事件，既有记录沿用原有效期；到期事件自动清除。已保存的审计、WAF 攻击记录、检测和通知保留天数同时用于自动清理。</Typography.Paragraph>
      </ModuleSection>
    </>}
  </div>;
}
