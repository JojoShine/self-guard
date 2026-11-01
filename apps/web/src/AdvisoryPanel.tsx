import {IntelligencePanel} from './IntelligencePanel';
import {paginationDefaults} from './pagination';
import {ModuleSection,ModuleToolbar,StatusTag} from './ModuleSection';
import './detection-panels.css';
import { useEffect, useState } from "react";
import { Alert, App, Button, Form, Input, Modal, Select, Space, Switch, Table, Typography, Tabs } from "antd";
import { api } from "./api";
import {formatTime} from './presentation';

const statusNames: Record<string, string> = { IDLE: "尚未同步", SYNCING: "同步中", SUCCEEDED: "同步完成", PARTIAL: "部分覆盖", FAILED: "同步失败" };
const when = (value?: string) => value ? formatTime(value) : "尚无成功同步";
function LegacyAdvisoryPanel() {
  const { message } = App.useApp();
  const [form] = Form.useForm();
  const [items, setItems] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [busyId, setBusyId] = useState("");
  const [saving, setSaving] = useState(false);
  const [canEdit, setCanEdit] = useState(false);
  const [error, setError] = useState("");
  const [open, setOpen] = useState(false);
  const [editing, setEditing] = useState<any>();
  async function load() {
    setLoading(true);
    try {
      const results = await Promise.allSettled([api("/advisories/sources"), api("/auth/me")]);
      if (results[0].status === "fulfilled") setItems(results[0].value.items);
      if (results[1].status === "fulfilled") setCanEdit(["ADMIN", "ANALYST"].includes(results[1].value.role));
      for (const result of results) if (result.status === "rejected") throw result.reason;
    } catch (e) { setError((e as Error).message); }
    finally { setLoading(false); }
  }
  useEffect(() => { void load(); }, []);
  function edit(source?: any) {
    setError(""); setEditing(source); form.resetFields();
    form.setFieldsValue(source || { format: "OSV", enabled: true }); setOpen(true);
  }
  async function save() {
    try {
      const values = await form.validateFields();
      setSaving(true); setError("");
      await api(editing ? `/advisories/sources/${editing.id}` : "/advisories/sources", values, editing ? "PATCH" : "POST");
      setOpen(false); message.success("数据源已保存"); await load();
    } catch (e) { if (e instanceof Error) setError(e.message); }
    finally { setSaving(false); }
  }
  async function sync(source: any) {
    setBusyId(source.id); setError("");
    try {
      const result = await api(`/advisories/sources/${source.id}/sync`, {});
      await load();
      if (result.source.status === "FAILED") { setError(result.source.error || "同步失败，可修正数据源或稍后重试"); return; }
      if (result.summary.withdrawn) message.info("该通告已撤回，已有来源规则已停用");
      else if (result.source.status === "PARTIAL") message.warning(`同步完成，导入 ${result.summary.imported} 条检测规则；存在未覆盖内容`);
      else message.success(`同步完成，导入 ${result.summary.imported} 条检测规则`);
    } catch (e) { setError((e as Error).message); }
    finally { setBusyId(""); }
  }
  return <div className="module-stack detection-panel">
    {error && <Alert type="error" message={error} showIcon closable onClose={() => setError("")} />}
    <ModuleSection title="漏洞数据源" description="管理 OSV 通告来源，并查看最近同步的规则覆盖情况。"><details className="module-note detection-guidance"><summary>{"OSV 单条通告数据源"}</summary><p>读取官方 OSV 通告，将 Debian、Ubuntu、Alpine 明确列出的版本，以及 Debian、Ubuntu 的 ECOSYSTEM 版本范围转为漏洞检测规则。Alpine 范围、其他范围类型及 Debian OVAL 尚不支持；未覆盖内容会明确列出，不能据此判断资产安全。未提供可识别严重级别的通告使用“信息”级别。</p></details>
    <ModuleToolbar><Button type="primary" disabled={!canEdit} onClick={() => edit()}>添加漏洞数据源</Button><Button loading={loading} onClick={() => { setError(""); void load(); }}>刷新数据源</Button><Button onClick={() => { location.hash = "rules"; }}>查看检测规则</Button>{!canEdit&&<span className="module-note">当前账户可查看数据源，无法编辑或同步</span>}</ModuleToolbar>
    <Table<any> pagination={paginationDefaults} rowKey="id" size="small" loading={loading} dataSource={items} locale={{emptyText:"暂无漏洞数据源"}} scroll={{ x: 1000 }} columns={[
      { title: "数据源", dataIndex: "name", render: (name, row) => <Space direction="vertical" size={0}><Typography.Text>{name}</Typography.Text><Typography.Link href={row.url} target="_blank" rel="noreferrer" style={{ maxWidth: 300, overflowWrap: "anywhere" }}>{row.url}</Typography.Link></Space> },
      { title: "启用", dataIndex: "enabled", render: value => <StatusTag value={value ? "ENABLED" : "DISABLED"} labels={{ENABLED:"已启用",DISABLED:"已停用"}}/> },
      { title: "同步状态", dataIndex: "status", render: (value, row) => <Space direction="vertical" size={4}><StatusTag value={value} labels={statusNames}/>{row.error && <Typography.Text type="danger" style={{ maxWidth: 220 }}>{row.error}</Typography.Text>}</Space> },
      { title: "上次成功同步", dataIndex: "lastSyncAt", render: when },
      { title: "最近成功同步覆盖", render: (_, row) => row.lastResult ? <Space direction="vertical" size={2}>
        <span>{row.lastResult.withdrawn ? "通告已撤回，规则停用" : `${row.lastResult.imported} 条检测规则`}</span>
        {row.lastResult.rangeRules !== undefined && <Typography.Text type="secondary">明确版本 {row.lastResult.exactVersionRules} 条 · 版本范围 {row.lastResult.rangeRules} 条</Typography.Text>}
        {!!row.lastResult.skippedRanges && <Typography.Text type="warning">{row.lastResult.skippedRanges} 个范围未支持</Typography.Text>}
        {!!row.lastResult.skippedEntries && <Typography.Text type="warning">{row.lastResult.skippedEntries} 个条目未导入</Typography.Text>}
        {!!row.lastResult.skippedEcosystems?.length && <Typography.Text type="secondary">未支持：{row.lastResult.skippedEcosystems.join("、")}</Typography.Text>}
      </Space> : "尚无同步结果" },
      { title: "操作", fixed: "right", render: (_, row) => canEdit ? <Space direction="vertical"><Button size="small" disabled={!!busyId || !row.enabled || (row.status === "SYNCING" && Date.now() - new Date(row.updatedAt).getTime() < 120000)} loading={busyId === row.id} onClick={() => void sync(row)}>{row.status === "FAILED" ? "重试同步" : "同步通告"}</Button><Button size="small" disabled={!!busyId} onClick={() => edit(row)}>编辑数据源</Button></Space> : "—" },
    ]} />
    <Typography.Paragraph className="module-note" type="secondary">展示最近 100 个数据源。通告同步不会自动执行检测；请在检测规则中发起检测。停用来源或修改地址会停用该来源已生成的规则，启用后需要重新同步。</Typography.Paragraph>
    </ModuleSection>
 <Modal centered className="module-modal" title={editing ? "编辑漏洞数据源" : "添加漏洞数据源"} open={open} closable={!saving} maskClosable={!saving} cancelButtonProps={{disabled:saving}} onCancel={() => !saving&&setOpen(false)} onOk={() => void save()} confirmLoading={saving} okText="保存数据源">
      {error && <Alert type="error" message={error} style={{ marginBottom: 12 }} />}
      <Form form={form} layout="vertical" className="detection-form module-form-grid" disabled={saving}>
        <Form.Item name="name" label="数据源名称" extra="为历史通告转规则任务命名，便于区分来源。" rules={[{ required: true, whitespace: true, max: 500 }]}><Input placeholder="例如 Debian 安全通告" /></Form.Item>
        <Form.Item name="format" label="通告格式" extra="此历史入口按单条 OSV 通告转换规则；多源快照请使用前一标签页。"><Select options={[{ value: "OSV", label: "OSV JSON（单条通告）" }]} /></Form.Item>
        <Form.Item className="module-field-wide" name="url" label="通告地址" rules={[{ required: true }, { type: "url", message: "请输入有效 HTTPS 地址" }, { max: 500 }]} extra="官方地址：https://api.osv.dev/v1/vulns/漏洞编号；自建来源域名需由部署管理员明确允许。"><Input placeholder="https://api.osv.dev/v1/vulns/DSA-2026-0000" /></Form.Item>
        <Form.Item name="enabled" label="启用来源" extra="停用来源会停用该来源已生成的规则，重新启用后需同步。" valuePropName="checked"><Switch /></Form.Item>
        <Alert className="module-field-wide" type="warning" showIcon message="停用来源或修改地址会停用已有来源规则；重新启用后需同步。单次响应最多 2 MiB，10 秒超时；失败可重试。" />
      </Form>
    </Modal>
  </div>;
}

export function AdvisoryPanel(){return <Tabs items={[{key:"intelligence",label:"多源情报与快照",children:<IntelligencePanel/>},{key:"legacy",label:"历史通告转规则",children:<LegacyAdvisoryPanel/>}]}/>;}
