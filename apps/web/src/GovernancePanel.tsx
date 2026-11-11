import {paginationDefaults,pageWithinTotal} from './pagination';
import { useEffect, useRef, useState } from "react";
import {
  Alert, App, Button, Checkbox, Descriptions, Form, Input, InputNumber,
  Modal, Select, Space, Switch, Table, Typography, Skeleton,
} from "antd";
import { api } from "./api";
import { ModuleSection, ModuleToolbar, StatusTag } from "./ModuleSection";
import { formatTime } from "./presentation";

const { Text, Paragraph } = Typography;
const roles = [
  { value: "ADMIN", label: "管理员" },
  { value: "ANALYST", label: "安全分析员" },
  { value: "OPERATOR", label: "运维操作员" },
  { value: "VIEWER", label: "只读用户" },
];
const retentionLabels: Record<string, string> = {
  auditDays: "操作审计", wafEventDays: "WAF 原始事件", evaluationDays: "检测结果", notificationDays: "站内通知",
};
const categoryLabels: Record<string, string> = { audit: "操作审计", wafEvents: "WAF 原始事件", evaluations: "检测结果", notifications: "站内通知" };
const statusLabels: Record<string, string> = { PENDING: "等待处理", RUNNING: "导入中", FAILED: "导入失败", SUCCEEDED: "导入完成" };
const date = formatTime;
const importExample = JSON.stringify({ items: [{ externalId: "scanner-001", title: "检查结果", kind: "RISK", severity: "HIGH", source: "external-scanner", evidence: "外部检查证据" }] }, null, 2);

export function GovernancePanel({ section,onOpenFinding,simpleNotifications=false }: { section: string;onOpenFinding?:(id:string)=>void;simpleNotifications?:boolean }) {
  const { message } = App.useApp();
  const [form] = Form.useForm();
  const [settingsForm] = Form.useForm();
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [user, setUser] = useState<any>();
  const [data, setData] = useState<any>({});
  const [preview, setPreview] = useState<any>();
  const [purgeOpen, setPurgeOpen] = useState(false);
  const [importOpen, setImportOpen] = useState(false);
  const [retryBatch, setRetryBatch] = useState<any>();
  const [importText, setImportText] = useState(importExample);
  const [page, setPage] = useState(1);
  const [pageSize,setPageSize] = useState(paginationDefaults.defaultPageSize);
  const request = useRef(0);
  const admin = user?.role === "ADMIN";
  const canImport = ["ADMIN", "ANALYST"].includes(user?.role);
  async function load(targetPage = page,size=pageSize) {
    const current = ++request.current;
    setLoading(true);
    setError("");
    try {
      const currentUser = await api("/auth/me");
      if (current !== request.current) return;
      setUser(currentUser);
      if (section === "governance") {
        const result = await api("/governance/approval-policy");
        if (current !== request.current) return;
        setData(result); form.setFieldsValue(result);
      } else if (section === "retention") {
        if (currentUser.role !== "ADMIN") { setData({}); return; }
        const result = await api("/governance/retention");
        if (current !== request.current) return;
        setData(result); form.setFieldsValue(result);
      } else if (section === "notifications") {
        const [settings, notifications] = await Promise.all([
          api("/governance/notification-settings"),
          api(`/governance/notifications?page=${targetPage}&pageSize=${size}`),
        ]);
        if (current !== request.current) return;
        const validPage=pageWithinTotal(targetPage,notifications.total,size);
        if(validPage!==targetPage){await load(validPage,size);return;}
        settingsForm.setFieldsValue(settings); setData(notifications);setPage(targetPage);setPageSize(size);
      } else if (section === "imports") {
        if (!["ADMIN", "ANALYST"].includes(currentUser.role)) { setData({}); return; }
        const result = await api("/governance/imports");
        if (current === request.current) setData(result);
      }
    } catch (e) { if (current === request.current) setError((e as Error).message); }
    finally { if (current === request.current) setLoading(false); }
  }
  useEffect(() => {
    setData({}); setUser(undefined); setPage(1); setPreview(undefined); setImportOpen(false); setPurgeOpen(false);
    form.resetFields(); settingsForm.resetFields();
    void load(1);
    return () => { request.current++; };
  }, [section]);
  async function action(work: () => Promise<void>) {
    setBusy(true); setError("");
    try { await work(); }
    catch (e) { setError((e as Error).message); }
    finally { setBusy(false); }
  }
  async function save(path: string, values: unknown) {
    await action(async () => {
      await api("/governance/" + path, values, "PATCH");
      message.success("设置已保存"); setPreview(undefined); await load();
    });
  }
  function openImport(batch?: any) {
    setRetryBatch(batch);
    setImportText(batch ? JSON.stringify({ items: batch.items }, null, 2) : importExample);
    setImportOpen(true);
  }
  if (loading && !Object.keys(data).length) return <ModuleSection title={section==="governance"?"审批策略":section==="retention"?"数据保留与清理":section==="notifications"?"站内通知":"外部结果导入"}><Skeleton active title={false} paragraph={{rows:4}}/></ModuleSection>;
  return <div className="module-stack">
    {error && <Alert type="error" message={error} showIcon closable onClose={() => setError("")} action={<Button size="small" onClick={() => void load()}>重新加载</Button>} />}
    {section === "governance" && <ModuleSection title="审批策略" extra={<Button loading={loading} disabled={busy} onClick={() => void load()}>刷新策略</Button>} description="设置审批角色与申请人自批规则，保存后即时应用于批准和驳回。">

      {!admin && <Alert type="info" message="当前策略可查看；管理员可以修改审批设置。" showIcon />}
      <Form form={form} layout="vertical" className="module-form-grid" disabled={!admin || busy} onFinish={v => void save("approval-policy", v)}>
        <Form.Item name="approverRoles" label="允许审批的角色" rules={[{ required: true, type: "array", min: 1, message: "至少选择一个审批角色" }]} extra="只有这些角色可以批准或驳回受控修复申请；保存后会立即影响后续审批。">
          <Select mode="multiple" options={roles} />
        </Form.Item>
        <Form.Item name="allowSelfApproval" label="允许申请人自批" valuePropName="checked" extra="决定申请人能否批准自己提交的任务；与审批角色限制同时生效。"><Switch checkedChildren="允许" unCheckedChildren="禁止" /></Form.Item>
        <Form.Item className="module-field-wide"><Button type="primary" htmlType="submit" loading={busy}>保存审批策略</Button></Form.Item>
      </Form>
    </ModuleSection>}
    {section === "retention" && (admin ? <ModuleSection title="数据保留与清理" extra={<Button loading={loading} disabled={busy} onClick={() => void load()}>刷新设置</Button>} description="先保存保留设置，再预览到期范围并确认清理。">
      <Paragraph>配置保留天数后，可预览到期记录，再确认清理。审计至少保留 30 天；清理不包含资产、问题、事件和修复任务。</Paragraph>
      <Form form={form} layout="vertical" className="module-form-grid" disabled={busy} onFinish={v => void save("retention", v)}>
        {Object.entries(retentionLabels).map(([key, label]) => <Form.Item key={key} name={key} label={`${label}（天）`} rules={[{ required: true }]} extra="保留超过设定天数的对应记录进入到期范围；审计至少保留30天，清理前先预览。"><InputNumber min={key === "auditDays" ? 30 : 1} max={3650} precision={0} /></Form.Item>)}
        <Form.Item className="module-field-wide"><Button type="primary" htmlType="submit" loading={busy}>保存保留设置</Button></Form.Item>
      </Form>
      <ModuleToolbar><Button loading={busy} onClick={() => void action(async () => setPreview(await api("/governance/retention/preview", {})))}>预览到期记录</Button>{preview && <Button danger disabled={busy} onClick={() => setPurgeOpen(true)}>清理到期记录</Button>}</ModuleToolbar>
      {preview && <Descriptions bordered column={{ xs: 1, sm: 1, md: 2 }} size="small" title="到期记录预览" style={{ marginTop: 20 }}>
        {Object.entries(preview.counts).map(([key, count]) => <Descriptions.Item key={key} label={categoryLabels[key] || key}>{String(count)} 条 · 创建于 {date(preview.cutoffs[key])} 之前</Descriptions.Item>)}
      </Descriptions>}
      <Modal className="module-modal" width="min(640px, calc(100vw - 32px))" title="确认永久清理到期记录" open={purgeOpen} closable={!busy} maskClosable={!busy} cancelButtonProps={{disabled:busy}} onCancel={() => !busy && setPurgeOpen(false)} cancelText="取消" okText="确认清理" okButtonProps={{ danger: true, loading: busy }} onOk={() => void action(async () => {
        const result = await api("/governance/retention/purge", { confirm: true });
        message.success(`已清理 ${Object.values(result.deleted).reduce((sum: number, n) => sum + Number(n), 0)} 条记录`);
        setPurgeOpen(false); setPreview(await api("/governance/retention/preview", {}));
      })}>
        {error && <Alert type="error" showIcon message={error} />}
        <Paragraph>将按已保存的保留设置，永久删除到期的审计、WAF 原始事件、检测结果和通知。此操作无法在平台内撤销。</Paragraph>
        {preview && <Paragraph>当前预览共 {Object.values(preview.counts).reduce((sum: number, n) => sum + Number(n), 0)} 条；执行时按当前时间重新计算到期范围。</Paragraph>}
      </Modal>
    </ModuleSection> : <Alert type="info" message="保留设置与清理功能仅管理员可用。" showIcon />)}
    {section === "notifications" && <>
      <ModuleSection title="通知订阅" description="选择需要接收的站内提醒。">
      <Form form={settingsForm} layout="vertical" className="module-form-grid" disabled={busy} onFinish={v => void save("notification-settings", v)}>
        <Form.Item name="enabled" valuePropName="checked" extra="控制是否生成你的站内提醒，停用不改变实际风险和任务状态。"><Checkbox>启用站内通知</Checkbox></Form.Item>
        {!simpleNotifications&&<Form.Item name="approvals" valuePropName="checked" extra="当当前权限允许审批的任务进入待审批时提醒，仍需逐项核对审批依据。"><Checkbox>我可审批的任务</Checkbox></Form.Item>}
        {!simpleNotifications&&<Form.Item name="taskFailures" valuePropName="checked" extra="只提醒你提交任务的失败情况；请进入任务核对执行与验证结果。"><Checkbox>我提交的任务失败</Checkbox></Form.Item>}
        <Form.Item name="criticalFindings" valuePropName="checked" extra="当严重问题指派给你时提醒，后续处置仍在安全中心完成。"><Checkbox>指派给我的严重问题</Checkbox></Form.Item>
        <Form.Item name="assignedFindings" valuePropName="checked" extra="仅站内提醒；对当前仍待处理、指派给你的问题首次提醒；通知保留期间不重复生成。"><Checkbox>指派给我的普通问题（站内）</Checkbox></Form.Item>
        <Form.Item name="overdueFindings" valuePropName="checked" extra="仅站内提醒；通知保留期间，同一处理期限只提醒一次；清理通知后仍未处理的问题可能再次提醒。超期24小时后，向开启此项且有查看权限的管理员升级；修改期限后独立计算。"><Checkbox>问题超期与24小时升级（站内）</Checkbox></Form.Item>
        <Form.Item className="module-field-wide"><Button type="primary" htmlType="submit" loading={busy}>保存订阅</Button></Form.Item>
      </Form>
      </ModuleSection>
      <ModuleSection title="站内通知" extra={<Button loading={loading} disabled={busy} onClick={() => void load()}>刷新通知</Button>}>
      <ModuleToolbar><Text>未读 {data.unread || 0} 条</Text><Button loading={busy} onClick={() => void action(async () => { const result = await api("/governance/notifications/sync", {}); message.success(`新增 ${result.created} 条通知`); setPage(1); await load(1); })}>同步站内待办</Button></ModuleToolbar>
      <Paragraph className="module-note" type="secondary">按已保存的订阅和当前授权范围生成站内通知。列表保留生成时的记录，当前状态请进入对应问题查看。</Paragraph>
      <Table<any> rowKey="id" loading={loading} dataSource={data.items || []} size="small" scroll={{ x: 760 }} locale={{ emptyText: "暂无站内通知" }} pagination={{...paginationDefaults,current:page,total:data.total||0,pageSize,disabled:loading,onChange:(next,size)=>{const target=size===pageSize?next:1;void load(target,size);}}} columns={[
        { title: "通知", dataIndex: "title" },
        { title: "状态", dataIndex: "readAt", render: v => <StatusTag value={v?"READ":"UNREAD"}/> },
        { title: "时间", dataIndex: "createdAt", render: date },
        { title: "操作", render: (_, row) => <Space><Button size="small" onClick={() => { if(row.resource==='findings'&&row.resourceId&&onOpenFinding){onOpenFinding(row.resourceId);return} location.hash = row.resource === "tasks" ? "tasks" : "findings"; }}>查看{row.resource === "tasks" ? "任务" : "问题"}</Button>{!row.readAt && <Button size="small" disabled={busy} onClick={() => void action(async () => { await api(`/governance/notifications/${row.id}/read`, {}, "PATCH"); await load(); })}>标为已读</Button>}</Space> },
      ]} />
      </ModuleSection>
    </>}
    {section === "imports" && (canImport ? <ModuleSection title="外部结果导入" description="批量导入风险与告警结果，并跟踪处理状态。">
      <ModuleToolbar><Button type="primary" disabled={busy} onClick={() => openImport()}>导入外部结果</Button><Button loading={loading} disabled={busy} onClick={() => void load()}>刷新批次</Button></ModuleToolbar>
      <Paragraph className="module-note">支持风险和告警结果。单批最多 100 条；按来源、外部编号、资产及类型去重。失败批次可修正后重试，整批成功后才写入结果。</Paragraph>
      <Table<any> pagination={paginationDefaults} rowKey="id" loading={loading} size="small" dataSource={data.items || []} scroll={{ x: 850 }} locale={{ emptyText: "暂无导入批次" }} columns={[
        { title: "批次", dataIndex: "id", ellipsis: true },
        { title: "提交人", dataIndex: "actor" },
        { title: "状态", dataIndex: "status", render: s => <StatusTag value={s} labels={statusLabels} /> },
        { title: "结果", render: (_, row) => row.error || (row.result ? `${row.result.total} 条完成` : "等待结果") },
        { title: "创建时间", dataIndex: "createdAt", render: date },
        { title: "操作", render: (_, row) => row.status === "FAILED" ? <Button size="small" disabled={busy} onClick={() => openImport(row)}>修正并重试</Button> : "—" },
      ]} />
      <Text className="module-note" type="secondary">显示最近 100 个可见批次。管理员可查看全部，分析员可查看自己提交的批次。</Text>
      <Modal className="module-modal" width="min(760px, calc(100vw - 32px))" title={retryBatch ? "修正并重试导入" : "导入外部结果"} open={importOpen} closable={!busy} maskClosable={!busy} cancelButtonProps={{disabled:busy}} onCancel={() => !busy && setImportOpen(false)} cancelText="取消" confirmLoading={busy} okText={retryBatch ? "重试导入" : "开始导入"} onOk={() => void action(async () => {
        let payload;
        try { payload = JSON.parse(importText); } catch { throw new Error("JSON 格式无效，请检查后重试"); }
        const result = await api(retryBatch ? `/governance/imports/${retryBatch.id}/retry` : "/governance/imports", payload);
        setImportOpen(false); await load();
        if (result.status === "FAILED") message.warning("批次导入失败，原因已记录，可修正后重试");
        else message.success(`成功导入 ${result.result?.total || 0} 条结果`);
      })}>
        {error && <Alert type="error" message={error} showIcon style={{ marginBottom: 12 }} />}
        {retryBatch?.error && <Alert type="warning" message={retryBatch.error} style={{ marginBottom: 12 }} />}
        <Paragraph>填写包含 items 数组的 JSON。资产编号 assetId 为可选字段，填写时必须对应现有资产。</Paragraph>
        <Input.TextArea rows={16} disabled={busy} value={importText} onChange={e => setImportText(e.target.value)} style={{ fontFamily: "monospace" }} />
      </Modal>
    </ModuleSection> : <Alert type="info" message="外部结果导入仅管理员和安全分析员可用。" showIcon />)}
  </div>;
}
