import {RecordSelect} from './RecordSelect';
import {paginationDefaults} from './pagination';
import {DateField} from './DateField';
import { useEffect, useState } from "react";
import { Button, Modal, Form, Input, Switch, Alert, Select, Table, Typography } from "antd";
import { api } from "./api";
import { ModuleSection, ModuleToolbar, StatusTag } from "./ModuleSection";
import { formatTime } from "./presentation";

export function WorkflowTools({ resource, record, onChanged,initialMode="",onClose,onBusyChange }: { resource: string; record: any; onChanged: () => void;initialMode?:string;onClose?:()=>void;onBusyChange?:(busy:boolean)=>void }) {
  const [mode, setMode] = useState(initialMode);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [form] = Form.useForm();
  async function open(next: string) {
    form.resetFields(); setError(""); setMode(next);
    if (next === "triage") form.setFieldsValue({ read: !!record.readAt, relatedRiskId: record.relatedRiskId });
    if (next === "context") form.setFieldsValue({ type: record.type, assetIds: record.assetIds || [], taskIds: record.taskIds || [], remainingRisks: record.remainingRisks });
  }

  async function send(path: string, body: unknown, method?: string) {
    setBusy(true);onBusyChange?.(true); setError("");
    try { await api(path, body, method); setMode(""); onChanged(); }
    catch (e) { setError((e as Error).message); throw e; }
    finally { setBusy(false);onBusyChange?.(false); }
  }
  async function submit() {
    try {
      const v = await form.validateFields();
      const root = "/workflows/" + resource + "/" + record.id;
      if (mode === "triage") await send(root + "/triage", {
        ...(v.dueAt ? { dueAt: new Date(v.dueAt).toISOString(), reason: v.reason } : {}),
        ...(record.kind === "ALERT" ? { relatedRiskId: v.relatedRiskId || null } : {}),
        read: !!v.read, confirmed: !!v.confirmed,
      }, "PATCH");
      if (mode === "context") await send(root + "/context", { type: v.type, remainingRisks: v.remainingRisks || "", assetIds: v.assetIds || [], taskIds: v.taskIds || [] }, "PATCH");
      if (mode === "window") await send(root + "/window", { notBefore: new Date(v.notBefore).toISOString(), windowEnd: new Date(v.windowEnd).toISOString() });
      if (mode === "cancel") await send(root + "/cancel", { reason: v.reason });
      if (mode === "archive") await send(root + "/archive", { archived: !record.archivedAt });
    } catch (e) { if (e instanceof Error) setError(e.message); }
  }
  const titles: Record<string, string> = { triage: "问题研判", context: "事件影响范围", window: "执行窗口（修改后重新审批）", cancel: "取消任务", archive: record.archivedAt ? "恢复资产" : "归档资产" };
  const submitLabel = ({triage:"保存研判",context:"保存影响范围",window:"保存执行窗口",cancel:"确认取消任务",archive:record.archivedAt?"确认恢复资产":"确认归档资产"} as Record<string,string>)[mode];
  if (!["assets","findings","incidents","tasks"].includes(resource)) return null;
  return <>
    {!mode && error && <Alert type="error" showIcon message={error} closable onClose={() => setError("")} />}
    {!initialMode&&<ModuleToolbar>
      {resource === "assets" && <Button disabled={busy} onClick={() => void open("archive")}>{record.archivedAt ? "恢复资产" : "归档资产"}</Button>}
      {resource === "findings" && <Button disabled={busy} onClick={() => void open("triage")} title="确认、标记已读、调整期限或关联风险">问题研判</Button>}
      {resource === "incidents" && <Button disabled={busy} onClick={() => void open("context")}>影响范围与剩余风险</Button>}
      {resource === "tasks" && ["PENDING", "APPROVED"].includes(record.status) && <><Button disabled={busy} onClick={() => void open("window")}>设置执行窗口</Button><Button danger disabled={busy} onClick={() => void open("cancel")}>取消未执行任务</Button></>}
    </ModuleToolbar>}
    {!!mode&&<section className="workflow-inline-editor module-subsection" aria-label={titles[mode]||"处置表单"}><h3>{titles[mode]}</h3>
      {error && <Alert type="error" showIcon message={error} style={{ marginBottom: 12 }} />}
      <Form form={form} layout="vertical" className="module-form-grid" disabled={busy}>
        {mode === "triage" && <>
          <Form.Item name="read" label="已读" valuePropName="checked" extra="标记已阅读该发现，不代表问题已处理或已经修复。"><Switch /></Form.Item>
          {record.kind === "RISK" && record.status === "OPEN" && <Form.Item name="confirmed" label="确认风险" valuePropName="checked" extra="勾选表示已核对风险实际成立；仍需安排处置和独立复测。"><Switch /></Form.Item>}
          {record.kind === "ALERT" && <Form.Item name="relatedRiskId" label="关联风险" extra="选择与本告警存在实际关系的风险，保留关联便于后续调查；不要仅凭标题相似关联。"><RecordSelect resource="findings" kind="RISK" placeholder="按风险标题查找已有风险"/></Form.Item>}
          <Form.Item name="dueAt" label="新的处理期限" extra="调整负责人完成处置的时间，不会改变风险是否存在。"><DateField showTime/></Form.Item>
          <Form.Item name="reason" label="延期原因" extra="说明为什么需要延期以及后续安排，保留给其他处置人员核对。"><Input.TextArea /></Form.Item>
        </>}
        {mode === "context" && <>
          <Form.Item name="type" label="事件类型" rules={[{ required: true }]} extra="选择本次调查的主要类别，帮助分流和统计；它不会替代实际证据判断。"><Select options={[{value:'OTHER',label:'其他'},{value:'VULNERABILITY',label:'软件漏洞'},{value:'WEB_ATTACK',label:'Web攻击'},{value:'MALWARE',label:'恶意程序'},{value:'UNAUTHORIZED_ACCESS',label:'未授权访问'},{value:'CONFIGURATION',label:'配置风险'},...(!['OTHER','VULNERABILITY','WEB_ATTACK','MALWARE','UNAUTHORIZED_ACCESS','CONFIGURATION'].includes(record.type)&&record.type?[{value:record.type,label:'既有类型：'+record.type}]:[])]}/></Form.Item>
          <Form.Item name="assetIds" label="受影响资产" extra="选择已有证据涉及的主机；关联记录仍需位于当前账户授权范围。"><RecordSelect resource="assets" mode="multiple" placeholder="按主机名查找并选择"/></Form.Item>
          <Form.Item name="taskIds" label="处置任务" extra="关联本次调查中实际执行或计划执行的修复任务，便于回查审批和验证。"><RecordSelect resource="tasks" mode="multiple" placeholder="按任务标题查找并选择"/></Form.Item>
          <Typography.Paragraph type="secondary">目录每次加载15条，可按名称查找或继续加载；已有选择按记录身份保留。</Typography.Paragraph>
          <Form.Item name="remainingRisks" label="剩余风险说明" extra="说明尚未消除的风险、暂时保留原因和后续责任，不把事件结案等同所有风险关闭。"><Input.TextArea /></Form.Item>
        </>}
        {mode === "window" && <>
          <Form.Item name="notBefore" label="最早执行时间" rules={[{ required: true }]} extra="任务不得早于此时领取；使用当前本地时间，与窗口结束共同限定维护时间。"><DateField showTime/></Form.Item>
          <Form.Item name="windowEnd" label="窗口结束" rules={[{ required: true }]} extra="超过此时不能继续作为本次维护窗口领取；已发生的变更不会自动撤销。"><DateField showTime/></Form.Item>
        </>}
        {mode === "cancel" && <><Alert type="warning" message="取消仅阻止尚未执行的任务，不回滚已完成变更。" /><Form.Item name="reason" label="取消原因" rules={[{ required: true }]} extra="说明停止后续执行的业务原因；取消不会回滚已完成的主机变更。"><Input.TextArea /></Form.Item></>}
        {mode === "archive" && <div className="module-field-wide"><Alert type={record.archivedAt ? "info" : "warning"} showIcon message={record.archivedAt ? "恢复后允许 Agent 继续上报和领取任务；请核对主机身份及实际在线状态。" : "归档后保留历史记录，Agent 将不能上报或领取任务；存在执行中任务时不能归档。"} /></div>}
      </Form>
      <ModuleToolbar><Button type="primary" aria-label={submitLabel} aria-busy={busy} danger={(mode==="archive"&&!record.archivedAt)||mode==="cancel"} loading={busy} onClick={()=>void submit()}>{submitLabel}</Button><Button disabled={busy} onClick={()=>{setMode("");onClose?.();}}>取消编辑</Button></ModuleToolbar>
    </section>}
  </>;
}

export function WorkflowBatchPanel() {
  const [items, setItems] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [open, setOpen] = useState(false);
  const [canEdit, setCanEdit] = useState(false);
  const [form] = Form.useForm();
  async function load() {
    setLoading(true); setError("");
    try {
      const results = await Promise.allSettled([api("/workflows/batches"), api("/auth/me")]);
      if (results[0].status === "fulfilled") setItems(results[0].value.items);
      if (results[1].status === "fulfilled") setCanEdit(["ADMIN", "OPERATOR"].includes(results[1].value.role));
      for (const result of results) if (result.status === "rejected") throw result.reason;
    } catch (e) { setError((e as Error).message); }
    finally { setLoading(false); }
  }
  useEffect(() => { void load(); }, []);
  async function create() {
    try {
      const values = await form.validateFields();
      setBusy(true); setError("");
      await api("/workflows/batches", values); setOpen(false); await load();
    } catch (e) { if (e instanceof Error) setError(e.message); }
    finally { setBusy(false); }
  }
  return <div className="module-stack">
    {error && <Alert type="error" showIcon message={error} closable onClose={() => setError("")} />}
    <ModuleSection title="批次执行说明"><Typography.Paragraph>将未分组、待审批任务组成顺序执行批次。每个任务仍需独立审批；发生失败时可自动停止后续任务。停止批次不会回滚已经完成的变更。</Typography.Paragraph></ModuleSection>
    <ModuleSection title="修复批次" description="每个任务独立审批，并按批次顺序执行。" extra={<ModuleToolbar><Button type="primary" disabled={!canEdit||loading||busy} onClick={() => { form.resetFields(); form.setFieldsValue({ stopOnFailure: true }); setOpen(true); }}>新建修复批次</Button><Button onClick={() => void load()} disabled={busy} loading={loading}>刷新批次</Button></ModuleToolbar>}>
    {!canEdit&&!loading&&<Typography.Paragraph type="secondary">当前账户可查看批次；仅管理员与操作员可创建或停止批次。</Typography.Paragraph>}
    <Table<any> pagination={paginationDefaults} rowKey="id" dataSource={items} loading={loading} scroll={{x:1000}} locale={{emptyText:"暂无修复批次"}} columns={[
      { title: "批次", dataIndex: "title", width:260, render: value => <span className="module-record-title">{value}</span> },
      { title: "状态", dataIndex: "status", render: value => <StatusTag value={value} labels={{RUNNING:"执行中",STOPPED:"已停止",COMPLETED:"已完成"}}/> },
      { title: "失败处理", dataIndex: "stopOnFailure", render: value => value ? "失败即停止" : "继续后续任务" },
      { title: "创建人", dataIndex: "createdBy" },
      { title: "创建时间", dataIndex: "createdAt", render: formatTime },
      { title: "操作", render: (_, row) => canEdit && row.status === "RUNNING" ? <Button danger size="small" disabled={busy} onClick={() => Modal.confirm({ className: "module-modal", cancelText: "取消", title: "停止修复批次", content: "后续未执行任务将取消；正在执行和已完成的任务不受影响，已完成变更不会回滚。", okText: "确认停止", okButtonProps: { danger: true }, onOk: async () => {
        setBusy(true);
        try { await api(`/workflows/batches/${row.id}/stop`, {}); await load(); }
        catch (e) { setError((e as Error).message); throw e; }
        finally { setBusy(false); }
      } })}>停止批次</Button> : "—" },
    ]} />
    <Typography.Paragraph className="module-note" type="secondary">显示最近 100 个批次。任务可按名称查找、分批加载，仅选择尚未分组的待审批记录；保存时重新核对资格。</Typography.Paragraph>
    </ModuleSection>
    <Modal className="module-modal" title="新建修复批次" open={open} onCancel={() => { if (!busy) setOpen(false); }} closable={!busy} maskClosable={!busy} cancelButtonProps={{disabled:busy}} cancelText="取消" onOk={() => void create()} confirmLoading={busy} okText="创建批次">
      {error && <Alert type="error" showIcon message={error} style={{ marginBottom: 12 }} />}
      <Form form={form} layout="vertical" disabled={busy}>
        <Form.Item name="title" label="批次名称" rules={[{ required: true, whitespace: true, max: 500 }]} extra="说明这一批主机接入或任务变更的业务目的，便于跟踪整体进度和失败原因。"><Input /></Form.Item>
        <Form.Item name="taskIds" label="待审批任务" rules={[{ required: true, type: "array", min: 1, max: 100, message: "请选择 1–100 个任务" }]} extra="选择需要按顺序审批推进的任务，核对目标与变更内容；后续仍按审批策略执行。"><RecordSelect resource="tasks" mode="multiple" status="PENDING" unbatched maxCount={100} placeholder="按任务标题查找待审批候选"/></Form.Item>
        <Form.Item name="stopOnFailure" label="出现失败时停止后续任务" valuePropName="checked" extra="失败后阻止未开始任务继续执行，保留已完成变更与验证结果，不自动回滚。"><Switch /></Form.Item>
      </Form>
    </Modal>
  </div>;
}
