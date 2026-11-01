import {BusinessGroupCreateButton} from './BusinessGroupCreateButton';
import {AssetCreateSshFields} from './AssetSshFields';
import {HostWafSetup,HostNetworkPanel} from './HostNetworkPanel';
import {AssetListActions} from './AssetListActions';
import type {AssetActionMode} from './AssetListActions';
import {AssetActionDrawer} from './AssetActionDrawer';
import {RecordFormHost} from './RecordFormHost';
import {BusinessSelect} from './BusinessSelect';
import {RecordSelect} from './RecordSelect';
import {InlineRecordAction} from './InlineRecordAction';
import {wafEventTitle,wafAccessTitle} from './waf-replay';
import {WafAccessView} from './WafAccessView';
import {RecordFieldsTable} from './RecordFieldsTable';
import {WafInspectionView} from './WafInspectionView';
import {AssetInventoryView} from './AssetInventoryView';
import {ScanPanel} from './ScanPanel';
import {SecurityContext} from './SecurityContext';
import {RecordWorkflowEditor} from './RecordWorkflowEditor';
import {statusOptions} from './status-options';
import {businessFieldHelp} from './business-fields';
import {assetOSDisplay,assetOSFormValues,assetOSPayload} from './asset-os';
import {AssetOperatingSystemFields} from './AssetOperatingSystemFields';
import {WafRuleLibraryPanel} from './WafRuleLibraryPanel';
import {AgentInstallationPanel} from './AgentInstallationPanel';
import {paginationDefaults,readPageSize,pageWithinTotal} from './pagination';
import {LoginView} from "./LoginView";
import {Brand} from "./Brand";
import {DesignSystemPage} from "./DesignSystemPage";
import {OperationGuide} from "./OperationGuide";
import {themeConfig,applyThemeTokens} from "./theme";
import {displayStatus,displaySource,formatTime} from "./presentation";
import {AppstoreOutlined,ClusterOutlined,RadarChartOutlined,ControlOutlined,ToolOutlined,GlobalOutlined,BarChartOutlined,SettingOutlined,MenuFoldOutlined,MenuUnfoldOutlined,ReloadOutlined,FilterOutlined,DownOutlined,UpOutlined,BellOutlined,UploadOutlined,ReadOutlined} from '@ant-design/icons';
import {QueryControls,defaultFilters,readLocation,queryParams} from "./QueryControls";
import {DateField} from "./DateField";
import {TemplatePanel,TemplateDetails} from "./TemplatePanel";
import {RuleToolsPanel} from "./RuleToolsPanel";
import {DatabaseRulesPage} from './DatabaseRulesPanel';
import {StoragePanel} from "./StoragePanel";
import {ReportPanel} from "./ReportPanel";
import {dashboardDestination} from "./dashboard-navigation";
import {Dashboard} from "./Dashboard";
import {EvidenceView} from "./EvidenceView";
import {RecordSummary} from "./RecordSummary";
import {ModuleSection,StatusTag,SeverityTag,DetectionMatchTag} from "./ModuleSection";
import {AssetHistoryPanel} from "./AssetHistoryPanel";
import {CertificatePanel} from "./CertificatePanel";
import {CompletionPanel,ScopeEditor} from "./CompletionPanel";
import {CorrelationPanel} from "./CorrelationPanel";
import {RelatedTimeline} from "./RelatedTimeline";
import {AdvisoryPanel} from "./AdvisoryPanel";
import {GovernancePanel} from "./GovernancePanel";
import {WorkflowTools,WorkflowBatchPanel} from "./WorkflowTools";
import React, { useState, useEffect, useRef } from "react";
import { createRoot } from "react-dom/client";
import {
  ConfigProvider,
  Tooltip,
  Breadcrumb,
  Avatar,
  Popover,
  Layout,
  Menu,
  Button,
  Upload,
  Input,
  InputNumber,
  Select,
  Table,
  Tag,
  Alert,
  Drawer,
  Modal,
  Form,
  Switch,
  Space,
  Empty,
  Spin,
  Descriptions,
  Timeline,
  App as AntApp,
} from "antd";
import zhCN from "antd/locale/zh_CN";
import { api, useSession, parseObject } from "./api";
import "./style.css";
import "./module.css";
import { useViews } from "./views";
import { taskParameters } from "./tasks";
type Row = Record<string, any>;
const severity = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "UNRATED"];
const labels: Record<string, string> = {
  CRITICAL: "严重",
  HIGH: "高",
  MEDIUM: "中",
  LOW: "低",
  INFO: "信息",
  UNRATED: "未评级",
  INCIDENT: "事件",
  ADMIN: "管理员",
  ANALYST: "安全分析员",
  OPERATOR: "运维修复员",
  VIEWER: "只读人员",
  RISK: "风险",
  ALERT: "告警",
  OPEN: "待确认",
  CONFIRMED: "待处理",
  IN_PROGRESS: "处理中",
  VERIFYING: "待验证",
  CLOSED: "已关闭",
  ACCEPTED: "风险接受",
  FALSE_POSITIVE: "误报",
  PENDING: "待审批",
  APPROVED: "待执行",
  RUNNING: "执行中",
  RESOLVED: "已处理",
  UNKNOWN: "结果待确认",
  EXPIRED: "已过期",
  true: "验证通过",
  false: "验证未通过",
  SUCCEEDED: "验证通过",
  FAILED: "执行失败",
  REJECTED: "已拒绝",
  CANCELLED:"已取消",
  ROLLED_BACK:"已回滚",
  OBSERVE: "观察",
  BLOCK: "阻断",
};
const groups: [string, [string, string][]][] = [
  [
    "资产中心",
    [
      ["assets", "资产列表"],
      ["business", "业务分组"],
      ["enroll", "采集与接入"],
    ],
  ],
  [
    "安全中心",
    [
      ["findings", "全部发现"],
      ["risks", "风险管理"],
      ["alerts", "告警管理"],
      ["incidents", "事件调查"],
    ],
  ],
  [
    "策略中心",
    [
      ["rules", "检测规则"],
      ["baseline", "配置基线"],["data-security", "数据安全规则"],["rule-scope", "规则适用范围"],["rule-test", "规则样本验证"],
      ["detection", "检测任务"],["scans", "扫描计划"],
      ["sources", "漏洞数据源"],
      ["correlation", "关联检测"],["telemetry", "遥测记录"],
    ],
  ],
  [
    "修复中心",
    [
      ["tasks", "修复任务"],
      ["approvals", "待审批"],
      ["templates", "修复模板"],
      ["batches", "修复批次"],
    ],
  ],
  [
    "Web 防护",
    [
      ["sites", "站点管理"],["waf-events", "攻击记录"],
      ["policies", "防护策略"],["waf-rules", "防护规则库"],
      ["access", "访问日志"],
      ["nodes", "节点状态"],
      ["policy-test", "防护规则测试"],["certificates", "站点证书"],
    ],
  ],
  [
    "报告中心",
    [
      ["reports", "安全报告"],
      ["trends", "趋势分析"],
      ["exports", "导出记录"],
    ],
  ],
  [
    "系统管理",
    [
      ["users", "用户与权限"],["design-system","界面规范"],
      ["credentials", "凭据管理"],
      
      ["audit", "操作审计"],
      ["operations", "平台运维"],
      ["rollouts", "Agent灰度升级"],["webhook", "外部通知"],["deliveries", "通知投递"],["backup", "定期备份"],
        ["governance", "审批策略"],["retention", "数据保留"],["imports", "导入批次"],["notifications", "我的通知"],
    ],
  ],
];
const names = Object.fromEntries([
  ["overview", "工作台"],
  ["operation-guide", "操作指南"],
  ...groups.flatMap((g) => g[1]),
]);
const mapping: Record<string, string> = {
  nodes: "waf-nodes",
  detection: "evaluations",
  sources: "rules",
  findings: "discoveries",
  access: "waf-access",
  risks: "findings",
  alerts: "findings",
  baseline: "rules",
  approvals: "tasks",
  policies: "sites",
  business: "assets",
  enroll: "assets",
};
const inlineDetailModes=['edit','password','reject','verify','run','assign','status'];
const modulePages=["scans","waf-rules","enroll","operation-guide","data-security","rule-scope","rule-test","certificates","rollouts","webhook","deliveries","backup","correlation","telemetry","policy-test","sources","batches","governance","retention","imports","notifications","templates","reports"];
const supported = [
  "waf-nodes",
  "evaluations",
  "discoveries",
  "assets",
  "findings",
  "incidents",
  "rules",
  "tasks",
  "sites",
  "users",
  "audit",
  "waf-events",
  "waf-access",
];
function Application() {
  const { message } = AntApp.useApp();
  const session = useSession();
  const [page, setPage] = useState(readLocation().page);
  const [guideReturn,setGuideReturn] = useState('overview');
  const [rows, setRows] = useState<Row[]>([]);
  const [total, setTotal] = useState(0);
  const [overview, setOverview] = useState<Row>();
  const [ops, setOps] = useState<Row>();
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [q, setQ] = useState(readLocation().q);
  const [sev, setSev] = useState<string|undefined>(readLocation().severity);
  const [status, setStatus] = useState<string|undefined>(readLocation().status);
  const [number, setNumber] = useState(readLocation().number);
  const [pageSize,setPageSize] = useState(readLocation().pageSize);
  const [extraFilters,setExtraFilters]=useState(readLocation().extra);
  const [batchResults,setBatchResults]=useState<{id:string;ok:boolean;message:string}[]>([]);
  const [detail, setDetail] = useState<Row>();
  const [structuredField,setStructuredField]=useState<{title:string;value:unknown}>();
  const [modal, setModal] = useState("");
  const [listEditing,setListEditing]=useState(false);
  const [assetAction,setAssetAction]=useState<{record:Row;mode:AssetActionMode;version:number}>();
  const [busy, setBusy] = useState(false);
  const [form] = Form.useForm();
  const selectedTemplate = Form.useWatch("template", form);
  const selectedAsset = Form.useWatch("assetId", form);
  const selectedRuleKind = Form.useWatch("kind", form);
  const resource = mapping[page] || page;
  const statusValues=resource==='tasks'?['PENDING','APPROVED','RUNNING','VERIFYING','SUCCEEDED','FAILED','UNKNOWN','REJECTED','CANCELLED','EXPIRED','ROLLED_BACK']:resource==='incidents'?['OPEN','IN_PROGRESS','VERIFYING','CLOSED']:['findings','discoveries'].includes(resource)?page==='alerts'?['OPEN','IN_PROGRESS','RESOLVED','FALSE_POSITIVE']:page==='risks'?['OPEN','CONFIRMED','IN_PROGRESS','VERIFYING','CLOSED','ACCEPTED','FALSE_POSITIVE']:['OPEN','CONFIRMED','IN_PROGRESS','VERIFYING','CLOSED','RESOLVED','ACCEPTED','FALSE_POSITIVE']:[];
  const [user, setUser] = useState<Row>();
  const [detailResource, setDetailResource] = useState("");
  const [comments, setComments] = useState<Row[]>([]);
  const [attachments, setAttachments] = useState<Row[]>([]);
  const [versions, setVersions] = useState<Row[]>([]);
  const [uploading, setUploading] = useState(false);
  const [history, setHistory] = useState<Row[]>([]);
  const [note, setNote] = useState("");
  const [detailError, setDetailError] = useState("");
  const isAdmin = user?.role === "ADMIN";
  const saved = useViews();
  const [density, setDensity] = useState<"small" | "middle" | "large">("middle");
  const [navCollapsed,setNavCollapsed]=useState(false);
  const [advancedOpen,setAdvancedOpen]=useState(false);
  const pageRef=useRef(page);
  const advancedCount=Object.entries(extraFilters).filter(([key,value])=>value&&value!==(defaultFilters as any)[key]).length;
  useEffect(()=>{if(advancedCount)setAdvancedOpen(true)},[advancedCount]);
  const otherAdvancedCount=advancedCount-(extraFilters.business?1:0);
  const [hidden, setHidden] = useState<string[]>([]);
  const [selected, setSelected] = useState<React.Key[]>([]);
  const [batchError, setBatchError] = useState("");
  const requestVersion = useRef(0);
  const detailRequestVersion = useRef(0);
  const renderedDetailVersion = detailRequestVersion.current;
  const inlineFormTarget = useRef<HTMLDivElement>(null);
  async function bulkFindings(mode:"read"|"assign",owner?:string){
    setBusy(true);setBatchError("");const results:{id:string;ok:boolean;message:string}[]=[];
    try{for(const id of selected){try{if(mode==="read")await api('/workflows/findings/'+id+'/triage',{read:true},'PATCH');else await api('/findings/'+id,{owner},'PATCH');results.push({id:String(id),ok:true,message:'已保存'});}catch(e){results.push({id:String(id),ok:false,message:(e as Error).message});}}setSelected([]);await refresh();setBatchResults(results);if(results.every(row=>row.ok))message.success('所选发现已更新');}finally{setBusy(false);}
  }
  const activeGroup = groups.find(([, items]) =>
    items.some(([key]) => key === page),
  )?.[0];
  const [openGroups, setOpenGroups] = useState<string[]>(
    activeGroup ? [activeGroup] : [],
  );
  useEffect(
    () => setOpenGroups(previous=>activeGroup&&!previous.includes(activeGroup)?[...previous,activeGroup]:previous),
    [activeGroup],
  );
  useEffect(() => {
    if (session.token)
      api("/auth/me")
        .then(setUser)
        .catch((e) => setError(e.message));
    else {
      detailRequestVersion.current++;
      setUser(undefined);
      setRows([]);
      setOverview(undefined);
      setDetail(undefined);setAssetAction(undefined);setListEditing(false);
      setModal("");
      setComments([]);
      setAttachments([]);
      setHistory([]);
      setSelected([]);
    }
  }, [session.token]);
  function openAssetAction(record:Row,mode:AssetActionMode){
    const version=++detailRequestVersion.current;setDetail(undefined);setStructuredField(undefined);setModal("");setListEditing(false);setAssetAction({record,mode,version});
  }
  async function showDetail(r: Row, override?: string) {
    setAssetAction(undefined);setListEditing(false);
    const version = ++detailRequestVersion.current;
    setModal(current=>inlineDetailModes.includes(current)?"":current);
    const current = () => version === detailRequestVersion.current && session.token === useSession.getState().token;
    if (!override && ["evaluations", "waf-nodes", "waf-access"].includes(resource)) {
      setDetailResource(resource);
      setDetail(r);
      setComments([]);
      setHistory([]);
      setDetailError("");
      return;
    }
    const target =
      override ||
      (r.kind === "INCIDENT"
        ? "incidents"
        : resource === "discoveries" ||
            page === "overview" ||
            page === "reports"
          ? "findings"
          : resource);
    setDetailResource(target);
    setAttachments([]);
    setVersions([]);
    setComments([]);
    setHistory([]);
    setDetailError("");
    try {
      const updated = await api("/" + target + "/" + encodeURIComponent(r.id));
      if (!current()) return;
      setDetail(updated);
      if (["findings", "incidents", "tasks", "assets"].includes(target)) {
        const c = await api(`/${target}/${r.id}/comments`);
        if (current()) setComments(c.items || c);
        const files = await api(`/${target}/${r.id}/attachments`);
        if (current()) setAttachments(files.items);
      }
      if (["rules", "sites"].includes(target)) {
        const revisions = await api(`/${target}/${r.id}/versions`);
        if (current()) setVersions(revisions.items);
      }
      if (isAdmin) {
        const a = await api("/audit?resourceId=" + encodeURIComponent(r.id));
        if (current()) setHistory(a.items);
      }
    } catch (e) {
      if (current()) setDetailError((e as Error).message);
    }
  }
  function editDetail(record?:Row,target=detailResource) {
    const selected=record||detail;
    if(!selected)return;
    if(record){detailRequestVersion.current++;setAssetAction(undefined);setDetailResource(target);setDetail(record);}
    setListEditing(!!record);setError("");
    form.resetFields();
    const allowed: Record<string, string[]> = {
      assets: ["hostname", "os", "ip", "business", "owner", "tags"],
      rules: [
        "name",
        "kind",
        "severity",
        "enabled",
        "config",
        "intervalSeconds",
      ],
      sites: ["name", "hostname", "upstream", "mode", "enabled", "config"],
      users: ["name", "role"],
    };
    const v = Object.fromEntries(
      (allowed[target] || []).map((k) => [k, selected[k]]),
    );
    if (v.tags) v.tags = v.tags.join(",");
    if (v.config) v.config = JSON.stringify(v.config, null, 2);
    if(target==='assets')Object.assign(v,assetOSFormValues(selected));
    form.setFieldsValue(v);
    setModal("edit");
  }
  const opsRoutes: Record<string, string> = {
    business: "business-groups",
    trends: "trends",
    exports: "exports",
    credentials: "credentials",
    notifications: "notifications",
    operations: "health",
  };
  const navigate = (key: string) => {
    location.hash = key;
  };
  useEffect(() => {
    const handler = () => {
      const next=readLocation();
      if(pageRef.current!==next.page){requestVersion.current++;setRows([]);setTotal(0);setLoading(true);setAdvancedOpen(false);pageRef.current=next.page;}
      detailRequestVersion.current++;
      setPage(next.page);setQ(next.q);setSev(next.severity);setStatus(next.status);setNumber(next.number);setPageSize(next.pageSize);setExtraFilters(next.extra);
      setBatchResults([]);
      setModal(current=>inlineDetailModes.includes(current)?"":current);
      setDetail(undefined);setAssetAction(undefined);setListEditing(false);
      setStructuredField(undefined);
      setHidden([]);
      setSelected([]);
      setError("");
      setBatchError("");
      setOps(undefined);
    };
    addEventListener("hashchange", handler);
    return () => removeEventListener("hashchange", handler);
  }, []);
  useEffect(()=>{if(!session.token)return;const query=queryParams(q,sev,status,number,extraFilters,pageSize);if(page==='enroll'){const tab=new URLSearchParams(location.hash.split('?')[1]||'').get('tab');if(tab&&['connection','batch','installations','releases'].includes(tab))query.set('tab',tab)}window.history.replaceState(null,"",location.pathname+location.search+"#"+page+"?"+query.toString());},[session.token,page,q,sev,status,number,extraFilters,pageSize]);
  async function refresh() {
    if (pageRef.current !== page) return;
    if(modulePages.includes(page)){setLoading(false);return;}
    const version = ++requestVersion.current;
    const token = session.token;
    const current = () =>
      version === requestVersion.current &&
      token === useSession.getState().token && pageRef.current === page;
    setLoading(true);
    setError("");
    try {
      if (opsRoutes[page]) {
        const data = await api("/operations/" + opsRoutes[page]);
        if (current()) setOps(data);
      } else if (page === "overview" || page === "reports") {
        const data = await api("/overview");
        if (current()) setOverview(data);
      } else if (supported.includes(resource)) {
        const query = queryParams(q,sev,status,number,extraFilters,pageSize);
        if (sev) query.set("severity", sev);
        if (status) query.set("status", status);
        if (page === "risks" || page === "alerts")
          query.set("kind", page === "risks" ? "RISK" : "ALERT");
        if (page === "approvals") query.set("status", "PENDING");
        if (page === "baseline") query.set("kind", "BASELINE");
        if (page === "sources") query.set("kind", "VULNERABILITY");
        const data = await api("/" + resource + "?" + query);
        if (current()) {
          const validPage=pageWithinTotal(number,data.total,pageSize);
          setTotal(data.total);
          if(validPage!==number){setRows([]);setNumber(validPage);return;}
          setRows(data.items);
        }
      }
    } catch (e) {
      if (current()) setError((e as Error).message);
    } finally {
      if (current()) setLoading(false);
    }
  }

  useEffect(() => {
    setSelected([]);
    if (session.token) void refresh();
  }, [session.token, page, q, sev, status, number,extraFilters,pageSize]);
  async function action(path: string, body: unknown, method?: string) {
    const version=detailRequestVersion.current;
    setBusy(true);
    try {
      const result = await api(path, body, method);
      message.success("操作已保存");
      if(version===detailRequestVersion.current){setModal("");setDetail(undefined);setListEditing(false);}
      await refresh();
      return result;
    } catch (e) {
      if(version===detailRequestVersion.current)setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  }
  function openCreate() {
    detailRequestVersion.current++;setAssetAction(undefined);setDetail(undefined);setListEditing(false);
    form.resetFields();
    form.setFieldsValue({
      severity: "MEDIUM",
      intervalSeconds: null,
      kind: page === "sources" ? "VULNERABILITY" : "BASELINE",
      enabled: true,
      mode: "OBSERVE",
      config:
        page === "sources"
          ? '{"package":"example","affectedVersion":"1.0","advisory":"内部公告编号","os":"Linux"}'
          : resource === "rules"
            ? '{"path":"/etc/example.conf","mode":"0640"}'
            : "{}",
      template: "FILE_PERMISSION",
      permission: "0640",
    });
    setModal("create");
  }
  async function submit() {
    try {
      const values = await form.validateFields();
      for (const key of ['dueAt','expiresAt']) if (values[key]) values[key]=new Date(values[key]).toISOString();
      if(modal==='bulk-assign'){await bulkFindings('assign',values.owner);setModal('');return;}
      if (modal === "assign") {
        const data = Object.fromEntries(
          Object.entries(values).filter(([, v]) => v !== "" && v !== undefined),
        );
        await action(`/${detailResource}/${detail!.id}`, data, "PATCH");
        return;
      }
      if (modal === "run") {
        await action(
          `/rules/${detail!.id}/run`,
          values.assetId ? { assetId: values.assetId } : {},
        );
        return;
      }
      if (modal === "save-view") {
        saved.save({ name: values.name, userId:user?.id, page, q, severity: sev, status,extra:extraFilters,number,pageSize,density,hidden });
        setModal("");
        return;
      }
      if (modal === "password") {
        await action(`/users/${detail!.id}`, values, "PATCH");
        return;
      }
      if (modal === "import") {
        const items = JSON.parse(values.items);
        if (!Array.isArray(items)) throw new Error("导入内容必须是数组");
        await action("/findings/import", { items });
        return;
      }
      if (modal === "reject") {
        await action(`/tasks/${detail!.id}/reject`, values);
        return;
      }
      if (modal === "verify") {
        await action(
          `/${detailResource === "findings" ? "findings" : "tasks"}/${detail!.id}/verify`,
          { ...values, resolved: values.resolved === "true" },
        );
        return;
      }
      if (modal === "status") {
        await action(
          `/${detailResource}/${detail!.id}`,
          Object.fromEntries(
            Object.entries(values).filter(
              ([k, v]) =>
                v !== undefined &&
                v !== "" &&
                (detailResource === "findings" || k !== "reason"),
            ),
          ),
          "PATCH",
        );
        return;
      }
      const data = { ...values };
      for (const key of Object.keys(data))
        if (data[key] === "" || data[key] === null || data[key] === undefined)
          delete data[key];
      if (modal === "edit" && editorResource === "assets" && Object.hasOwn(values,"business") && !values.business) data.business = null;
      if (editorResource === "rules")
        data.intervalSeconds =
          data.kind === "VULNERABILITY"
            ? (values.intervalSeconds ?? null)
            : null;
      if (data.config) data.config = parseObject(data.config);
      if (editorResource === "tasks") {
        data.parameters = taskParameters(data);
        delete data.path;
        delete data.permission;
        delete data.configKey;
        delete data.expectedValue;
        delete data.value;
      }
      if (editorResource === "assets") {Object.assign(data,assetOSPayload(values));delete data.osChoice;delete data.configureSsh;if(!values.configureSsh||data.os!=='linux')delete data.sshAccess;}
      if (editorResource === "assets")
        data.tags = (data.tags || "")
          .split(",")
          .map((v: string) => v.trim())
          .filter(Boolean);
      if (editorResource === "incidents")
        data.findingIds = data.findingIds || [];
      await action(
        "/" + (modal === "edit" ? detailResource + "/" + detail!.id : resource),
        data,
        modal === "edit" ? "PATCH" : "POST",
      );
    } catch (e) {
      if (e instanceof Error) setError(e.message);
    }
  }
  const editorResource = modal === "edit" ? detailResource : resource;
  const field = (
    name: string,
    label: string,
    required = true,
    textarea = false,
  ) => (
    <Form.Item
      name={name}
      label={label}
      extra={businessFieldHelp(name)}
      rules={[{ required, message: `请填写${label}` }]}
    >
      {name==='business'?<BusinessSelect onBusyChange={setBusy} canCreate={editorResource!=='assets'&&!!user&&['ADMIN','ANALYST'].includes(user.role)&&(user.role==='ADMIN'||user.dataScope?.restricted!==true)}/>:name==='assetId'?<RecordSelect resource="assets" allowArchived={false}/>:name==='findingId'?<RecordSelect resource="findings" kind="RISK" assetId={selectedAsset}/>:name==='findingIds'?<RecordSelect resource="findings" mode="multiple" maxCount={100}/>:textarea ? <Input.TextArea rows={4} /> : ['dueAt','expiresAt'].includes(name) ? <DateField showTime/> : <Input />}
    </Form.Item>
  );
  const select = (name: string, label: string, values: string[]) => (
    <Form.Item name={name} label={label} extra={businessFieldHelp(name)} rules={[{ required: true }]}>
      <Select
        options={values.map((value) => ({
          value,
          label: labels[value] || value,
        }))}
      />
    </Form.Item>
  );
  if (!session.token)return <LoginView busy={busy} error={error} onSubmit={async values=>{setBusy(true);setError('');try{const data=await api('/auth/login',values);session.setToken(data.token)}catch(e){setError((e as Error).message)}finally{setBusy(false)}}}/>;
  if (page==='operation-guide')return <OperationGuide onReturn={()=>navigate(guideReturn)}/>;
  const baseColumns = [
    {
      title: resource==="waf-events"?"攻击记录":resource==="waf-access"?"访问记录":"名称 / 标题",
      key: "title",
      render: (_: unknown, r: Row) => (
        <Button className="record-title-link" type="link" onClick={() => void showDetail(r)}>
          {resource==='waf-events'?wafEventTitle(r):resource==='waf-access'?wafAccessTitle(r):r.title ||
            r.ruleName ||
            r.name ||
            r.hostname ||
            r.email ||
            r.action ||
            r.path ||
            r.id}
        </Button>
      ),
    },
    {
      title: "类型",
      dataIndex: "kind",
      render: (v: string) => labels[v] || v || "—",
    },
    {
      title: "严重程度",
      dataIndex: "severity",
      render: (value:string)=>value?<SeverityTag value={value}/>:"—",
    },
    {
      title: "状态",
      key: "status",
      render: (_:unknown,row:Row)=>{
        const value=row.status||row.mode||(typeof row.enabled==='boolean'?(row.enabled?'ENABLED':'DISABLED'):row.role);
        if(!value)return "—";
        const label=row.status==='FAILED'&&row.verification?.resolved===false?'独立复测未通过':row.role&&!row.status&&!row.mode?labels[row.role]||row.role:undefined;
        return <StatusTag value={value} label={label}/>;
      },
    },
    {
      title: "关联 / 来源",
      key: "source",
      render: (_: unknown, r: Row) =>
        r.assetHostname ||
        (r.source ? displaySource(r.source) : undefined) ||
        r.business ||
        r.hostname ||
        (r.assetId ? "已关联资产" : "—"),
    },
    {
      title: "最近更新（本地时区）",
      key: "date",
      render: (_: unknown, r: Row) =>
        r.updatedAt || r.lastSeen || r.createdAt
          ? <span className="record-cell-time">{formatTime(r.updatedAt || r.lastSeen || r.createdAt)}</span>
          : "—",
    },
  ];
  const textColumn = (title: string, dataIndex: string) => ({
    title,
    dataIndex,
    render: (v: any) =>
      v === undefined || v === null
        ? "—"
        : typeof v === "object"
          ? <Button type="link" className="record-title-link" onClick={()=>setStructuredField({title,value:v})}>查看字段明细</Button>
          : /(?:At|timestamp|lastSeen)$/.test(dataIndex)
            ? <span className="record-cell-time">{formatTime(v)}</span>
            : String(v),
  });
  const extra: Record<string, any[]> = {
    "waf-nodes": [
      textColumn("版本", "version"),
      {
        title: "最近状态",
        render: (_: unknown, r: Row) =>
          Date.now() - Date.parse(r.lastSeen) <= 90000
            ? <StatusTag value="ONLINE" label="90秒内收到心跳"/>
            : <StatusTag value="STALE" label="数据过期 / 节点离线"/>,
      },
      textColumn("已同步站点版本", "sites"),
      textColumn("丢弃事件", "droppedEvents"),
      textColumn("最后上报", "lastSeen"),
    ],
    evaluations: [
      textColumn("规则名称", "ruleName"),
      baseColumns[1],
      baseColumns[3],
      textColumn("资产", "assetId"),
      {
        title: "检测结论",
        dataIndex: "matched",
        render: (v:boolean,row:Row)=><DetectionMatchTag matched={v} status={row.status}/>,
      },
    ],
    assets: [
      {title:"操作系统",dataIndex:"os",render:(_:unknown,row:Row)=>assetOSDisplay(row).label},
      textColumn("IP 地址", "ip"),
      textColumn("所属业务", "business"),
      textColumn("负责人", "owner"),
    ],
    rules: [
      baseColumns[1],
      baseColumns[2],
      baseColumns[3],
      textColumn("版本", "version"),
    ],
    sites: [
      textColumn("域名", "hostname"),
      textColumn("上游服务", "upstream"),
      baseColumns[3],
      textColumn("版本", "version"),
    ],
    tasks: [
      {
        title: "目标资产",
        render: (_: unknown, r: Row) =>
          r.assetHostname || (r.assetId ? "已关联资产" : "未关联"),
      },
      textColumn("修复模板", "template"),
      baseColumns[3],
    ],
    users: [
      textColumn("邮箱", "email"),
      {
        title: "角色",
        dataIndex: "role",
        render: (v: string) => labels[v] || v,
      },
      {
        title: "账户状态",
        dataIndex: "disabled",
        render: (v:boolean)=><StatusTag value={v?"DISABLED":"ENABLED"} label={v?"已停用":"正常"}/>,
      },
    ],
    audit: [
      textColumn("操作者", "actor"),
      textColumn("资源", "resource"),
      textColumn("资源 ID", "resourceId"),
    ],
    "waf-access": [textColumn("节点","nodeId"),textColumn("站点","siteId"),textColumn("方法","method"),textColumn("状态码","status"),textColumn("时间","timestamp"),textColumn("耗时(微秒)","durationMicros")],
    "waf-events": [
      textColumn("请求方法", "method"),
      textColumn("路径", "path"),
      {title:"防护动作",dataIndex:"action",render:(value:string)=><StatusTag value={value}/>},
      textColumn("规则", "ruleId"),
      textColumn("客户端 IP", "remoteIp"),
    ],
  };
  const columns = [
    baseColumns[0],
    ...(extra[resource] || baseColumns.slice(1, 5)),
    baseColumns[5],
    ...(resource==='assets'&&user&&(['ADMIN','ANALYST'].includes(user.role)||user.dataScope?.canReadEvidence!==false)?[{title:'操作',key:'actions',width:280,render:(_:unknown,row:Row)=><AssetListActions record={row} role={user.role} evidenceAllowed={user.role==='ADMIN'||user.dataScope?.canReadEvidence!==false} onEdit={()=>editDetail(row,'assets')} onOpen={mode=>openAssetAction(row,mode)}/>}]:['rules','sites','users'].includes(resource)&&(resource==='rules'?['ADMIN','ANALYST'].includes(user?.role||''):isAdmin)?[{title:'操作',key:'actions',width:120,render:(_:unknown,row:Row)=><Button onClick={()=>editDetail(row,resource)}>编辑配置</Button>}]:[]),
  ];
  return (
    <Layout style={{ minHeight: "100dvh" }}>
      <Layout.Sider className="sidebar" theme="dark" width={232} collapsedWidth={72} collapsed={navCollapsed} breakpoint="lg" onBreakpoint={setNavCollapsed}>
        <Button type="text" className="brand-home" aria-label="Self Guard 返回工作台" onClick={()=>navigate('overview')}><Brand compact={navCollapsed} light/></Button>
        <Menu
          mode="inline"
          theme="dark"
          aria-label="主导航"
          selectedKeys={[page]}
          openKeys={navCollapsed?undefined:openGroups}
          onOpenChange={keys=>{if(!navCollapsed)setOpenGroups(keys)}}
          onClick={({ key }) => navigate(key)}
          items={[
            { key: "overview", label: "工作台", icon:<AppstoreOutlined/> },
            ...groups.map(([name, items]) => ({
              key: name,
              label: name,
              icon: ({'资产中心':<ClusterOutlined/>,'安全中心':<RadarChartOutlined/>,'策略中心':<ControlOutlined/>,'修复中心':<ToolOutlined/>,'Web 防护':<GlobalOutlined/>,'报告中心':<BarChartOutlined/>,'系统管理':<SettingOutlined/>} as Record<string,React.ReactNode>)[name],
              children: items.map(([key, label]) => ({ key, label })),
            })),
          ]}
        />
        <div className="sidebar-footer"><Tooltip title={navCollapsed?'展开导航':'收起导航'} placement="right"><Button type="text" aria-label={navCollapsed?'展开导航':'收起导航'} icon={navCollapsed?<MenuUnfoldOutlined/>:<MenuFoldOutlined/>} onClick={()=>setNavCollapsed(!navCollapsed)}/></Tooltip>{!navCollapsed&&<span>Self Guard · 安全运营</span>}</div>
      </Layout.Sider>
      <Layout>
        <Layout.Header className="top">
          <Breadcrumb items={[{title:'安全运营'},{title:activeGroup||names[page]||'工作台'},...(activeGroup?[{title:names[page]}]:[])]}/>
          <Space size={16} className="top-actions">
            <Button type="text" className="guide-entry" aria-label="操作指南" icon={<ReadOutlined/>} onClick={()=>{setGuideReturn(location.hash.slice(1)||page);navigate('operation-guide')}}>操作指南</Button>
            <Tooltip title="我的通知"><Button type="text" aria-label="我的通知" icon={<BellOutlined/>} onClick={()=>navigate('notifications')}/></Tooltip>
            <Avatar size={30} className="account-avatar">{user?.name?.slice(0,1)||'用'}</Avatar>
            <span className="account-name">
              {user?.name} · {labels[user?.role] || user?.role}
            </span>
            <Button
              onClick={async () => {
                try {
                  await api("/auth/logout", {});
                } catch {
                } finally {
                  session.setToken("");
                }
              }}
            >
              退出登录
            </Button>
          </Space>
        </Layout.Header>
        <Layout.Content className="page">
          <div className="heading">
            <div>
              <h1>{names[page] || "工作台"}</h1>
              <span className="page-description">{({overview:'关注风险变化，推进每一项待办。',findings:'统一查看漏洞、主机与 Web 防护发现，按优先级开展处置。',risks:'确认影响范围、分派负责人，并跟踪修复与验证结果。',alerts:'研判主机与 Web 防护告警，关联风险并组织事件调查。',incidents:'汇总相关发现、影响资产与处置任务，组织调查并记录结论。','waf-events':'查看 HTTP/HTTPS 请求的 WAF 命中与处置记录；攻击特征命中不等于已确认应用漏洞。',rules:'管理已创建的主机、软件、日志与配置检测规则；WAF规则在Web防护中维护。',baseline:'查看主机与数据库配置检查规则，跟踪实际状态与基线要求的偏差。','data-security':'按基础模板创建数据库行为和配置检测规则，结果进入风险管理或告警管理。','rule-scope':'设置检测规则适用的资产、业务、标签与基线豁免。','rule-test':'提供离线样本核对检测逻辑，不修改适用范围，也不发起真实扫描。',assets:'掌握主机清单、业务归属与采集状态。',tasks:'跟踪审批、执行、独立复验与回滚的完整过程。',approvals:'核对目标、变更内容与恢复方案后进行审批。',sites:'管理受保护站点、上游服务与当前防护策略。','design-system':'一套共同的视觉与交互规则，贯穿平台的每个页面。'} as Record<string,string>)[page]||`查看和管理${names[page]||'平台记录'}。`}</span>
            </div>
            <Space>
              {page!=="design-system"&&!modulePages.includes(page)&&<Button icon={<ReloadOutlined/>} onClick={() => void refresh()}>刷新</Button>}
              {page==="sites"&&isAdmin&&<HostWafSetup/>}
              {!modulePages.includes(page)&&['assets','findings','incidents','rules','tasks','sites','discoveries'].includes(resource)&&<Button onClick={async()=>{try{const query=queryParams(q,sev,status,number,extraFilters,pageSize);query.set('resource',resource);if(page==='risks'||page==='alerts')query.set('kind',page==='risks'?'RISK':'ALERT');if(page==='approvals')query.set('status','PENDING');if(page==='baseline')query.set('kind','BASELINE');const result=await api('/workflows/export?'+query);const url=URL.createObjectURL(new Blob([JSON.stringify(result,null,2)],{type:'application/json'}));const a=document.createElement('a');a.href=url;a.download='selfguard-'+resource+'.json';a.click();setTimeout(()=>URL.revokeObjectURL(url),1000);if(result.truncated)message.warning('已导出前10000条，文件中已标记截断');}catch(e){setError((e as Error).message)}}}>导出筛选结果</Button>}
              {!modulePages.includes(page)&&(["assets", "incidents", "rules", "tasks", "sites"].includes(
                resource,
              ) ||
                (resource === "users" && isAdmin)) && (
                <Button type="primary" onClick={openCreate}>
                  {({assets:'添加资产',incidents:'创建调查',rules:'创建规则',tasks:'创建任务',sites:'添加站点',users:'添加用户'} as Record<string,string>)[resource]||'新建'}
                </Button>
              )}
              {!modulePages.includes(page)&&["findings", "discoveries"].includes(resource) && (
                <Button
                  type="primary"
                  onClick={() => {
                    form.resetFields();
                    setModal("import");
                  }}
                >
                  导入发现
                </Button>
              )}
            </Space>
          </div>
          {error && (
            <Alert
              style={{ marginBottom: 16 }}
              type="error"
              showIcon
              message={error}
              closable
              onClose={() => setError("")}
            />
          )}
          <div className={modulePages.includes(page)?"module-page":undefined}>
          {page==="waf-rules"?<WafRuleLibraryPanel/>:page==="enroll"?<AgentInstallationPanel/>:page==="design-system"?<DesignSystemPage/>:page==="data-security"?<DatabaseRulesPage/>:["rule-scope","rule-test"].includes(page)?<RuleToolsPanel key={page} mode={page==="rule-scope"?"scope":"test"}/>: page==="certificates"?<CertificatePanel/>:["rollouts","webhook","deliveries","backup"].includes(page)?<CompletionPanel key={page} section={page}/>: ["correlation","telemetry","policy-test"].includes(page)?<CorrelationPanel key={page} mode={page==="correlation"?"rules":page as "telemetry"|"policy-test"}/>:page==="sources"?<AdvisoryPanel/>:page==="scans"?<ScanPanel/>:page==="batches"?<WorkflowBatchPanel/>:["governance","retention","imports","notifications"].includes(page)?<div className="module-stack"><GovernancePanel key={page} section={page}/>{page==="retention"&&<StoragePanel/>}</div>:opsRoutes[page] ? (
            <Spin spinning={loading}>
              <ModuleSection extra={page==='business'&&!!user&&['ADMIN','ANALYST'].includes(user.role)&&!user.dataScope?.restricted?<BusinessGroupCreateButton onCreated={()=>void refresh()}/>:undefined} title={({business:'业务分组概览',trends:'发现与处置趋势',exports:'历史导出记录',credentials:'组件凭据状态',operations:'平台运行状态'} as Record<string,string>)[page]||names[page]}>
                {ops ? (
                  <>
                    {page === "business" && (
                      <Table
                        scroll={{x:460}}
                        locale={{emptyText:"暂无授权业务分组"}}
                        rowKey="business"
                        dataSource={ops.items}
                        columns={[
                          textColumn("业务分组", "business"),
                          textColumn("全部资产数量", "assetCount"),
                        ]}
                        pagination={paginationDefaults}
                      />
                    )}{" "}
                    {page === "trends" && (
                      <>
                        <p>
                          最近 30 天 · {ops.timezone}。{ops.basis}
                        </p>
                        <Table
                          scroll={{x:860}}
                          rowKey="day"
                          dataSource={ops.items}
                          columns={[
                            textColumn("日期", "day"),
                            textColumn("新建发现", "findings"),
                            textColumn("上述发现当前已关闭 / 已解决", "closed"),
                            textColumn("新建修复任务", "tasks"),
                            textColumn("已接收 WAF 事件", "events"),
                          ]}
                          pagination={paginationDefaults}
                        />
                      </>
                    )}
                    {page === "exports" && (
                      <>
                        <p>最近 {ops.limit} 条审计导出记录。</p>
                        <Table
                          scroll={{x:760}}
                          locale={{emptyText:"暂无记录"}}
                          rowKey="id"
                          dataSource={ops.items}
                          columns={[
                            textColumn("导出人", "actor"),
                            textColumn("数据范围", "resource"),
                            textColumn("生成时间", "createdAt"),
                          ]}
                          pagination={paginationDefaults}
                        />
                      </>
                    )}
                    {page === "credentials" && (
                      <>
                        <p>
                          注册凭据：
                          {ops.components?.enrollmentConfigured
                            ? "已配置"
                            : "未配置"}{" "}
                          · WAF 凭据：
                          {ops.components?.wafConfigured ? "已配置" : "未配置"}
                          。仅展示配置状态，不展示密钥。
                        </p>
                        <Table
                          scroll={{x:760}}
                          locale={{emptyText:"暂无记录"}}
                          rowKey="id"
                          dataSource={ops.items}
                          columns={[
                            textColumn("主机", "hostname"),
                            {
                              title: "Agent 凭据",
                              dataIndex: "enrolled",
                              render: (v:boolean)=><StatusTag value={v?"ENABLED":"DISABLED"} label={v?"有效":"未注册 / 已撤销"}/>,
                            },
                            textColumn("更新时间", "updatedAt"),
                            {
                              title: "操作",
                              render: (_: unknown, r: Row) =>
                                isAdmin && r.enrolled ? (
                                  <Button
                                    danger
                                    onClick={() =>
                                      Modal.confirm({className:"module-modal",
                                        title: "撤销 Agent 凭据",
                                        content: `${r.hostname} 将无法继续上报和领取任务，需重新注册。`,
                                        onOk: () =>
                                          action(
                                            `/operations/assets/${r.id}/revoke`,
                                            {},
                                          ),
                                      })
                                    }
                                  >
                                    撤销凭据
                                  </Button>
                                ) : null,
                            },
                          ]}
                          pagination={paginationDefaults}
                        />
                      </>
                    )}
                    {page === "notifications" && (
                      <>
                        <Alert
                          type="info"
                          message="站内待办汇总"
                          description="此页面依据实际任务与风险计算；尚未配置外部消息发送渠道。"
                        />
                        <div className="metrics" style={{ marginTop: 16 }}>
                          {[
                            ["pendingApprovals", "待审批任务", "approvals"],
                            ["failedTasks", "失败 / 结果待确认", "tasks"],
                            ["criticalRisks", "严重未关闭风险", "risks"],
                          ].map(([key, label, target]) => (
                            <Button
                              key={key}
                              style={{ height: 80 }}
                              onClick={() => navigate(target)}
                            >
                              {label}：{ops[key]}
                            </Button>
                          ))}
                        </div>
                        <small>检查时间：{ops.checkedAt}</small>
                      </>
                    )}
                    {page === "operations" && (
                      <Descriptions
                        bordered
                        column={1}
                        items={[
                          {
                            key: "database",
                            label: "数据库连通性",
                            children: ops.database?.ok
                              ? "检查通过"
                              : "检查未通过",
                          },
                          {
                            key: "latency",
                            label: "数据库响应",
                            children: `${ops.database?.latencyMs} ms`,
                          },
                          {
                            key: "uptime",
                            label: "API 进程运行时间",
                            children: `${ops.process?.uptimeSeconds} 秒`,
                          },
                          {
                            key: "version",
                            label: "Node 版本",
                            children: ops.process?.nodeVersion,
                          },
                          {
                            key: "checked",
                            label: "检查时间",
                            children: ops.checkedAt,
                          },
                        ]}
                      />
                    )}
                  </>
                ) : (
                  !loading && (
                    <Empty
                      description={
                        error ? "读取失败，请查看错误说明" : "暂无数据"
                      }
                    />
                  )
                )}
              </ModuleSection>
            </Spin>
          ) : page === "reports" ? <ReportPanel /> : page === "overview" ? (
            <Spin spinning={loading}>
              {overview ? (
                <Dashboard overview={overview} onOpen={(r,target)=>navigate(target==='tasks'?'tasks':target==='incidents'?'incidents':r.kind==='ALERT'?'alerts':r.kind==='RISK'?'risks':'findings')} onMetric={group=>navigate(dashboardDestination(group))}/>
              ) : (
                !loading && <Empty description="尚未取得概览数据，请重试" />
              )}
            </Spin>
          ) : supported.includes(resource) ? (
            <div className="panel data-panel">
              {page === "detection" && (
                <Alert
                  style={{ marginBottom: 16 }}
                  type="info"
                  message="真实检测执行记录"
                  description="手动运行当前支持软件包版本精确匹配；基线、日志和文件完整性由 Agent 执行。未产生记录不等同于已验证安全。"
                />
              )}
              {page === "sources" && (
                <p>
                  当前维护人工录入的漏洞公告规则及精确版本条件；尚未配置外部公告自动同步。
                </p>
              )}
              <div className="list-controls">
              <div className="query-primary">
                <Input.Search
                  style={{ width: 280 }}
                  placeholder="搜索标题、名称或主机"
                  value={q}
                  onChange={(e) => {setQ(e.target.value);setNumber(1);}}
                  allowClear
                  onSearch={(v) => {
                    setQ(v);
                    setNumber(1);
                  }}
                />
                {['findings','incidents','rules','discoveries'].includes(resource)&&(<Select
                  allowClear
                  placeholder="严重程度"
                  aria-label="严重程度筛选"
                  style={{ width: 140 }}
                  value={sev}
                  onChange={(v) => {
                    setSev(v);
                    setNumber(1);
                  }}
                  options={severity.map((value) => ({
                    value,
                    label: labels[value],
                  }))}
                />)}
                {statusValues.length>0&&<Select allowClear showSearch aria-label="处置状态筛选" placeholder="处置状态" style={{width:150}} value={status} onChange={value=>{setStatus(value);setNumber(1)}} options={[...new Set([...statusValues,...(status?[status]:[])])].map(value=>({value,label:displayStatus(value)}))}/>}
                <Button className="advanced-trigger" icon={<FilterOutlined/>} aria-expanded={advancedOpen} onClick={()=>setAdvancedOpen(!advancedOpen)}>高级筛选{advancedCount>0?` · ${advancedCount}`:''}{advancedOpen?<UpOutlined/>:<DownOutlined/>}</Button>

              </div>
              {advancedOpen&&<div className="advanced-query"><div className="advanced-query-header"><span>按创建日期、业务、负责人或资产组合筛选</span>                <Button
                  onClick={() => {
                    setQ("");
                    setSev(undefined);
                    setStatus(undefined);setExtraFilters(defaultFilters);
                    setNumber(1);
                  }}
                >
                  清空筛选
                </Button></div><QueryControls resource={resource} value={extraFilters} onChange={value=>{setExtraFilters(value);setNumber(1);}}/></div>}
              {(q||sev||status||advancedCount>0)&&<div className="active-filters"><span>已应用</span>{q&&<Tag closable onClose={()=>{setQ('');setNumber(1)}}>搜索：{q}</Tag>}{sev&&<Tag closable onClose={()=>{setSev(undefined);setNumber(1)}}>{labels[sev]}</Tag>}{status&&<Tag closable onClose={()=>{setStatus(undefined);setNumber(1)}}>{displayStatus(status)}</Tag>}{extraFilters.business&&<Tag>业务：{extraFilters.business}</Tag>}{otherAdvancedCount>0&&<span>其他条件 {otherAdvancedCount} 项</span>}<Button type="link" size="small" onClick={()=>{setQ('');setSev(undefined);setStatus(undefined);setExtraFilters(defaultFilters);setNumber(1)}}>清空条件</Button></div>}
              </div>
              <div className="table-toolbar"><span className="result-count">共<strong>{total}</strong>条记录</span><div className="table-tools">
                <Select
                  placeholder="已保存视图"
                  aria-label="已保存视图"
                  style={{ width: 180 }}
                  value={undefined}
                  options={saved.views
                    .filter((v) => v.page === page&&!!user?.id&&v.userId===user.id)
                    .map((v) => ({ value: v.name, label: v.name }))}
                  onChange={(name) => {
                    const v = saved.views.find((v) => v.name === name&&v.userId===user?.id);
                    if (v) {
                      setQ(v.q);
                      setSev(v.severity);
                      setStatus(v.status);setExtraFilters(v.extra||defaultFilters);setDensity(v.density||"middle");setHidden(v.hidden||[]);
                      setNumber(v.number||1);setPageSize(readPageSize(v.pageSize));
                    }
                  }}
                />
                <Button
                  onClick={() => {
                    form.resetFields();
                    setModal("save-view");
                  }}
                >
                  保存当前视图
                </Button>
                <Popover trigger="click" placement="bottomRight" title="显示设置" content={<div className="table-display-options"><label>表格密度<Select
                  aria-label="表格密度"
                  value={density}
                  onChange={setDensity}
                  options={[
                    { value: "small", label: "紧凑" },
                    { value: "middle", label: "标准" },
                    { value: "large", label: "宽松" },
                  ]}
                /></label>
                <label>隐藏列<Select
                  mode="multiple"
                  placeholder="隐藏列"
                  aria-label="隐藏列"
                  style={{ minWidth: 160, maxWidth: 320 }}
                  value={hidden}
                  onChange={setHidden}
                  options={columns
                    .slice(1)
                    .map((c) => ({ value: c.title, label: c.title }))}
                /></label>
</div>}><Button icon={<SettingOutlined/>}>显示设置</Button></Popover>
                <Button type="text" onClick={async()=>{try{await navigator.clipboard.writeText(location.href);message.success('当前筛选链接已复制')}catch{setError('无法复制链接，请从地址栏复制当前筛选地址')}}}>复制筛选链接</Button>
              </div></div>
              {selected.length > 0 && ["rules","sites"].includes(resource) && (
                <Space wrap className="bulk-actions">
                  <span>已选择本页 {selected.length} 项</span>
                  {[true, false].map((enabled) => (
                    <Button
                      key={String(enabled)}
                      loading={busy}
                      onClick={() =>
                        Modal.confirm({className:"module-modal",
                          title: `${enabled ? "启用" : "停用"}所选 ${selected.length} 项`,
                          content: "仅处理当前选择的记录，每项结果独立记录。",
                          onOk: async () => {
                            setBusy(true);
                            const failures: string[] = [];
                            for (const id of selected) {
                              try {
                                await api(
                                  `/${resource}/${id}`,
                                  { enabled },
                                  "PATCH",
                                );
                              } catch (e) {
                                failures.push(`${id}: ${(e as Error).message}`);
                              }
                            }
                            setBusy(false);
                            setSelected([]);
                            await refresh();
                            setBatchError(failures.join("；"));
                            if (!failures.length)
                              message.success("所选记录已更新");
                          },
                        })
                      }
                    >
                      {enabled ? "批量启用" : "批量停用"}
                    </Button>
                  ))}
                </Space>
              )}
              {selected.length>0&&resource==='findings'&&['ADMIN','ANALYST'].includes(user?.role)&&<Space wrap className="bulk-actions"><span>已选择本页 {selected.length} 条发现</span><Button loading={busy} onClick={()=>void bulkFindings('read')}>批量标记已读</Button><Button onClick={()=>{form.resetFields();setModal('bulk-assign');}}>批量分派负责人</Button></Space>}
              {batchResults.length>0&&<Alert type={batchResults.some(row=>!row.ok)?'warning':'success'} message={'批量处理结果：成功 '+batchResults.filter(row=>row.ok).length+'，失败 '+batchResults.filter(row=>!row.ok).length} description={<ul>{batchResults.map(row=><li key={row.id}>{row.id}：{row.ok?'成功':'失败'} · {row.message}</li>)}</ul>} closable onClose={()=>setBatchResults([])} style={{marginBottom:12}}/>}
              {batchError && (
                <Alert
                  type="error"
                  message="部分操作失败"
                  description={batchError}
                />
              )}
              <Table
                rowKey="id"
                size={density}
                loading={loading}
                columns={columns.filter((c) => !hidden.includes(c.title))}
                rowSelection={
                  ["rules", "sites", "findings"].includes(resource)
                    ? { selectedRowKeys: selected, onChange: setSelected }
                    : undefined
                }
                dataSource={error ? [] : rows}
                scroll={{ x: 900 }}
                locale={{
                  emptyText: error
                    ? "查询失败，请查看错误并重试"
                    : "暂无记录。可创建记录或接入采集组件。",
                }}
                pagination={{
                  ...paginationDefaults,
                  current: number,
                  pageSize,
                  total,
                  onChange: (next,size)=>{setNumber(size===pageSize?next:1);setPageSize(size);},
                  showTotal: (n) => `共 ${n} 条`,
                }}
              />
            </div>
          ) : page === "templates" ? <TemplatePanel /> : (
            <div className="panel">
              <Alert
                type="info"
                showIcon
                message="此能力尚未接入管理接口"
                description="当前版本不提供此页面的运行数据或操作。请查看实施记录中的功能边界。"
              />
            </div>
          )}
          </div>
          {assetAction&&<AssetActionDrawer key={assetAction.record.id+assetAction.mode} {...assetAction} role={user?.role} onModeChange={mode=>openAssetAction(assetAction.record,mode)} onClose={()=>{detailRequestVersion.current++;setAssetAction(undefined)}} onChanged={()=>{if(assetAction.version!==detailRequestVersion.current)return;setAssetAction(undefined);void refresh();}}/>}
          {modal!=="edit"&&!structuredField&&<Drawer
            open={!!detail}
            width="min(860px, calc(100vw - 24px))"
            className="record-drawer"
            title={
              detailResource==='waf-events'&&detail?wafEventTitle(detail):detailResource==='waf-access'&&detail?wafAccessTitle(detail):detail?.title || detail?.name || detail?.hostname || "记录详情"
            }
            onClose={() => {detailRequestVersion.current++;setModal(current=>inlineDetailModes.includes(current)?"":current);setDetail(undefined)}}
          >
            {detail && (
              <>
                <RecordSummary record={detail} resource={detailResource}/>
 <SecurityContext key={"context"+detailResource+detail.id} record={detail} resource={detailResource} onOpen={(record,target)=>void showDetail(record,target)}/>
 <RecordWorkflowEditor key={detailResource+detail.id} record={detail} resource={detailResource} canEdit={["ADMIN","ANALYST"].includes(user?.role||"")} onChanged={updated=>{if(renderedDetailVersion!==detailRequestVersion.current)return;setDetail({...detail,...updated});void refresh();}}/>
                <div className="record-actions">
                  {detailResource === "findings" &&
                    detail.kind === "RISK" &&
                    detail.assetId && (
                      <Button
                        type="primary"
                        onClick={() => {
                          const finding = detail;
                          form.resetFields();
                          form.setFieldsValue({
                            title: `修复：${finding.title}`,
                            assetId: finding.assetId,
                            findingId: finding.id,
                            template: "FILE_PERMISSION",
                            permission: "0640",
                          });
                          navigate("tasks");
                          setModal("create");
                        }}
                      >
                        创建关联修复任务
                      </Button>
                    )}
                  {detail.assetId && (
                    <Button
                      onClick={() =>
                        void showDetail({ id: detail.assetId }, "assets")
                      }
                    >
                      查看关联资产
                    </Button>
                  )}
                  {detail.findingId && (
                    <Button
                      onClick={() =>
                        void showDetail({ id: detail.findingId }, "findings")
                      }
                    >
                      查看关联风险
                    </Button>
                  )}
                  {detailResource === "rules" &&
                    detail.kind === "VULNERABILITY" && (
                      <Button
                        onClick={() => {
                          form.resetFields();
                          setModal("run");
                        }}
                      >
                        运行软件漏洞检测
                      </Button>
                    )}
                  {(["rules", "sites"].includes(detailResource) ||
                    (detailResource === "users" && isAdmin)) && (
                    <Button onClick={()=>editDetail()}>编辑配置</Button>
                  )}
                  {detailResource === "users" && isAdmin && (
                    <>
                      <Button
                        onClick={() =>
                          void action(
                            `/users/${detail.id}`,
                            { disabled: !detail.disabled },
                            "PATCH",
                          )
                        }
                      >
                        {detail.disabled ? "启用账户" : "停用账户"}
                      </Button>
                      <Button
                        onClick={() => {
                          form.resetFields();
                          setModal("password");
                        }}
                      >
                        重置密码
                      </Button>
                    </>
                  )}
                  {detailResource === "tasks" &&
                    detail.status === "PENDING" && (
                      <>
                        <InlineRecordAction key={'approve:'+detail.id} label="批准" title="批准受控文件变更" description="审批后 Agent 可以领取并执行此任务。请核对当前目标、路径和变更参数；执行成功仍须独立复测。" confirmLabel="确认批准" onConfirm={async()=>{const updated=await api(`/tasks/${detail.id}/approve`,{});setDetail(current=>current?.id===detail.id?updated:current);message.success('任务已批准，等待 Agent 领取');await refresh();}}/>
                        <Button
                          onClick={() => {
                            form.resetFields();
                            setModal("reject");
                          }}
                        >
                          拒绝
                        </Button>
                      </>
                    )}
                  {(detailResource === "tasks" ||
                    (detailResource === "findings" &&
                      detail.kind === "RISK" &&
                      ["ADMIN", "ANALYST"].includes(user?.role))) &&
                    detail.status === "VERIFYING" && (
                      <Button
                        onClick={() => {
                          form.resetFields();
                          setModal("verify");
                        }}
                      >
                        提交独立复测
                      </Button>
                    )}
                  {["rules", "sites"].includes(detailResource) && (
                    <Button
                      onClick={() =>
                        void action(
                          `/${detailResource}/${detail.id}`,
                          { enabled: !detail.enabled },
                          "PATCH",
                        )
                      }
                    >
                      {detail.enabled ? "停用" : "启用"}
                    </Button>
                  )}
                  {detailResource === "sites" && detail.ruleDeploymentId && detail.mode==='OBSERVE' && <Button onClick={()=>{setDetail(undefined);navigate('waf-rules');}}>在规则发布中切换阻断</Button>}
                  {detailResource === "sites" && !(detail.ruleDeploymentId && detail.mode==='OBSERVE') && (
                    <Button loading={busy} danger={detail.mode==='OBSERVE'} onClick={()=>void action(`/sites/${detail.id}`,{mode:detail.mode==='OBSERVE'?'BLOCK':'OBSERVE'},'PATCH')}>
                      {detail.mode==='OBSERVE'?'切换为阻断':'切换为观察'}
                    </Button>
                  )}
                </div>
                <div ref={inlineFormTarget}/>
                {detailError && <Alert className="record-feedback" type="error" message={detailError} />}
                {detailResource==="assets"&&<section className="record-subsection"><AssetHistoryPanel id={detail.id} onInspect={(value,title)=>setStructuredField({value,title})}/></section>}
                {user&&user.role!=="VIEWER"&&detailResource!=="assets"&&<div className="record-tool-groups">

                {detailResource==="users"&&isAdmin&&<div className="record-validation-actions"><ScopeEditor record={detail} onChanged={()=>{if(renderedDetailVersion===detailRequestVersion.current)void showDetail(detail,"users")}}/></div>}
                {detailResource==='tasks'&&['ADMIN','OPERATOR','ANALYST'].includes(user?.role)&&['VERIFYING','SUCCEEDED','FAILED'].includes(detail.status)&&<Space wrap className="record-validation-actions"><Button onClick={async()=>{try{await api('/repair/'+detail.id+'/verify',{});message.success('已创建独立读取复测任务');await refresh()}catch(e){setDetailError((e as Error).message)}}}>独立读取复测</Button><InlineRecordAction key={'rollback:'+detail.id} danger label="申请回滚" title="创建回滚任务" description="将依据 Agent 本地可信历史创建恢复变更前状态的任务，任务仍需审批。创建申请不会立即执行回滚。" confirmLabel="确认创建回滚申请" onConfirm={async()=>{await api('/repair/'+detail.id+'/rollback',{});message.success('已创建回滚申请，审批后才会执行');await refresh();}}/></Space>}
                {user && user.role!=="VIEWER" && detailResource!=="assets" && <WorkflowTools key={detailResource+detail.id} resource={detailResource} record={detail} onChanged={()=>{if(renderedDetailVersion!==detailRequestVersion.current)return;void showDetail(detail,detailResource);void refresh()}}/>}
                </div>}
                {detailResource==="tasks"&&detail.plan&&<section className="record-plan"><h3>审批方案 · {detail.plan.name} v{detail.plan.version}</h3><Alert type="info" message={detail.plan.impact} description={detail.plan.preflightStatus}/><p>执行窗口：{detail.plan.notBefore?formatTime(detail.plan.notBefore):'审批后可领取'} — {formatTime(detail.plan.windowEnd||detail.plan.expiresAt)}；修改窗口后需要重新审批。</p><TemplateDetails template={detail.plan}/></section>}
                {detailResource === "tasks" && detail.status === "FAILED" && (
                  <Alert
                    className="record-feedback"
                    style={{ marginTop: 16 }}
                    type="error"
                    message={
                      detail.verification?.resolved === false
                        ? "独立复测未通过"
                        : "任务执行失败"
                    }
                    description={
                      detail.verification?.resolved === false
                        ? detail.verification.evidence
                        : detail.result?.evidence ||
                          detail.reason ||
                          "请查看执行结果与审计记录。"
                    }
                  />
                )}
                {detailResource==="assets"&&<><HostNetworkPanel key={"network"+detail.id} assetId={detail.id}/><AssetInventoryView key={detail.id} inventory={detail.inventory} onInspect={(value,title)=>setStructuredField({value,title})}/></>}
                {detailResource==="waf-events"&&<WafInspectionView record={detail}/>}
                {detailResource==="waf-access"&&<WafAccessView record={detail}/>}
                {!["findings","incidents","assets","waf-events","waf-access"].includes(detailResource)&&<EvidenceView value={detail.evidence ?? detail.parameters ?? detail.config ?? detail.inventory ?? detail.description} title="证据与执行参数"/>}
                {detail.result && <EvidenceView value={detail.result} title="执行结果"/>}
                <RecordFieldsTable value={detail} title="完整原始记录"/>
                {["findings", "incidents", "tasks", "assets"].includes(
                  detailResource,
                ) && (
                  <>
                    <RelatedTimeline key={detailResource+detail.id+comments.length} resource={detailResource} id={detail.id} onOpen={(r,target)=>void showDetail(r,target)}/>
                    <h3>调查与处理备注</h3>
                    <Timeline
                      items={comments.map((c) => ({
                        children: (
                          <>
                            <span>{c.actor || c.author}</span>
                            <p>{c.body || c.content}</p>
                            <small className="record-cell-time">{formatTime(c.createdAt)}</small>
                          </>
                        ),
                      }))}
                    />
                    <Input.TextArea
                      aria-label="处理备注"
                      value={note}
                      onChange={(e) => setNote(e.target.value)}
                      rows={3}
                    />
                    <Button
                      style={{ marginTop: 8 }}
                      disabled={!note.trim()}
                      onClick={async () => {
                        try {
                          await api(
                            `/${detailResource}/${detail.id}/comments`,
                            { body: note },
                          );
                          setNote("");
                          const c = await api(
                            `/${detailResource}/${detail.id}/comments`,
                          );
                          setComments(c.items || c);
                        } catch (e) {
                          setDetailError((e as Error).message);
                        }
                      }}
                    >
                      添加备注
                    </Button>
                  </>
                )}
                {["findings", "incidents", "tasks", "assets"].includes(
                  detailResource,
                ) && (
                  <>
                    <h3>证据附件</h3>
                    {user?.role !== "VIEWER" && (
                      <div className="evidence-upload">
                        <Upload
                          showUploadList={false}
                          multiple={false}
                          disabled={uploading}
                          beforeUpload={async (file) => {
                            if (file.size > 1024 * 1024) {
                              setDetailError("附件不能超过 1 MiB");
                              return Upload.LIST_IGNORE;
                            }
                            setUploading(true);
                            setDetailError("");
                            try {
                              const data = await new Promise<string>(
                                (resolve, reject) => {
                                  const reader = new FileReader();
                                  reader.onerror = () =>
                                    reject(new Error("无法读取附件"));
                                  reader.onload = () =>
                                    resolve(
                                      String(reader.result).split(",")[1],
                                    );
                                  reader.readAsDataURL(file);
                                },
                              );
                              await api(
                                `/${detailResource}/${detail.id}/attachments`,
                                {
                                  name: file.name,
                                  contentType:
                                    file.type || "application/octet-stream",
                                  data,
                                },
                              );
                              const result = await api(
                                `/${detailResource}/${detail.id}/attachments`,
                              );
                              setAttachments(result.items);
                              message.success("附件已上传");
                            } catch (err) {
                              setDetailError((err as Error).message);
                            } finally {
                              setUploading(false);
                            }
                            return Upload.LIST_IGNORE;
                          }}
                        >
                          <Button icon={<UploadOutlined/>} loading={uploading} disabled={uploading}>上传附件</Button>
                        </Upload>
                        <span className="muted">选中文件后自动上传，最大 1 MiB</span>
                      </div>
                    )}
                    <Table
                      size="middle"
                      rowKey="id"
                      scroll={{x:600}}
                      pagination={paginationDefaults}
                      key={"attachments:"+detailResource+detail.id}
                      dataSource={attachments}
                      locale={{ emptyText: "尚无附件" }}
                      columns={[
                        { title: "附件名称", dataIndex: "name" },
                        {
                          title: "大小",
                          dataIndex: "size",
                          render: (v: number) => `${v} 字节`,
                        },
                        { title: "上传人", dataIndex: "author" },
                        {
                          title: "操作",
                          render: (_: unknown, file: Row) => (
                            <Button
                              type="link"
                              onClick={async () => {
                                try {
                                  const result = await api(
                                    `/${detailResource}/${detail.id}/attachments/${file.id}`,
                                  );
                                  const bytes = Uint8Array.from(
                                    atob(result.data),
                                    (c) => c.charCodeAt(0),
                                  );
                                  const url = URL.createObjectURL(
                                    new Blob([bytes], {
                                      type: "application/octet-stream",
                                    }),
                                  );
                                  const link = document.createElement("a");
                                  link.href = url;
                                  link.download = result.name;
                                  link.click();
                                  URL.revokeObjectURL(url);
                                } catch (err) {
                                  setDetailError((err as Error).message);
                                }
                              }}
                            >
                              下载
                            </Button>
                          ),
                        },
                      ]}
                    />
                  </>
                )}
                {["rules", "sites"].includes(detailResource) && (
                  <>
                    <h3>配置版本</h3>
                    <p>
                      恢复历史快照会创建一个新版本，保留完整历史。站点策略需等待节点同步。
                    </p>
                    <Table
                      size="middle"
                      rowKey="id"
                      scroll={{x:650}}
                      key={"versions:"+detailResource+detail.id}
                      dataSource={versions}
                      pagination={paginationDefaults}
                      columns={[
                        { title: "版本", dataIndex: "version" },
                        { title: "修改人", dataIndex: "actor" },
                        { title: "修改时间", dataIndex: "createdAt", render:formatTime },
                        {
                          title: "操作",
                          render: (_: unknown, v: Row) =>
                            (isAdmin ||
                              (detailResource === "rules" &&
                                user?.role === "ANALYST")) &&
                            v.version !== detail.version ? (
                              <InlineRecordAction key={'restore:'+detail.id+':'+v.version} presentation="modal" label="恢复为新版本" title={`恢复版本 ${v.version}`} description="将使用该历史配置生成新的活动版本。请先核对展开的历史快照与当前配置，确认启停状态与业务影响。" confirmLabel="确认恢复为新版本" onConfirm={async()=>{const opened=detailRequestVersion.current;await api(`/${detailResource}/${detail.id}/restore`,{version:v.version});message.success('历史配置已恢复为新版本');if(opened===detailRequestVersion.current)await showDetail(detail,detailResource);await refresh();}}/>
                            ) : null,
                        },
                      ]}
                      expandable={{
                        expandedRowRender: (v) => (
                          <>
                            <h4>历史快照</h4>
                            <RecordFieldsTable value={v.snapshot} title="历史配置字段"/>
                            <h4>当前配置</h4>
                            <RecordFieldsTable value={{
                                  config: detail.config,
                                  enabled: detail.enabled,
                                  mode: detail.mode,
                                }} title="站点历史状态字段"/>
                          </>
                        ),
                      }}
                    />
                  </>
                )}
                {isAdmin && (
                  <>
                    <h3>操作时间线</h3>
                    <Timeline
                      items={history.map((h) => ({
                        children: (
                          <>
                            {h.action} · {h.actor}
                            <p>
                              {formatTime(h.createdAt)}
                            </p>
                          </>
                        ),
                      }))}
                    />
                  </>
                )}
              </>
            )}
          </Drawer>}
          {structuredField&&<Drawer open placement="right" className="record-drawer" width="min(860px, calc(100vw - 24px))" title={structuredField.title} onClose={()=>setStructuredField(undefined)}><RecordFieldsTable value={structuredField.value}/></Drawer>}
          <RecordFormHost
            centered={["assets","sites","rules"].includes(editorResource)}
            inlineTarget={modal!=="edit"&&detail&&!["sites","rules"].includes(detailResource)&&inlineDetailModes.includes(modal)?inlineFormTarget.current:null}
            className="module-modal"
            title={
              modal === "assign" || modal === "bulk-assign"
                ? "分派负责人"
                : modal === "run"
                  ? "运行软件漏洞检测"
                  : modal === "save-view"
                    ? "保存当前视图"
                    : modal === "edit"
                      ? "编辑记录"
                      : modal === "password"
                        ? "重置密码"
                        : modal === "status"
                          ? "更新处置状态"
                          : modal === "create"
                            ? "新建记录"
                            : modal === "import"
                              ? "导入外部发现"
                              : modal === "reject"
                                ? "拒绝任务"
                                : "独立复测"
            }
            open={!!modal}
            maskClosable={!busy}
            closable={!busy}
            cancelButtonProps={{disabled:busy,'aria-label':'取消'}}
            cancelText="取消"
            okText={modal==='import'?'导入发现':modal==='run'?'开始检测':modal==='verify'?'提交复测':modal==='reject'?'拒绝任务':modal==='create'?'创建记录':'保存'}
            okButtonProps={{danger:modal==='reject','aria-label':modal==='import'?'导入发现':modal==='run'?'开始检测':modal==='verify'?'提交复测':modal==='reject'?'拒绝任务':modal==='create'?'创建记录':'保存'}}
            onCancel={() => {if(busy)return;if(modal==="edit")setError("");setModal("");if(listEditing){setDetail(undefined);setListEditing(false);}}}
            onOk={() => void submit()}
            confirmLoading={busy}
            destroyOnClose
          >
            {error && (
              <Alert
                type="error"
                message={error}
                style={{ marginBottom: 16 }}
              />
            )}
            <Form form={form} layout="vertical" preserve={false} disabled={busy} onValuesChange={changed=>{if(editorResource==='tasks'&&Object.hasOwn(changed,'assetId'))form.setFieldValue('findingId',undefined)}}>
              {modal === "bulk-assign" ? field("owner","负责人") : modal === "assign" ? (
                <>
                  {field("owner", "负责人")}
                  {detailResource === "findings" &&
                    field("dueAt", "处理期限（可选）", false)}
                </>
              ) : modal === "run" ? (
                <>
                  <p>
                    按已采集软件包与规则中的版本进行精确匹配。留空将检查所有已登记资产；结果不代表完成全部漏洞扫描。
                  </p>
                  {field("assetId", "目标资产（可选）", false)}
                </>
              ) : modal === "save-view" ? (
                field("name", "视图名称")
              ) : modal === "password" ? (
                <Form.Item
                  name="password"
                  label="新密码（至少 16 字符）"
                  rules={[{ required: true, min: 16 }]} extra="设置后替换当前账户密码并撤销既有登录会话；使用独立且足够长的密码。"
                >
                  <Input.Password />
                </Form.Item>
              ) : modal === "status" ? (
                <>
                  {select("status", "目标状态", statusOptions(detailResource,detail?.kind,detail?.status))}
                  {field(
                    "reason",
                    "处置原因",
                    detailResource === "findings",
                    true,
                  )}
                  {detailResource === "findings" &&
                    field(
                      "expiresAt",
                      "风险接受到期时间（仅接受风险时填写）",
                      false,
                    )}
                  {detailResource === "incidents" && (
                    <>
                      {field("conclusion", "处置结论", false, true)}
                      {field("verification", "验证证据", false, true)}
                    </>
                  )}
                </>
              ) : modal === "import" ? (
                <>
                  <p>
                    JSON 数组；每条需包含
                    title、kind、severity、source、externalId、evidence（证据文本字符串），可选
                    assetId。
                  </p>
                  {field("items", "发现数组", true, true)}
                </>
              ) : modal === "reject" ? (
                field("reason", "拒绝原因")
              ) : modal === "verify" ? (
                <>
                  {select("resolved", "复测结论", ["true", "false"])}
                  {field("evidence", "独立复测证据", true, true)}
                </>
              ) : (
                <>
                  {editorResource === "users" && isAdmin && (
                    <>
                      {modal === "create" && (
                        <>
                          {field("email", "邮箱")}
                          <Form.Item
                            name="password"
                            label="初始密码（至少 16 字符）"
                            rules={[{ required: true, min: 16 }]} extra="为新账户设置独立登录密码，通过受控方式交给实际使用人，不使用组件令牌。"
                          >
                            <Input.Password />
                          </Form.Item>
                        </>
                      )}
                      {field("name", "显示名称")}
                      {select("role", "角色", [
                        "ADMIN",
                        "ANALYST",
                        "OPERATOR",
                        "VIEWER",
                      ])}
                    </>
                  )}
                  {editorResource === "assets" && (
                    <>
                      {field("hostname", "主机名")}
                      <AssetOperatingSystemFields/>
                      {field("ip", "IP 地址", false)}
                      {field("business", "所属业务", false)}
                      {field("owner", "负责人", false)}
                      {field("tags", "标签（英文逗号分隔）", false)}
                      {modal==='create'&&['ADMIN','OPERATOR'].includes(user?.role||'')&&<AssetCreateSshFields/>}
                    </>
                  )}
                  {editorResource === "incidents" && (
                    <>
                      {field("title", "事件标题")}
                      {select("severity", "严重程度", severity)}
                      {field("description", "事件描述", true, true)}
                      {field(
                        "findingIds",
                        "关联发现（最多100项）",
                        false,
                      )}
                    </>
                  )}
                  {editorResource === "rules" && (
                    <>
                      {field("name", "规则名称")}
                      {select("kind", "检测类型", [
                        "BASELINE",
                        "LOG",
                        "FIM",
                        "VULNERABILITY",
                      ])}
                      {select("severity", "严重程度", severity)}
                      {field("config", "规则配置 JSON", true, true)}
                      {selectedRuleKind === "VULNERABILITY" && (
                        <Form.Item
                          name="intervalSeconds"
                          label="自动检测间隔（秒）"
                          extra="留空停用调度；60–604800 秒，仅对软件漏洞规则执行服务端检测。"
                          rules={[{ type: "integer", min: 60, max: 604800 }]}
                        >
                          <InputNumber
                            min={60}
                            max={604800}
                            precision={0}
                            placeholder="不自动执行"
                            style={{ width: "100%" }}
                          />
                        </Form.Item>
                      )}
                      <Form.Item
                        name="enabled"
                        label="启用"
                        valuePropName="checked" extra="控制此配置是否参与后续运行；保存后生效，停用仍保留既有历史记录。"
                      >
                        <Switch />
                      </Form.Item>
                    </>
                  )}
                  {editorResource === "tasks" && (
                    <>
                      <Alert
                        type="warning"
                        message="任务审批后会变更目标主机；请核对模板、目标和业务影响。"
                      />
                      {field("title", "任务标题")}
                      {field("assetId", "目标资产")}
                      {field("findingId", "关联风险", false)}
                      {select("template", "修复模板", [
                        "FILE_PERMISSION",
                        "CONFIG_VALUE", "SERVICE_STATE",
                      ])}
                      {selectedTemplate!=="SERVICE_STATE"&&<>{field("path", "目标文件绝对路径")}{field("healthService","关联服务健康检查（可选，仅本地白名单.service）",false)}</>}
                      {selectedTemplate === "SERVICE_STATE" ? <><Alert type="warning" message="服务启动或停止可能影响业务，Agent 必须配置明确的服务白名单。"/>{field('service','服务单元（例如 auditd.service）')}{select('expectedState','预期当前状态',['active','inactive'])}{select('serviceState','目标状态',['active','inactive'])}</> : selectedTemplate === "CONFIG_VALUE" ? (
                        <>
                          <Alert
                            type="info"
                            message="仅修改已有 KEY=VALUE 的指定行；必须与预期当前值一致。文件最大 64 KiB，审批后执行，不重启服务。"
                          />
                          {field("configKey", "配置键")}
                          <Form.Item
                            name="expectedValue"
                            label="预期当前值"
                            rules={[{ required: true }]} extra="执行前先核对该配置项仍为此值；不一致时拒绝变更，避免覆盖其他人的修改。"
                          >
                            <Input.Password />
                          </Form.Item>
                          <Form.Item
                            name="value"
                            label="目标值"
                            rules={[{ required: true }]} extra="填写本次修复需要写入的配置值；与预期当前值一起核对业务影响。"
                          >
                            <Input.Password />
                          </Form.Item>
                        </>
                      ) : (
                        field("permission", "目标权限（例如 0640）")
                      )}
                    </>
                  )}
                  {editorResource === "sites" && (
                    <>
                      {field("name", "站点名称")}
                      {field("hostname", "站点域名")}
                      {field("upstream", "上游地址（http:// 或 https://）")}
                      {select("mode", "防护模式", ["OBSERVE", "BLOCK"])}
                      {field("config", "防护配置 JSON", true, true)}
                      <Form.Item
                        name="enabled"
                        label="启用"
                        valuePropName="checked" extra="控制此配置是否参与后续运行；保存后生效，停用仍保留既有历史记录。"
                      >
                        <Switch />
                      </Form.Item>
                    </>
                  )}
                </>
              )}
            </Form>
          </RecordFormHost>
        </Layout.Content>
      </Layout>
    </Layout>
  );
}
function Root() {
  return (
    <ConfigProvider
      locale={zhCN}
      theme={themeConfig}
      button={{autoInsertSpace:false}}
    >
      <AntApp>
        <Application />
      </AntApp>
    </ConfigProvider>
  );
}
applyThemeTokens();
createRoot(document.getElementById("root")!).render(<Root />);
