const legacyGroups: [string, [string, string][]][] = [
  [
    "资产中心",
    [
      ["assets", "资产列表"],["asset-candidates","资产发现与认领"],["database-instances","数据库实例"],
      ["business", "业务分组"],
      ["enroll", "采集与接入"],
    ],
  ],
  [
    "网络安全",
    [
      ['network-findings','网络发现'],['network-risks','网络风险'],['network-alerts','网络告警'],['network-incidents','网络调查'],['network-hosts','主机与流量'],
      ["sites", "站点管理"],["waf-events", "攻击记录"],
      ["policies", "防护策略"],["waf-rules", "防护规则库"],["access", "访问日志"],
      ["nodes", "节点状态"],["policy-test", "防护规则测试"],["certificates", "站点证书"],
    ],
  ],
  ['数据安全',[
    ['data-findings','数据发现'],['data-risks','数据风险'],['data-alerts','数据告警'],['data-incidents','数据调查'],
    ['data-classification','数据分类分级'],['data-security','准入与行为规则'],['database-audit','数据库审计'],['data-access','访问行为记录'],['data-access-sources','采集覆盖与探针'],
  ]],
  [
    "策略中心",
    [
      ["rules", "检测规则"],
      ["baseline", "配置基线"],["rule-sources-status","规则来源与更新"],["rule-scope", "规则适用范围"],["rule-test", "规则样本验证"],
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
export const groups: [string, [string,string][]][] = [
 ['资产',[['assets','主机资产'],['database-instances','数据实例'],['business','业务分组']]],
 ['网络安全',[['network-hosts','流量分析'],['scans','漏洞管理'],['network-alerts','安全告警']]],
 ['数据安全',[['data-access','访问审计'],['data-classification','分类分级'],['data-alerts','安全告警']]],
 ['设置',[['users','用户与权限'],['webhook','通知设置'],['retention','存储与保留'],['backup','备份'],['audit','操作审计'],['operations','平台状态']]],
];
export const workspacePages:[string,string][]=[['overview','概览'],['findings','全部安全记录'],['risks','风险记录'],['alerts','告警记录']];
export const names:Record<string,string> = Object.fromEntries([
 ...legacyGroups.flatMap(([,pages])=>pages),...workspacePages,...groups.flatMap(([,pages])=>pages),
 ['incidents','历史调查'],['operation-guide','使用指南'],['asset-candidates','待认领资产'],['enroll','资产接入'],['database-audit','数据库审计'],['data-access-sources','数据采集配置'],['data-security','准入与行为规则'],['network-risks','漏洞与配置检查结果'],['network-sensors','流量分析'],
]);
const wafPages=['sites','policies','waf-rules','waf-events','access','nodes','policy-test','certificates'];
const workflowPages=['tasks','approvals','templates','batches','incidents','network-incidents','data-incidents','governance','correlation'];
export function retiredModule(page:string):string|undefined {
 if(wafPages.includes(page))return '自研 WAF 已退出本期功能。当前平台提供流量观测和漏洞检测，不承担网站实时拦截。历史数据保留，未变更业务代理。';
 if(workflowPages.includes(page))return '本期聚焦安全观测与问题核查，暂不提供审批、调查编排或自动修复。历史记录保留。';
 if(['reports','trends','exports'].includes(page))return '独立报告中心已退出本期功能。请在安全记录中筛选并导出所需结果，历史记录保留。';
 if(['telemetry','imports','design-system','notifications'].includes(page))return '该维护工具不在当前日常工作范围内，已有记录保留。';
}
const relatedPages:Record<string,string>={
 'network-sensors':'network-hosts',
 'asset-candidates':'assets',enroll:'assets',
 sources:'scans','rule-sources-status':'scans',rules:'scans',baseline:'scans','rule-scope':'scans','rule-test':'scans',detection:'scans','network-risks':'scans','network-findings':'scans',
 'database-audit':'data-access','data-access-sources':'data-access','data-security':'data-alerts','data-risks':'data-alerts','data-findings':'data-alerts',
 credentials:'operations',rollouts:'operations',deliveries:'webhook',notifications:'webhook',
};
// Related configuration stays discoverable without adding a navigation level.
export function navigationSections(_group:string):{key:string;label:string;pages:string[]}[]{return [];}
export type SecurityPageScope={domain:'NETWORK'|'DATA';resource:'findings'|'discoveries';kind?:'RISK'|'ALERT'|'INCIDENT'};
export function securityPageScope(page:string):SecurityPageScope|undefined {
 const match=/^(network|data)-(findings|risks|alerts|incidents)$/.exec(page);if(!match)return;
 const kind:Record<string,SecurityPageScope['kind']>={risks:'RISK',alerts:'ALERT',incidents:'INCIDENT'};
 return {domain:match[1]==='network'?'NETWORK':'DATA',resource:['risks','alerts'].includes(match[2])?'findings':'discoveries',kind:kind[match[2]]};
}
export function applySecurityPageQuery(page:string,query:URLSearchParams){const scope=securityPageScope(page);if(scope){query.set('securityDomain',scope.domain);if(scope.kind)query.set('kind',scope.kind);else query.delete('kind');}return query;}

export function resolveNavigation(page:string){
 const activePage=relatedPages[page]||page;
 const group:typeof groups[number]|undefined=workspacePages.some(([key])=>key===page)?['概览',[]]:groups.find(([,pages])=>pages.some(([key])=>key===activePage));
 return {group,activePage,section:undefined as {key:string;label:string;pages:string[]}|undefined,modules:group?.[1]||[]};
}
