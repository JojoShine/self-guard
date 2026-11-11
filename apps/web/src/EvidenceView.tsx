import {Typography} from 'antd';
import {RecordFieldsTable} from './RecordFieldsTable';
import {displaySource,displayStatus,formatTime} from './presentation';
import './record-details.css';

export function parseEvidence(value:unknown):unknown{
 let parsed=value;
 for(let level=0;level<2&&typeof parsed==='string';level++){
  if(parsed==='[已隐藏]')break;
  try{parsed=JSON.parse(parsed);}catch{break;}
 }
 return parsed;
}
const labels:Record<string,string>={sourceIp:'来源IP',sourcePort:'来源端口',user:'尝试账号',database:'目标数据库',tls:'连接已加密',sourceParts:'本次完整来源的组成',snapshotId:'来源快照编号',artifactSha256:'下载文件摘要',contentSha256:'合并后完整内容摘要',normalizerVersion:'数据解释版本',sourceUrl:'原始数据地址',osvOriginalVersion:'通告原始版本时间',modified:'来源修改时间',withdrawn:'来源撤回时间',archiveScope:'本次来源适用范围',excludedAffected:'未纳入本次范围的适用条件数',upstream:'厂商通告涉及的上游漏洞',related:'相关通告',reportedEcosystem:'来源原始发行范围',coveredEcosystems:'已校验的完整生态范围',versions:'明确受影响版本',ranges:'受影响版本范围',repo:'来源代码仓库',purl:'标准软件标识',limit:'范围上界（不含）',normalization:'来源范围解释情况',activeUnscopedAffected:'未明确软件身份的活动范围',unscopedAffectedCount:'未提供软件身份的范围数量',scopeWarning:'适用范围说明',withdrawnIdentityIssues:'已撤回历史身份说明',ruleId:'命中规则编号',variable:'匹配位置',messageTemplate:'规则说明',valueSha256:'匹配内容摘要',valueBytes:'匹配内容字节数',tags:'规则分类',logDataSha256:'补充匹配摘要',logDataBytes:'补充匹配字节数',distribution:'发行系统',versionId:'发行版本',packageCollection:'系统包采集情况',portCollection:'端口采集情况',serviceCollection:'服务采集情况',distributionCollection:'发行版采集情况',ports:'监听端口',port:'端口',protocol:'协议',address:'地址',services:'系统服务',bomRef:'清单组件标识',dependsOn:'依赖组件标识',provenance:'版本依据',sourceSha256:'来源内容摘要',inputs:'实际采集输入',format:'采集格式',reportedName:'原始报告名称',reportedPackage:'来源原始包名',kind:'依据类型',vendorStatus:'厂商状态',urgency:'厂商处理优先级',codename:'发行版代号',release:'发行版本',repositories:'仓库版本',nodsa:'未发布独立安全通告的说明',nodsaReason:'厂商说明',component:'实际软件',observations:'实际观测记录',sourceVersion:'源软件包版本',binaryVersion:'安装子包版本',architecture:'软件架构',manager:'包管理器',missingSourceMetadata:'缺少源包元数据',omittedObservations:'未在本条记录留存的其余数量',name:'软件名称',version:'软件版本',ecosystem:'软件生态',origin:'源软件包',description:'漏洞内容',descriptionSource:'漏洞内容来源',applicability:'软件适用依据',sources:'来源与快照',provider:'官方来源',externalId:'来源通告编号',fixed:'修复版本',introduced:'开始受影响版本',last_affected:'最后受影响版本',events:'版本范围边界',range:'受影响范围',scheme:'版本比较规则',knownExploited:'本条编号收录在野利用',exploitation:'利用情况',requiredAction:'建议行动',scores:'原始评分',score:'基础分',sourceStale:'来源依据已过期',severityConflict:'评分来源存在差异',applicabilityConflict:'软件适用来源存在冲突',scope:'判断范围',eventCount:'窗口内日志',windowSeconds:'时间窗口（秒）',mode:'条件关系',ruleName:'关联规则',path:'检查路径',service:'服务',key:'配置项',type:'检查类型',status:'检查结果',actual:'实际值',expected:'期望值',value:'目标值',expectedValue:'原配置值',state:'目标服务状态',expectedState:'原服务状态',change:'文件变化',package:'软件包',affectedVersion:'受影响版本',fixedVersion:'修复版本',advisory:'安全通告',matches:'命中软件包数',count:'数量',source:'日志来源',method:'请求方法',action:'防护动作',outcome:'结果',category:'分类',message:'日志消息',reason:'说明',complete:'完整采集',collection:'采集情况',offset:'日志偏移',bytes:'字节数',lines:'日志行数',success:'执行成功',evidence:'补充证据',relationship:'引用关系'};
const scoreLabels:Record<string,string>={...labels,version:'评分规范与版本',vector:'来源原始向量或评级',score:'来源数值分',source:'评分来源',type:'评分类型',severity:'来源报告等级'};
const sourceLabels:Record<string,string>={...labels,version:'情报数据版本',stale:'来源已过期',rawSha256:'通告内容摘要',sourceUrl:'原始数据地址'};
const sourcePartLabels:Record<string,string>={...sourceLabels,role:'来源资料角色'};
const providerNames:Record<string,string>={OSV:'OSV软件适用数据',NVD:'NVD漏洞资料',CISA_KEV:'CISA在野利用目录',DEBIAN:'Debian厂商漏洞状态',ALPINE:'Alpine安全数据'};
const values:Record<string,string>={ANNUAL_SOURCE:'官方年度原包',BASELINE_UPDATES:'建立完整基线的官方修改源',COMPLETE_BASE:'完整基线原包',VERIFIED_DELTA:'已校验的增量原件',UPSTREAM_REFERENCE:'厂商更新通告引用',SEMVER:'语义版本规则',GIT:'Git代码提交范围',ECOSYSTEM:'对应生态版本规则',DEBIAN:'Debian/Ubuntu版本规则',RPM:'RPM版本规则',APK:'Alpine版本规则',GO:'Go模块版本规则',PEP440:'Python版本规则',MAVEN:'Maven版本规则',OSV_UNSCOPED:'上游未提供软件身份（仅保留范围）',OSV_WITHDRAWN_PACKAGE:'已撤回历史包（不参与活动匹配）',LOCK_FILE:'锁文件解析版本（候选）',SBOM:'导入SBOM（候选）',NPM_LOCK_FILE:'npm锁文件v2/v3',CYCLONEDX_1_6:'CycloneDX1.6 JSON',INSTALLED_METADATA:'实际部署元数据',NPM_INSTALLED_TREE:'npm已安装目录',PYTHON_SITE_PACKAGES:'Python已安装分发',MAVEN_JAR:'Java制品坐标',GO_BINARY:'Go二进制构建信息',DEBIAN_STATUS:'Debian 厂商适用判断',DISTRIBUTION_FIX:'发行版修复版本',OSV_PACKAGE:'来源组件条件',FIXED:'低于修复版本',AFFECTED:'厂商确认受影响',NOT_AFFECTED:'厂商确认不受影响',UNKNOWN:'待确认',resolved:'已解决',open:'尚未修复',undetermined:'厂商待确认',DATABASE_AUTH:'数据库疑似口令爆破',DATABASE_CLEARTEXT:'数据库未加密连接',DATABASE_SECURITY:'数据库配置检查',DETECT_ONLY:'仅检测',NOT_BLOCKED:'未执行阻断',NOT_MODIFIED:'未修改配置',CONFIGURATION_ONLY:'仅文件配置观察',OBSERVED_CONNECTION_LOGS:'真实连接审计',MYSQL_TLS_REQUIRED:'MySQL必须使用安全传输',POSTGRES_TLS_ENABLED:'PostgreSQL启用TLS',POSTGRES_HBA_TLS:'PostgreSQL网络连接加密策略',POSTGRES_HBA_AUTH:'PostgreSQL网络认证策略',CREDENTIAL_FILE_MODE:'数据库凭据文件仅属主可访问',FILE_PERMISSION:'文件权限',CONFIG_VALUE:'配置值',SERVICE_STATE:'服务状态',checked:'已检查',unreadable:'无法读取',missing:'缺失',present:'存在',created:'新建',deleted:'删除',modified:'修改',active:'运行中',inactive:'已停止',failed:'失败',BLOCK:'阻断',OBSERVE:'观察',ALLOW:'放行',ALL:'全部满足',ANY:'任一满足','missing or duplicate key':'配置项缺失或重复'};
const fieldLabels:Record<string,string>={type:'事件类型',source:'来源','data.status':'响应状态','data.method':'请求方法','data.action':'防护动作','data.ruleId':'命中规则','data.outcome':'结果','data.category':'分类','data.message':'日志消息'};
const operatorLabels:Record<string,string>={eq:'等于',contains:'包含'};
function text(value:unknown):string{
 if(value===null||value===undefined)return '—';
 if(typeof value==='boolean')return value?'是':'否';
 return typeof value==='object'?JSON.stringify(value):String(value);
}
function lookup(map:Record<string,string>,value:unknown){const key=text(value);return Object.hasOwn(map,key)?map[key]:key;}
function display(format:(value:unknown)=>string,value:unknown){const result=format(value);return typeof result==='string'?result:text(value);}
function simple(value:unknown){return value===null||typeof value!=='object';}
function valueLabel(key:string,value:unknown):string{
 if(key==='introduced'&&value==='0')return '自初始版本起（代码范围表示初始提交）';
 if(key==='package'&&value==='*')return '此生态全部软件（来源通配范围）';
 if(key==='provider')return lookup(providerNames,value);
 if(key==='source')return display(displaySource,value);
 if(key==='status')return Object.hasOwn(values,text(value))?values[text(value)]:display(displayStatus,value);
 if(['role','relationship','kind','scheme','provenance','format','type','change','state','expectedState','action','mode','scope','outcome','key'].includes(key))return lookup(values,value);
 return text(value);
}
function timeLabel(value:unknown){const formatted=formatTime(value);return formatted==='—'?text(value):formatted;}
function FieldValue({name,value}:{name:string;value:unknown}){
 if(simple(value))return <span>{valueLabel(name,value)}</span>;
 if(Array.isArray(value)&&value.every(simple))return <span>{(value.slice(0,50).map(v=>text(v)).join('、')||'—')+(value.length>50?'；另有 '+(value.length-50)+' 项，可在下方完整字段表查看':'')}</span>;
 if(Array.isArray(value))return <ul className="evidence-nested-list">{value.slice(0,50).map((item,index)=><li key={index}><FieldValue name={name} value={item}/></li>)}{value.length>50&&<li className="evidence-secondary">其余 {value.length-50} 项可在完整原始字段中查看</li>}</ul>;
 const names=name==='scores'?scoreLabels:name==='sources'||name==='descriptionSource'?sourceLabels:name==='sourceParts'?sourcePartLabels:labels;
 const entries=Object.entries(value as object).filter(([key])=>Object.hasOwn(names,key));
 return entries.length?<dl className="evidence-nested">{entries.map(([key,item])=><div key={key}><dt>{names[key]}</dt><dd><FieldValue name={key} value={item}/></dd></div>)}</dl>:<span className="evidence-secondary">{Array.isArray(value)?`${value.length} 条内容`:`${Object.keys(value as object).length} 个字段`}，可在下方完整字段表查看</span>;
}
function isRecord(value:unknown):value is Record<string,unknown>{return value!==null&&typeof value==='object'&&!Array.isArray(value)}
function sensorEndpoint(ip:unknown,port:unknown){const address=typeof ip==='string'?ip:'未知';return typeof port==='number'?(address.includes(':')?'['+address+']':address)+':'+port:address}
function SensorAlertEvidence({value}:{value:Record<string,unknown>}){
 const metadata=isRecord(value.metadata)?value.metadata:{},alert=isRecord(metadata.alert)?metadata.alert:{};
 return <div className="module-stack"><p>命中检测规则，不等于已确认入侵。平台仅产生告警，未执行阻断；关联资产是采集主机，目标归属仍需核对。</p><dl className="evidence-fields">
  <div className="evidence-field"><dt>检测规则</dt><dd>{text(alert.signature)}</dd></div>
  <div className="evidence-field"><dt>实际连接</dt><dd>{sensorEndpoint(value.sourceIp,value.sourcePort)} → {sensorEndpoint(value.destinationIp,value.destinationPort)}</dd></div>
  <div className="evidence-field"><dt>采集方式</dt><dd>{value.mode==='REPLAY'?'离线回放，不能作为当前攻击证明':value.mode==='LIVE'?'实时采集记录':'未标记采集方式'}</dd></div>
  <div className="evidence-field"><dt>发生时间</dt><dd>{timeLabel(value.occurredAt)}</dd></div>
 </dl></div>;
}
function StructuredEvidence({value}:{value:Record<string,unknown>}){
 if(value.assetRole==='SENSOR_HOST'&&value.eventType==='alert')return <SensorAlertEvidence value={value}/>;
 const fields=Object.keys(labels).filter(key=>Object.hasOwn(value,key));
 const hasWindow=Object.hasOwn(value,'from')||Object.hasOwn(value,'to');
 const conditions=Array.isArray(value.conditions)?value.conditions:undefined;
 const upstream=Array.isArray(value.upstreamContext)?value.upstreamContext:undefined;
 return <>
 {['DATABASE_AUTH','DATABASE_CLEARTEXT'].includes(String(value.type))&&<div className="module-stack"><h4>真实行为说明</h4><p className="evidence-text">来源 {text(value.sourceIp)} → 本记录关联资产上的 {text(value.service)} 服务。{value.type==='DATABASE_AUTH'?<>时间窗口内观察到 {text(value.count)} 次认证失败，达到本条规则阈值；判为疑似口令爆破。</>:'连接审计明确报告连接成功且未加密。'}这里只报告检测结果，未自动封禁来源或断开数据库连接。</p><p className="evidence-secondary">下面列出实际账号、数据库、原始发生时间及记录摘要；目标以当前关联资产和日志实例为准，未推断后续数据库调用链。</p></div>}
 {(fields.length>0||hasWindow)&&<dl className="evidence-fields">
 {Object.hasOwn(value,'eventCount')&&<div className="evidence-field evidence-field--emphasis"><dt>{labels.eventCount}</dt><dd>{text(value.eventCount)}{typeof value.eventCount==='number'&&<span className="evidence-unit">条</span>}</dd></div>}
 {hasWindow&&<div className="evidence-field"><dt>关联窗口</dt><dd className="evidence-window">{Object.hasOwn(value,'from')&&<span>开始 {timeLabel(value.from)}</span>}{Object.hasOwn(value,'to')&&<span>结束 {timeLabel(value.to)}</span>}</dd></div>}
 {fields.filter(key=>key!=='eventCount').map(key=><div className="evidence-field" key={key}><dt>{labels[key]}</dt><dd><FieldValue name={key} value={value[key]}/></dd></div>)}
 </dl>}
 {conditions&&conditions.length>0&&<div className="evidence-conditions"><h4>匹配条件</h4><ol>{conditions.map((condition,index)=><li key={index}>{condition&&typeof condition==='object'?<>{Object.hasOwn(condition,'field')&&<span className="evidence-condition-field">{lookup(fieldLabels,condition.field)}</span>}{Object.hasOwn(condition,'operator')&&<span>{lookup(operatorLabels,condition.operator)}</span>}{Object.hasOwn(condition,'value')&&<span className="evidence-condition-value">{simple(condition.value)?text(condition.value):'结构化值（见下方完整字段表）'}</span>}{Object.hasOwn(condition,'threshold')&&<span className="evidence-secondary">至少 {text(condition.threshold)} 次</span>}</>:text(condition)}</li>)}</ol></div>}
 {upstream&&upstream.length>0&&<details className="evidence-source-context"><summary>查看关联CVE的独立来源信息（{upstream.length}条）</summary><p className="evidence-secondary">以下资料按厂商通告引用的CVE补充说明、评分与利用优先级，不改变本条厂商通告的身份或等级，也不证明本机已经被利用。</p><FieldValue name="upstreamContext" value={upstream}/></details>}
 {Object.hasOwn(value,'ruleId')&&<div className="evidence-reference"><span>关联规则标识</span><Typography.Text copyable={{text:text(value.ruleId)}}>{text(value.ruleId)}</Typography.Text></div>}
 {fields.length===0&&!hasWindow&&!conditions&&!Object.hasOwn(value,'ruleId')&&<p className="evidence-secondary">已提供结构化证据，可在下方完整字段表查看。</p>}
 </>;
}
export function EvidenceView({value,title='证据与检查结果'}:{value:unknown;title?:string}){
 const parsed=parseEvidence(value);
 const hidden=parsed==='[已隐藏]';
 const empty=parsed===null||parsed===undefined||parsed==='';
 const structured=parsed!==null&&typeof parsed==='object';
 return <section className="evidence-view" aria-label={title}>
 <h3 className="evidence-heading">{title}</h3>
 {hidden?<p className="evidence-hidden">[已隐藏]</p>:empty?<p className="evidence-empty">暂无证据</p>:structured?<>
 {Array.isArray(parsed)?<ol className="evidence-records">{parsed.slice(0,50).map((item,index)=><li key={index}>{item&&typeof item==='object'&&!Array.isArray(item)?<StructuredEvidence value={item}/>:<p className="evidence-text">{simple(item)?text(item):'结构化内容，可在下方完整字段表查看。'}</p>}</li>)}{parsed.length>50&&<li className="evidence-secondary">其余 {parsed.length-50} 项可在完整原始字段中查看</li>}</ol>:<StructuredEvidence value={parsed as Record<string,unknown>}/>}
 <details className="evidence-raw"><summary>技术字段与完整证据</summary><RecordFieldsTable value={parsed} labels={{...labels,version:'版本'}}/></details>
 </>:<p className="evidence-text">{text(parsed)}</p>}
 </section>;
}
