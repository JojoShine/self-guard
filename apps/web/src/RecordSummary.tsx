import {Typography} from 'antd';
import {assetOSDisplay} from './asset-os';
import {displayStatus,displaySeverity,displaySource,formatTime} from './presentation';
import './record-details.css';
import {StatusTag,SeverityTag} from './ModuleSection';
const types:Record<string,string>={RISK:'风险',ALERT:'告警',INCIDENT:'事件调查',BASELINE:'配置基线',LOG:'日志检测',FIM:'文件完整性',VULNERABILITY:'漏洞检测',FILE_PERMISSION:'文件权限',CONFIG_VALUE:'配置值',SERVICE_STATE:'服务状态',assets:'资产',findings:'发现',risks:'风险',alerts:'告警',incidents:'事件调查',tasks:'修复任务',rules:'检测规则',sites:'防护站点',users:'账户'};
function display(format:(value:unknown)=>string,value:unknown){const result=format(value);return typeof result==='string'?result:String(value);}
export function RecordSummary({record,resource}:{record:Record<string,any>;resource:string}){
 const kind=record.kind||record.type||record.template||resource;
 const os=resource==='assets'?assetOSDisplay(record):undefined;
 const metadata=[...(os?[["操作系统",os.label],["系统信息来源",os.source==='agent'?'Agent 实际采集':os.source==='declared'?'手工登记':'系统类型 / 待识别']]:[]),['负责人',record.owner],['业务',record.business],['创建时间',record.createdAt?formatTime(record.createdAt):undefined],['更新时间',record.updatedAt?formatTime(record.updatedAt):undefined]].filter(([,value])=>value!==undefined&&value!==null&&value!=='');
 return <section className="record-summary" aria-label="记录概要">
 <div className="record-badges">
 {record.severity&&<SeverityTag value={record.severity} ariaLabel={'严重程度：'+display(displaySeverity,record.severity)}/>}
 {record.status&&<StatusTag value={record.status} ariaLabel={'处置状态：'+display(displayStatus,record.status)}/>}
 {!record.status&&typeof record.enabled==='boolean'&&<StatusTag value={record.enabled?'ENABLED':'DISABLED'} ariaLabel={'启用状态：'+(record.enabled?'已启用':'已停用')}/>}
 {kind&&<span className="record-type">{Object.hasOwn(types,kind)?types[kind]:String(kind)}</span>}
 {record.source&&<span className="record-source">来源：{display(displaySource,record.source)}</span>}
 </div>
 {metadata.length>0&&<dl className="record-metadata">{metadata.map(([label,value])=><div key={String(label)}><dt>{label}</dt><dd>{value}</dd></div>)}</dl>}
 {record.id&&<div className="record-identifier"><span>记录标识</span><Typography.Text copyable={{text:String(record.id)}}>{String(record.id)}</Typography.Text></div>}
 </section>;
}
