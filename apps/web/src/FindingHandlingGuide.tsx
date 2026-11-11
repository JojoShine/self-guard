import {Button,Typography} from 'antd';
type Guide={check:string;handle:string;verify:string;href?:string;label?:string};
const guides:Record<string,Guide>={
 vulnerability:{check:'核对实际安装版本、软件包修订、情报适用范围和清单时间；版本命中不等于已被利用。',handle:'由业务负责人安排补丁、升级或经核实的配置缓解；暂不处理时登记风险接受理由和到期时间。',verify:'取得更新后的软件清单，使用相同适用依据复查，记录目标、检查时间和结果。',href:'#scans',label:'查看扫描与复查计划'},
 'active-scan':{check:'核对获准目标、实际连接、模板、响应或证书证据；连通和握手观察不等于漏洞。',handle:'按具体命中条件由运维调整服务、证书或应用配置，先评估合法业务影响。',verify:'在原授权范围再次执行同类检查，核对问题消失和合法业务正常；失败或未知不能关闭。',href:'#scans',label:'查看主动检查'},
 suricata:{check:'核对实际连接、规则、实时或回放、时间及主机日志；采集主机不一定是受攻击目标。',handle:'确认是否为授权测试或正常业务；疑似攻击交安全人员调查，隔离或封禁通过既有授权变更流程执行。',verify:'核对后续活动、相关日志与业务状态；仅没有新告警不足以证明攻击已经结束。',href:'#network-sensors',label:'查看协议与入侵检测记录'},
 'access-observation':{check:'核对实例、账号、对象分类、实际请求响应、返回量和完整性；最终业务用户可能未知。',handle:'由数据或应用负责人核查合法用途，按授权调整账号、权限或应用逻辑；疑似泄露保全已获准证据并人工调查。',verify:'用授权用例核对异常操作受限、合法访问正常；未采集、正文过期或规则停用不等于问题解决。',href:'#data-access',label:'查看访问审计'},
 'database-security':{check:'核对原生审计动作、实际结果、实例范围和分类快照；权限检查结果不等于业务执行成功。',handle:'由实例负责人核查来源、账号、访问时段和配置，按变更流程修正权限或业务配置。',verify:'检查对应原生审计和授权用例；未取得结果或行数时保留未知，不以推算结果关闭。',href:'#database-audit',label:'查看数据库审计'},
};
const fallback:Guide={check:'核对检测来源、发生时间、受影响对象和实际依据；当前依据不足时继续核查。',handle:'记录负责人、已采取措施及外部执行结果；误报需说明理由，仍存在的风险不能仅修改状态掩盖。',verify:'按原检测依据进行独立复查，记录对象、时间、方法及实际结果；复查未通过继续处理。'};
export function FindingHandlingGuide({source}:{source?:string}){
 const guide=guides[source||'']||fallback;
 return <aside className="module-subsection module-stack" aria-label="核查与后续处理建议"><Typography.Text strong>核查与后续处理建议</Typography.Text><ol><li><strong>先核查：</strong>{guide.check}</li><li><strong>再处理：</strong>{guide.handle}</li><li><strong>最后复查：</strong>{guide.verify}</li></ol>{guide.href&&<Button href={guide.href}>{guide.label}</Button>}<Typography.Text type="secondary">以上是处理指引，不代表平台已经执行阻断、修复或复查。具体动作由授权人员确认。</Typography.Text></aside>;
}
