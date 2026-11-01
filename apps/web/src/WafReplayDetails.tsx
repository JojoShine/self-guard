import {Alert,Descriptions,Typography} from 'antd';import {EvidenceView} from './EvidenceView';import {wafReplayOutcome} from './waf-replay';
export function WafReplayDetails({value}:{value:any}){const result=value.result;return <div className="module-stack">{value.validation&&<Alert type={value.validation.passed?'success':'warning'} showIcon message={value.validation.passed?'样本符合预期，已留存验证依据':'样本与预期不符，不能作为发布通过依据'}/>}<Alert type={wafReplayOutcome(result).type} showIcon message={wafReplayOutcome(result).title} description={value.basis}/><Descriptions column={1} bordered size="small" items={[
 {key:'coverage',label:'检查完整性',children:result.incomplete?.length?'检查不完整：'+result.incomplete.join('、'):'样本解析与已支持语义执行完成'},
 {key:'score',label:'异常评分',children:result.score},
 {key:'status',label:'阻断策略响应码',children:result.blocked?result.status??'来源未提供':'样本未触发阻断响应'},
 {key:'matches',label:'匹配指令',children:(result.matches||[]).join('、')||'无'},
 ]}/><Typography.Paragraph type="secondary">响应码来自本次规则决策，样本不会发往上游。命中依据保留实际变量位置和内容摘要，便于与上方输入核对。</Typography.Paragraph><EvidenceView value={result.evidence} title="实际命中依据"/>{result.omittedEvidence>0&&<Typography.Text type="secondary">另有 {result.omittedEvidence} 项匹配依据超过本次展示预算。</Typography.Text>}</div>}
