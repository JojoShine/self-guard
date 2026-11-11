import {Typography} from 'antd';
export function AccessCollectionGuide(){return <details className="module-subsection"><summary>接入步骤与协议覆盖边界</summary><div className="module-stack">
 <ol><li><strong>确认授权范围：</strong>选择主机、实例和实际端点，核实允许采集的请求响应、正文权限及容量。</li><li><strong>安装独立探针：</strong>基础 Agent 上报不等于访问探针已安装；下载私有来源配置，核对身份、版本与端点后按授权安装。</li><li><strong>核对配置确认：</strong>分别查看基础 Agent、探针版本、主机确认的配置版本和最近上报。重新下载配置会轮换来源凭据，应同步更新主机。</li><li><strong>验证有效请求与响应：</strong>由业务负责人发起获准用例，核对普通成功、失败、拒绝和异常记录，以及对象关联、完整性和队列缺口。</li></ol>
 <Typography.Paragraph>HTTP/1.1、MySQL、PostgreSQL、Redis 已有指定版本和场景验证；HTTP/2、复杂事务与查询、压缩、游标及订阅推送等仍有边界。Oracle、SQL Server、达梦和金仓沿用已有原生审计接入，不能按完整线协议请求响应支持理解。</Typography.Paragraph>
 <Typography.Paragraph>旁路网络采集不会自动解密 TLS。OpenSSL 进程观察需要固定进程及动态运行库，并按操作系统、内核、架构、库和协议逐组合验收；Agent 在线不等于 TLS 明文可读。完整结果以每条记录的实际证据和缺口为准。</Typography.Paragraph>
 <Typography.Text type="secondary">正文从捕获时间起保留七天，重传不续期；容量不足、过期及未支持路径不能解释为没有访问。首次核对完成后，再启用与业务匹配的检测规则。</Typography.Text>
 </div></details>}
