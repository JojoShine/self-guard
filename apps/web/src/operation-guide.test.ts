/// <reference types="vite/client" />
import {it,expect} from 'vitest';
import guide from './content/operation-guide.md?raw';
it('documents core observation paths and locally reachable configuration',()=>{for(const text of ['接入与查看主机','漏洞检查与结果核对','数据实例、分类与访问','核查异常与证据','漏洞数据源','采集配置','扫描配置'])expect(guide).toContain(text);});
it('teaches complete server/database monitoring and acceptance with diagrams',()=>{for(const text of ['交付前准备','资源监控','运行监控','只读监控账号','如何确认监控正常','交付验收清单','采集延迟'])expect(guide).toContain(text);expect(guide.match(/```mermaid/g)?.length).toBeGreaterThanOrEqual(3)});
it('states retired scope and evidence limits without teaching old workflows',()=>{for(const text of ['不提供自研 WAF','正文从捕获时间起保留7天','查看和导出正文分别需要授权','最终业务用户没有可信证据时保持未知'])expect(guide).toContain(text);for(const text of ['创建关联修复任务','站点接入到安全阻断','从风险到修复闭环'])expect(guide).not.toContain(text);});

it('explains the independent CVE and KEV workspace without claiming full detection',()=>{for(const text of ['漏洞管理','CVE与在野漏洞如何管理','使用与覆盖','修复后更新清单并复扫','不承诺覆盖全部CVE'])expect(guide).toContain(text)});

it('teaches all three detection layers and deferred Web target enrollment',()=>{for(const t of ['服务器组件、应用与Web分别怎么扫','检测规则库','node_modules','0.4.23','暂时没有Web目标'])expect(guide).toContain(t)});

it('teaches generic rules and native compile limits without a brand workflow',()=>{for(const text of ['通用扫描','原生编译','不支持','固定','正反样本'])expect(guide).toContain(text);expect(guide).not.toContain('常用中间件检测');expect(guide.match(/```mermaid/g)?.length).toBe(7)});
it('explains database automatic onboarding without automatic restart or invented SQL',()=>{for(const text of ['数据库自动接入','准备重启后接入','重新检查并继续','不自动制造演示查询','其他引擎使用“已有日志文件”','独立审计入库隔离未就绪时不可启用'])expect(guide).toContain(text)});
it('explains packet SQL request semantics and TLS without treating missing evidence as no SQL',()=>{for(const text of ['从访问流量查看 SQL 请求','清空筛选不会移除实例','不插值绑定参数','不得关闭数据库 TLS','不证明执行成功或事务提交'])expect(guide).toContain(text)});
