import {it,expect,vi} from 'vitest';import {renderToStaticMarkup} from 'react-dom/server';vi.mock('./api',()=>({api:vi.fn()}));
import {MonitoringSummary,MetricTrend} from './OperationalMonitoring';
it('distinguishes stale or missing data from healthy zero values',()=>{
 const html=renderToStaticMarkup(<MonitoringSummary state="STALE" lastSuccessAt="2026-11-10T00:00:00Z" lastError="连接检查失败"/>);expect(html).toContain('采集已过期');expect(html).toContain('连接检查失败');
 expect(renderToStaticMarkup(<MonitoringSummary state="NEEDS_AGENT_UPDATE"/>)).toContain('需要支持资源监控的采集版本');
 const chart=renderToStaticMarkup(<MetricTrend title="CPU使用率" points={[{at:'2026-11-10T00:00:00Z',value:0},{at:'2026-11-10T00:01:00Z',value:undefined}]}/>);expect(chart).toContain('CPU使用率');expect(chart).toContain('有效样本 1');expect(chart).not.toContain('NaN');
});

import {DatabaseRuntimeMetricView} from './OperationalMonitoring';
it('renders Redis identity, command metrics and unavailable memory without inventing values',()=>{
 const html=renderToStaticMarkup(<DatabaseRuntimeMetricView engine="redis" samples={[]} metric={{schema:'selfguard-database-metrics-v1',engine:'redis',database:'0',version:'7.4',capturedAt:'2026-11-11T00:00:00Z',status:'PARTIAL',issues:['MEMORY_LIMIT_UNSET'],connections:0,commandsPerSecond:12}}/>);
 expect(html).toContain('Redis 7.4');expect(html).toContain('命令速率');expect(html).toContain('未设置内存上限');expect(html).not.toContain('MEMORY_LIMIT_UNSET');expect(html).not.toContain('长查询数量');expect(html).not.toContain('锁等待会话');expect(html).not.toContain('提交 / 回滚速率');expect(html).toContain('未采集');expect(html).not.toContain('PostgreSQL');expect(html).not.toContain('NaN');
});

it('explains unavailable native metrics and unknown diagnostics without exposing machine codes',()=>{
 const html=renderToStaticMarkup(<DatabaseRuntimeMetricView engine="mysql" samples={[]} metric={{schema:'selfguard-database-metrics-v1',database:'app',version:'8.0',capturedAt:'2026-11-11T00:00:00Z',status:'PARTIAL',issues:['DATABASE_SIZE_UNAVAILABLE','LOCK_AND_QUERY_METRICS_UNAVAILABLE','FUTURE_NATIVE_GAP'],connections:1}}/>);
 expect(html).toContain('数据库容量统计不可读取');expect(html).toContain('锁等待和长查询统计不可读取');expect(html).toContain('该版本存在未识别的统计缺口，请核对采集诊断');expect(html).not.toContain('FUTURE_NATIVE_GAP');
});

it('puts concrete host gaps in the summary while preserving stale and unknown states',()=>{
 const html=renderToStaticMarkup(<MonitoringSummary state="PARTIAL" hostIssues={['FILESYSTEMS_PARTIAL']}/>);
 expect(html).toContain('部分挂载未采集');expect(html).not.toContain('部分指标未取得');
 const stale=renderToStaticMarkup(<MonitoringSummary state="STALE" hostIssues={['CPU_UNAVAILABLE','FUTURE_GAP']}/>);
 expect(stale).toContain('采集已过期');expect(stale).toContain('CPU统计不可读取');expect(stale).toContain('采集器报告了未识别的限制项');expect(stale).not.toContain('FUTURE_GAP');expect(stale).toContain('缺失值保持未知');
 expect(renderToStaticMarkup(<MonitoringSummary state="PARTIAL" hostIssues={[]}/>)).toContain('部分指标未取得');
});
