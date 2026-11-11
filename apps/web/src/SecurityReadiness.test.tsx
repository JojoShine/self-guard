import {expect,it,vi} from 'vitest';
vi.mock('./api',()=>({api:vi.fn()}));
import {renderToStaticMarkup} from 'react-dom/server';
import {SecurityReadiness,SecurityReadinessView,type SecurityReadinessSummary} from './SecurityReadiness';
const empty:SecurityReadinessSummary={checkedAt:'2026-11-09T00:00:00Z',windowMinutes:60,agents:{registered:0,recent:0,neverReported:0,stale:0},instances:0,traffic:{configured:0,enabled:0,reporting:0,recentWindows:0},sensors:{configured:0,enabled:0,liveReporting:0,recentEngineStats:0,replay:0},access:{configured:0,enabled:0,reporting:0,recentEvents:0},nativeAudit:{recentEvents:0},scans:{configured:0,enabled:0,recentRuns:0,failedRuns:0},handling:{active:0,unassigned:0,verifying:0,overdue:0}};
it('shows separate collection facts and actionable zero-data guidance',()=>{
 const html=renderToStaticMarkup(<SecurityReadinessView summary={empty}/>);
 for(const text of ['尚未接入主机','尚未配置数据访问来源','尚未配置扫描计划','近期上报不代表采集完整','没有告警不代表已经完成检查'])expect(html).toContain(text);
 for(const path of ['enroll','network-hosts','network-sensors','data-access-sources','scans'])expect(html).toContain('#'+path);
 expect(html).not.toContain('安全率');
 expect(renderToStaticMarkup(<SecurityReadiness/>)).toContain('采集与检查覆盖');
});
it('keeps restricted and unavailable sections distinct from zero',()=>{
 const html=renderToStaticMarkup(<SecurityReadinessView summary={{...empty,access:null,sensors:null,nativeAudit:null,scans:null}}/>);
 expect(html).toContain('当前权限不提供此项汇总');expect(html).not.toContain('尚未配置数据访问来源');
});
