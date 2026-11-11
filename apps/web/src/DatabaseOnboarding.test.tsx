import {expect,it,vi} from 'vitest';
import {renderToStaticMarkup} from 'react-dom/server';
import instanceSource from './DatabaseInstancesPanel.tsx?raw';
import auditSource from './DatabaseAuditPanel.tsx?raw';
import monitoringSource from './OperationalMonitoring.tsx?raw';
vi.mock('./api',()=>({api:vi.fn()}));
import {DatabaseCollectionEvidenceView} from './DatabaseCollectionStatus';
import {engineOptions} from './database-presentation';
it('offers Vastbase and opens the saved instance acceptance workspace',()=>{
 expect(engineOptions.some(o=>o.value==='vastbase')).toBe(true);
 const source=instanceSource;
 expect(source).toContain('setDetail(created)');expect(source).toContain('接入与验收');
 expect(source).toContain('<DatabaseAuditPanel instanceId={detail.id}');
});
it('shows statement receipts separately from connection receipts and retained text',()=>{
 const html=renderToStaticMarkup(<DatabaseCollectionEvidenceView value={{checkedAt:'2026-11-11T00:00:00Z',windowMinutes:60,sources:1,hosts:{authorized:1,reporting:1},recentEvents:10,latestEventAt:null,connections:{recentEvents:10,latestEventAt:null},statements:{sources:1,recentEvents:0,latestEventAt:null,retainedTextRecords:0},operations:{recentEvents:0}}}/>);
 expect(html).toContain('连接审计');expect(html).toContain('等待语句入库');expect(html).toContain('保留原文');
});
it('pins embedded audit requests even when clearing filters and uses command vocabulary',()=>{
 const source=auditSource;
 expect(source).toContain('instanceId:instanceId||filters.instanceId');expect(source).toContain("statementKind==='COMMAND'");expect(source).toContain('disabled={!!instanceId}');
});
it('saves before checking and displays generic memory metrics without a zero fallback',()=>{
 const source=monitoringSource;
 expect(source).toContain('保存并验证连接');expect(source).toContain('await check(false)');expect(source).toContain('metric.memoryPercent');expect(source).toContain('metric.issues');
});
it('retains a standalone instance deep link while setting embedded instance context',()=>{
 expect(auditSource).toContain('if(instanceId){setFilters({instanceId})');
});

import {DatabaseCapabilityView} from './DatabaseCapabilities';
it('explains adapter readiness without presenting internal status codes as instance verification',()=>{
 const html=renderToStaticMarkup(<DatabaseCapabilityView value={{engine:'oracle',name:'Oracle',runtime:{supported:true,requirements:['独立统计账号'],message:'显式验证连接',validation:'ADAPTER_PROFILE'},rawStatement:{supported:true,kind:'SQL',formats:[],message:'显式选择来源'},auditFormats:[],notes:['不会自动重启']}}/>);
 expect(html).toContain('当前实例版本待实测');expect(html).not.toContain('ADAPTER_PROFILE');expect(html).toContain('独立统计账号');
});

it('distinguishes host reporting from raw format collector readiness',()=>{
 const html=renderToStaticMarkup(<DatabaseCollectionEvidenceView engine="redis" value={{checkedAt:'2026-11-11T00:00:00Z',windowMinutes:60,sources:1,hosts:{authorized:1,reporting:1},recentEvents:0,latestEventAt:null,statements:{collectors:{required:1,ready:0},sources:1,recentEvents:0,latestEventAt:null,retainedTextRecords:0}}}/>);
 expect(html).toContain('原文采集器能力待确认');expect(html).toContain('Agent0.4.24');
});
