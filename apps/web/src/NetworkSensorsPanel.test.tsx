import {it,expect,vi} from 'vitest';import {renderToStaticMarkup} from 'react-dom/server';vi.mock('./api',()=>({api:vi.fn()}));
import {sensorHealth,NetworkSensorHealth,NetworkSensorEventDetails,type NetworkSensor,type NetworkSensorEvent} from './NetworkSensorsPanel';
const sensor:NetworkSensor={id:'source',name:'主机旁路',assetId:'asset',enabled:true,engineVersion:'8.0.6',ruleSetName:'ET Open',ruleSetVersion:'registered',updateEveryHours:24,evePath:'/var/log/suricata/eve.json',version:1,updatedAt:new Date().toISOString(),createdAt:new Date().toISOString(),health:{},stats:{},hasCredential:true,lastReportedAt:null,lastStatsAt:null,lastEventAt:null,lastMode:null};
it('never treats a configured source or reader heartbeat as healthy engine proof',()=>{
 expect(sensorHealth(sensor).label).toBe('等待采集器');const alive={...sensor,lastReportedAt:new Date().toISOString(),health:{status:'READING'}};expect(sensorHealth(alive).label).toBe('引擎健康待确认');expect(sensorHealth({...sensor,lastMode:'REPLAY'}).label).toBe('离线回放');expect(sensorHealth({...alive,lastStatsAt:new Date().toISOString(),stats:{}}).label).toBe('规则加载待确认');expect(sensorHealth({...alive,lastStatsAt:new Date().toISOString(),stats:{rulesLoaded:0}}).label).toBe('未加载检测规则');expect(sensorHealth({...alive,lastStatsAt:new Date().toISOString(),stats:{rulesFailed:1}}).label).toBe('规则加载异常');expect(sensorHealth({...alive,lastStatsAt:new Date().toISOString(),stats:{rulesLoaded:1},health:{rotationGaps:1}}).label).toBe('轮转边界待核对');
});
it('labels registered versions, file fingerprints and actual stats separately',()=>{
 const html=renderToStaticMarkup(<NetworkSensorHealth sensor={sensor}/>);for(const text of ['登记引擎版本','规则文件指纹','引擎加载规则数','未提供','不代表规则已经加载'])expect(html).toContain(text);
});
it('renders alert metadata as observations and supports bounded flow drilling without raw payload',()=>{
 const event:NetworkSensorEvent={id:'event',sensorId:'source',assetId:'asset',eventId:'a'.repeat(64),sourceSha256:'b'.repeat(64),occurredAt:new Date().toISOString(),eventType:'alert',mode:'REPLAY',flowId:'18446744073709551615',metadata:{alert:{signatureId:1,gid:1,rev:2,signature:'synthetic',severity:2,action:'allowed'}},sensor:{id:'source',name:'旁路',assetId:'asset'}};
 const html=renderToStaticMarkup(<NetworkSensorEventDetails event={event} onFlow={()=>{}}/>);for(const text of ['18446744073709551615','查看关联流量记录','不代表平台执行了阻断','规范化事件元数据','离线回放，不能作为当前攻击证明'])expect(html).toContain(text);expect(html).not.toContain('下载完整报文');
});

it('omits null ports from records without socket endpoints',()=>{const event:NetworkSensorEvent={id:'stats',sensorId:'source',assetId:'asset',eventId:'a'.repeat(64),sourceSha256:'b'.repeat(64),occurredAt:new Date().toISOString(),eventType:'stats',sourceIp:null,destinationIp:null,sourcePort:null,destinationPort:null,metadata:{stats:{uptime:2}},sensor:{id:'source',name:'旁路',assetId:'asset'}};const html=renderToStaticMarkup(<NetworkSensorEventDetails event={event} onFlow={()=>{}}/>);expect(html).not.toContain(':null');});

import {NetworkSensorsPanel} from './NetworkSensorsPanel';
it('shows protocol evidence first and keeps engine setup outside the daily view',()=>{
 vi.stubGlobal('location',{hash:'#network-sensors'});
 try{const html=renderToStaticMarkup(<NetworkSensorsPanel canManage/>);expect(html).toContain('协议记录');expect(html).toContain('采集配置');expect(html).toContain('查看安全告警');expect(html).not.toContain('传感器接入与健康');expect(html).not.toContain('重新签发配置');}finally{vi.unstubAllGlobals()}
});
it('opens source maintenance only through an explicit configuration view',()=>{
 vi.stubGlobal('location',{hash:'#network-sensors?view=configuration'});
 try{const html=renderToStaticMarkup(<NetworkSensorsPanel canManage/>);expect(html).toContain('返回协议记录');expect(html).toContain('重新签发配置');}finally{vi.unstubAllGlobals()}
});
