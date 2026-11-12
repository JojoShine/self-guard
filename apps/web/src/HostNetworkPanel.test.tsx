import {it,expect,vi} from 'vitest';vi.mock('./api',()=>({api:vi.fn()}));import {renderToStaticMarkup} from 'react-dom/server';import {HostNetworkReport} from './HostNetworkPanel';
it('explains packet evidence and bounded capture without implying WAF protection',()=>{const html=renderToStaticMarkup(<HostNetworkReport data={{capture:{startedAt:'2026-11-01T00:00:00Z',endedAt:'2026-11-01T00:00:01Z',scope:{interface:'eth0',protocol:'TCP',ports:[443]},packets:1,socketDropped:2,complete:false,stopReason:'BYTE_LIMIT',flows:[{sourceIp:'192.0.2.1',sourcePort:1234,destinationIp:'198.51.100.2',destinationPort:443,protocol:'TCP',packets:1,wireBytes:60}]}}}/>);for(const text of ['到达字节上限','192.0.2.1','198.51.100.2','不解密 HTTPS','本次捕获有范围或预算限制'])expect(html).toContain(text);expect(html).not.toContain('record-title-link');});
it('empty captures are shown honestly',()=>{expect(renderToStaticMarkup(<HostNetworkReport data={{}}/>)).toContain('尚未上报流量捕获');});

import {afterEach} from 'vitest';
import {TrafficCaptureContent,TrafficMonitorReport,pollTrafficMonitor,trafficMonitorNeedsPolling,type TrafficMonitor,type TrafficMonitorData} from './HostNetworkPanel';
const monitor:TrafficMonitor={id:'monitor-1',status:'STARTING',desiredState:'RUNNING',detail:'正在等待主机确认',config:{interface:'eth0',protocol:'TCP_UDP',ports:[443],cidrs:[]},lastReportAt:null,lastSequence:0,droppedWindows:0};
const monitoring=(value:TrafficMonitor|null=monitor):TrafficMonitorData=>({monitor:value,windows:{items:[],total:0,page:1,pageSize:10}});
it('offers collection configuration beside an unconfigured monitor only when a management action is supplied',()=>{
 const props={monitor:null,windows:monitoring(null).windows};
 const manageable=renderToStaticMarkup(<TrafficMonitorReport {...props} onConfigure={()=>{}}/>);
 expect(manageable).toMatch(/<button[^>]*>[\s\S]*?配置持续监控[\s\S]*?<\/button>/);
 expect(manageable).toContain('约一分钟');
 const readOnly=renderToStaticMarkup(<TrafficMonitorReport {...props}/>);
 expect(readOnly).not.toContain('配置持续监控</span>');
});
afterEach(()=>vi.useRealTimers());
it('defaults to continuous monitoring with temporary capture available separately and no total duration',()=>{
 const html=renderToStaticMarkup(<TrafficCaptureContent record={{id:'asset-1',hostname:'test-host'}}/>);
 expect(html).toContain('持续监控');expect(html).toContain('临时抓包 / 排障');expect(html).toContain('启用一次，持续监控直到明确停止');expect(html).toContain('0.4.18');
 expect(html).not.toContain('捕获时长（秒）');expect(html).not.toContain('最多保留报文数');expect(html).not.toContain('durationSeconds');
});
it('makes arbitrary and multiple port entry explicit instead of presenting presets as the only choices',()=>{
 const html=renderToStaticMarkup(<TrafficCaptureContent record={{id:'asset-1',hostname:'test-host'}}/>);
 expect(html).toContain('输入端口，例如 8080、9000');expect(html).toContain('按回车添加');expect(html).toContain('逗号或空格');expect(html).toContain('来源或目标任一端口匹配');expect(html).toContain('最多16个');
});
it('shows start and stop as awaiting host acknowledgement, never completed prematurely',()=>{
 const starting=renderToStaticMarkup(<TrafficMonitorReport monitor={monitor} windows={monitoring().windows}/>);
 expect(starting).toContain('正在启用，等待主机确认');expect(starting).toContain('尚未收到主机上报');expect(starting).not.toContain('主机已确认停止');
 const stopping=renderToStaticMarkup(<TrafficMonitorReport monitor={{...monitor,status:'STOPPING',desiredState:'STOPPED'}} windows={monitoring().windows}/>);
 expect(stopping).toContain('正在停止，等待主机确认');expect(stopping).toContain('尚未收到主机停止确认');expect(stopping).not.toContain('主机已确认停止');
 expect(trafficMonitorNeedsPolling({...monitor,status:'STOPPING',desiredState:'STOPPED'})).toBe(true);
 expect(trafficMonitorNeedsPolling({...monitor,status:'STOPPED',desiredState:'STOPPED'})).toBe(false);
});
it('shows the actual startup failure without requiring technical details to be opened',()=>{
 const html=renderToStaticMarkup(<TrafficMonitorReport monitor={{...monitor,status:'FAILED',desiredState:'STOPPED',detail:'主机 Agent 绑定的是其他平台，未启动'}} windows={monitoring().windows}/>);
 const beforeDetails=html.split('<details')[0];expect(beforeDetails).toContain('主机 Agent 绑定的是其他平台，未启动');expect(beforeDetails).toContain('role="alert"');
});
it('expands historical connection evidence only after a record is selected',()=>{
 const record:TrafficMonitorData['windows']['items'][number]={id:'window-1',sequence:1,startedAt:'2026-11-04T00:00:00Z',endedAt:'2026-11-04T00:01:00Z',summary:{packets:1,socketDropped:3,complete:false,stopReason:'PACKET_LIMIT',flows:[{sourceIp:'192.0.2.1',sourcePort:1234,destinationIp:'198.51.100.2',destinationPort:443,protocol:'TCP',packets:1,wireBytes:60}]}};
 const props={monitor:{...monitor,status:'RUNNING' as const,droppedWindows:2},windows:{items:[record],total:1,page:1,pageSize:10}};
 const collapsed=renderToStaticMarkup(<TrafficMonitorReport {...props}/>);expect(collapsed).not.toContain('192.0.2.1');expect(collapsed).toContain('查看连接明细');
 const html=renderToStaticMarkup(<TrafficMonitorReport {...props} selected={record}/>);
 for(const text of ['丢弃了 2 个汇总时段','达到包数预算','内核丢包 3','192.0.2.1','198.51.100.2'])expect(html).toContain(text);
});
it('polls pending states, then stops after the host acknowledges stop',async()=>{
 vi.useFakeTimers();const load=vi.fn().mockResolvedValueOnce(monitoring()).mockResolvedValueOnce(monitoring({...monitor,status:'STOPPING',desiredState:'STOPPED'})).mockResolvedValueOnce(monitoring({...monitor,status:'STOPPED',desiredState:'STOPPED'}));const onData=vi.fn(),onError=vi.fn();
 const dispose=pollTrafficMonitor(load,onData,onError);await vi.advanceTimersByTimeAsync(10000);expect(load).toHaveBeenCalledTimes(3);expect(onData).toHaveBeenCalledTimes(3);expect(onError).not.toHaveBeenCalled();await vi.advanceTimersByTimeAsync(20000);expect(load).toHaveBeenCalledTimes(3);dispose();
});
it('cleans up pending polling timers when the view closes',async()=>{
 vi.useFakeTimers();const load=vi.fn().mockResolvedValue(monitoring());const dispose=pollTrafficMonitor(load,vi.fn(),vi.fn());await vi.advanceTimersByTimeAsync(0);dispose();await vi.advanceTimersByTimeAsync(30000);expect(load).toHaveBeenCalledTimes(1);
});
it('ignores in-flight responses after cleanup',async()=>{
 vi.useFakeTimers();let resolve:((value:TrafficMonitorData)=>void)|undefined;const onData=vi.fn(),onError=vi.fn();const load=vi.fn(()=>new Promise<TrafficMonitorData>(done=>{resolve=done}));const dispose=pollTrafficMonitor(load,onData,onError);dispose();resolve?.(monitoring());await vi.advanceTimersByTimeAsync(10000);expect(onData).not.toHaveBeenCalled();expect(onError).not.toHaveBeenCalled();expect(load).toHaveBeenCalledTimes(1);
});
it('keeps the last state and retries after a network error',async()=>{
 vi.useFakeTimers();const load=vi.fn().mockRejectedValueOnce(new Error('offline')).mockResolvedValueOnce(monitoring({...monitor,status:'STOPPED',desiredState:'STOPPED'}));const onData=vi.fn(),onError=vi.fn();const dispose=pollTrafficMonitor(load,onData,onError);await vi.advanceTimersByTimeAsync(0);expect(onError).toHaveBeenCalledWith(expect.objectContaining({message:'offline'}));expect(onData).not.toHaveBeenCalled();await vi.advanceTimersByTimeAsync(5000);expect(onData).toHaveBeenCalledOnce();dispose();
});

it('explains interval aggregates with directional counts, bytes and honest average rates',()=>{
 const windows:TrafficMonitorData['windows']={items:[{id:'w',sequence:3,startedAt:'2026-11-06T00:00:00Z',endedAt:'2026-11-06T00:01:00Z',summary:{packets:2,socketDropped:0,complete:true,stopReason:'WINDOW_ELAPSED',flows:[{sourceIp:'10.0.0.1',sourcePort:40000,destinationIp:'10.0.0.2',destinationPort:443,protocol:'TCP',packets:2,wireBytes:7500}]}}],total:1,page:1,pageSize:10};
 const html=renderToStaticMarkup(<TrafficMonitorReport monitor={monitor} windows={windows}/>);
 for(const text of ['连接与流量记录','通信方向数','合计流量','平均速率','每条记录汇总','不是单次请求','1.00 kbps'])expect(html).toContain(text);expect(html).not.toContain('历史监控窗口');
});
it('distinguishes continuous budget rollover from historical gaps and real kernel drops',()=>{
 const window={id:'budget',sequence:1,startedAt:'2026-11-12T00:00:00Z',endedAt:'2026-11-12T00:00:01Z',summary:{packets:8192,socketDropped:0,complete:true,stopReason:'BUDGET_ROLLOVER',flows:[]}};
 const render=(summary=window.summary)=>renderToStaticMarkup(<TrafficMonitorReport monitor={{...monitor,status:'RUNNING'}} selected={{...window,summary}} windows={{items:[{...window,summary}],total:1,page:1,pageSize:10}}/>);
 expect(render()).toContain('持续采集已转入下一窗口');expect(render()).not.toContain('此时段的连接证据存在缺口');
 expect(render({...window.summary,complete:false,socketDropped:3})).toContain('内核丢包 3');
 expect(render({...window.summary,complete:false,stopReason:'BYTE_LIMIT'})).toContain('达到字节预算');
});
