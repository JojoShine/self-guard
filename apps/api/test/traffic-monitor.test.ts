import {test} from 'node:test';import assert from 'node:assert/strict';
import {monitorStartInput,monitorReportInput,monitorServiceCommand,supportsTrafficMonitor} from '../src/traffic-monitor-contract';
import {monitorIdentityCheckScript,trafficMonitorDiagnostic,monitorReportedState} from '../src/traffic-monitor-contract';
import {mkdtempSync,writeFileSync,rmSync} from 'node:fs';import {tmpdir} from 'node:os';import {join} from 'node:path';import {spawnSync} from 'node:child_process';
test('startup checks the installed Agent identity without exposing its credential',()=>{
 const dir=mkdtempSync(join(tmpdir(),'monitor-binding-'));
 try{
  writeFileSync(join(dir,'request'),JSON.stringify({assetId:id}));writeFileSync(join(dir,'collector'),JSON.stringify({StateDir:dir,Server:'https://other.invalid'}));
  const check=(assetId:string)=>{writeFileSync(join(dir,'identity.json'),JSON.stringify({assetId,token:'private-fixture-token'}));return spawnSync('python3',['-c',monitorIdentityCheckScript,join(dir,'request'),join(dir,'collector')],{encoding:'utf8'})};
  const mismatch=check('22345678-1234-4234-9234-123456789abc');assert.notEqual(mismatch.status,0);assert.match(mismatch.stderr,/SELFGUARD_MONITOR_FAILED:IDENTITY/);assert.doesNotMatch(mismatch.stdout+mismatch.stderr,/private-fixture-token|other.invalid/);
  const valid=check(id);assert.equal(valid.status,0,valid.stderr);
 }finally{rmSync(dir,{recursive:true,force:true})}
});
test('monitor startup failures retain fixed actionable diagnostics rather than arbitrary remote output',()=>{
 assert.equal(trafficMonitorDiagnostic('SELFGUARD_MONITOR_FAILED:IDENTITY\n')?.uncertain,false);
 assert.match(trafficMonitorDiagnostic('SELFGUARD_MONITOR_FAILED:SERVICE\n')!.detail,/Agent/);
 assert.equal(trafficMonitorDiagnostic('secret remote error'),undefined);
});
test('unacknowledged starts become unknown after two minutes without falsely declaring stopped',()=>{
 const monitor={status:'STARTING',desiredState:'RUNNING',createdAt:new Date(1000),lastReportAt:null,detail:'waiting'};
 assert.equal(monitorReportedState(monitor,121001).status,'UNKNOWN');assert.equal(monitorReportedState(monitor,121001).desiredState,'RUNNING');
 assert.equal(monitorReportedState(monitor,120000).status,'STARTING');assert.equal(monitorReportedState({...monitor,lastReportAt:new Date()},121001).status,'STARTING');
 assert.equal(monitorReportedState({...monitor,status:'RUNNING'},121001).status,'RUNNING');
});
const id='12345678-1234-4234-9234-123456789abc';
test('continuous scope has no client-controlled total duration or payload permission',()=>{const input={interface:'eth0',protocol:'TCP_UDP',ports:[443],cidrs:[]};assert.deepEqual(monitorStartInput.parse(input),input);for(const extra of [{durationSeconds:30},{includePayload:true},{interface:'eth0; id'},{ports:[]},{cidrs:['10.0.0.0/33']}])assert.equal(monitorStartInput.safeParse({...input,...extra}).success,false);});
test('reports carry bounded monotonic identity and explicit lifecycle without raw payload',()=>{const v={schema:'selfguard-traffic-monitor-v1',monitorId:id,status:'RUNNING',sequence:1,updatedAt:new Date().toISOString(),detail:'持续监测',droppedWindows:0};assert.equal(monitorReportInput.parse(v).status,'RUNNING');for(const extra of [{sequence:0},{sequence:2147483648},{payload:'secret'},{status:'SUCCESS'},{monitorId:'../bad'}])assert.equal(monitorReportInput.safeParse({...v,...extra}).success,false);});
test('service management keeps the privilege boundary and has no total-runtime timer',()=>{assert.equal(supportsTrafficMonitor({agentDiagnostics:{version:'0.4.14'}}),false);assert.equal(supportsTrafficMonitor({agentDiagnostics:{version:'0.4.18'}}),true);const command=monitorServiceCommand();assert.match(command,/--monitor-traffic/);assert.match(command,/Restart=on-failure/);assert.match(command,/systemctl enable selfguard-traffic-monitor\.service/);assert.match(command,/systemctl start selfguard-traffic-monitor\.service/);assert.equal(supportsTrafficMonitor({agentDiagnostics:{version:'0.4.16'}}),false);assert.match(command,/MemoryLimit=134217728/);assert.match(command,/CPUQuota=10%/);assert.doesNotMatch(command,/RuntimeMaxSec|StrictHostKeyChecking=no/);});
