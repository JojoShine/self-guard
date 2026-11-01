import {test} from 'node:test';import assert from 'node:assert/strict';import {trafficCaptureInput} from '../src/traffic-capture';import {installationProfileInput,validateInstallationCompatibility} from '../src/installations';
test('traffic reports reject bodies, headers, unbounded budgets and non-address hosts',()=>{
 const sample={schema:'selfguard-traffic-v1',startedAt:new Date().toISOString(),endedAt:new Date().toISOString(),scope:{interface:'lo',protocol:'TCP',ports:[443],cidrs:[],durationSeconds:30,maxPackets:100,maxBytes:65536,snapLen:128,includePayload:false,retentionHours:0},flows:[{sourceIp:'127.0.0.1',destinationIp:'192.0.2.5',sourcePort:1234,destinationPort:443,protocol:'TCP',packets:1,wireBytes:60}],packets:1,examinedPackets:1,capturedBytes:60,socketDropped:0,complete:true,stopReason:'DURATION_ELAPSED',decryption:'NONE'};
 assert.equal(trafficCaptureInput.parse(sample).flows.length,1);assert.throws(()=>trafficCaptureInput.parse({...sample,body:'password'}));assert.throws(()=>trafficCaptureInput.parse({...sample,scope:{...sample.scope,durationSeconds:100000}}));assert.throws(()=>trafficCaptureInput.parse({...sample,flows:[{...sample.flows[0],sourceIp:'not-an-ip'}]}));
});
test('automatic Web onboarding cannot be silently offered to older agents',()=>{
 const v=installationProfileInput.parse({releaseId:'11111111-1111-4111-8111-111111111111',server:'https://security.example',hostWaf:{siteId:'22222222-2222-4222-8222-222222222222',nginxConfig:'/etc/nginx/conf.d/app.conf',entryUrl:'http://127.0.0.1/'}});
 assert.throws(()=>validateInstallationCompatibility(v,'0.4.4'));assert.doesNotThrow(()=>validateInstallationCompatibility(v,'0.4.9'));
});
