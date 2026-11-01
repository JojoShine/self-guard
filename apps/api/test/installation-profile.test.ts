import 'reflect-metadata';import {test} from 'node:test';import assert from 'node:assert/strict';import {installationProfileInput,validateInstallationCompatibility} from '../src/installations';
const base={releaseId:'12345678-1234-4234-9234-123456789abc',server:'https://guard.example'};
test('installation collection scopes, proxy, state and resource budgets are explicit and bounded',()=>{
 const input={...base,stateDir:'/var/lib/selfguard-agent-production',proxyUrl:'http://proxy.example:3128',collectionRoot:'/srv/data',fimPaths:['/srv/data/config'],logPaths:['/srv/data/access.log'],maxCPUs:2,maxMemoryBytes:256*1048576,maxQueueBytes:16*1048576,bytesPerSecond:65536,cpuQuotaPercent:30};assert.equal(installationProfileInput.safeParse(input).success,true);
 for(const change of [{stateDir:'/etc/agent'},{stateDir:'/var/lib/selfguard-agent/../other'},{proxyUrl:'http://user:secret@proxy.example'},{proxyUrl:'file:///tmp/proxy'},{fimPaths:['/etc/shadow']},{logPaths:['/srv/database/other']},{collectionRoot:'/'},{maxMemoryBytes:1024},{cpuQuotaPercent:101},{maxCPUs:0}])assert.equal(installationProfileInput.safeParse({...input,...change}).success,false,JSON.stringify(change));
 assert.equal(installationProfileInput.safeParse({...base,fimPaths:['/srv/data/config']}).success,false);
});

test("older signed agents cannot silently ignore advanced installation settings",()=>{const defaults=installationProfileInput.parse(base);assert.doesNotThrow(()=>validateInstallationCompatibility(defaults,"0.2.6"));assert.throws(()=>validateInstallationCompatibility({...defaults,proxyUrl:"http://proxy.example:3128"},"0.2.6"));assert.throws(()=>validateInstallationCompatibility({...defaults,collectionRoot:"/srv/data"},"0.2.10"));assert.doesNotThrow(()=>validateInstallationCompatibility({...defaults,stateDir:"/var/lib/selfguard-agent-custom"},"0.3.0"));});

test('proxy mode choices are explicit, coherent and only available on capable signed versions',()=>{
 for(const proxyMode of ['DIRECT','ENVIRONMENT'])assert.equal(installationProfileInput.safeParse({...base,proxyMode}).success,true);
 assert.equal(installationProfileInput.safeParse({...base,proxyMode:'EXPLICIT',proxyUrl:'http://proxy.example:3128'}).success,true);
 for(const change of [{proxyMode:'EXPLICIT'},{proxyMode:'DIRECT',proxyUrl:'http://proxy.example:3128'},{proxyMode:'ENVIRONMENT',proxyUrl:'http://proxy.example:3128'},{proxyMode:'unexpected'}])assert.equal(installationProfileInput.safeParse({...base,...change}).success,false);
 const selected=installationProfileInput.parse({...base,proxyMode:'DIRECT'});assert.throws(()=>validateInstallationCompatibility(selected,'0.3.8'));assert.doesNotThrow(()=>validateInstallationCompatibility(selected,'0.3.9'));
});

test('application metadata inputs require explicit read scope and a capable signed agent',()=>{
 const selected={...base,collectionRoot:'/srv/apps',applicationInputs:[{format:'GO_BINARY',path:'/srv/apps/payment'}]};const parsed=installationProfileInput.parse(selected);assert.throws(()=>validateInstallationCompatibility(parsed,'0.3.9'));assert.doesNotThrow(()=>validateInstallationCompatibility(parsed,'0.4.0'));
 for(const applicationInputs of [[{format:'SHELL',path:'/srv/apps/code'}],[{format:'GO_BINARY',path:'/etc/shadow'}],[{format:'GO_BINARY',path:'/srv/apps/../secret'}],[{format:'GO_BINARY',path:'/srv/apps/payment'},{format:'GO_BINARY',path:'/srv/apps/payment'}]])assert.equal(installationProfileInput.safeParse({...selected,applicationInputs}).success,false);
});

test("prefixed platform requires a signed installer with prefix support",()=>{const input=installationProfileInput.parse({...base,server:"https://tbtparent.me/self-guard"});assert.throws(()=>validateInstallationCompatibility(input,"0.4.10"));assert.doesNotThrow(()=>validateInstallationCompatibility(input,"0.4.11"));});
