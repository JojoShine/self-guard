import {test} from 'node:test';
import assert from 'node:assert/strict';
import {accessSourceInput,accessCollectionState,accessRuleInput,accessRuleMatches} from '../src/access-observation';
import {accessEventInput} from '../src/access-contract';
test('sensitive reads can require excessive returns while normal and unknown reads remain audit only',()=>{
 const rule=accessRuleInput.parse({id:'sensitive-export',name:'敏感数据超量读取',category:'BEHAVIOR',detector:'SENSITIVE_READ',severity:'MEDIUM',minimumLevel:3,minimumBytes:1000});
 const event=accessEventInput.parse({eventId:'6bc04a33-c4cf-48e3-8282-9833e52d0b97',startedAt:new Date().toISOString(),endedAt:new Date().toISOString(),sessionId:'session',operation:'SELECT',result:'SUCCESS',completeness:'PARTIAL',gaps:['BODY_NOT_CAPTURED'],requestBytes:0,responseBytes:999,objects:[],chunks:[]});
 assert.equal(accessRuleMatches(rule,event,5),false);assert.equal(accessRuleMatches(rule,{...event,responseBytes:1000},5),true);assert.equal(accessRuleMatches(rule,{...event,responseBytes:1000,result:'UNKNOWN'},5),false);assert.equal(accessRuleMatches(rule,{...event,responseBytes:1000},null),false);
});
test('source collection state separates authorization, actual heartbeat and configuration confirmation',()=>{
 const now=Date.now(),source={enabled:true,credentialValid:true,version:2,lastReportAt:new Date(now),health:{state:'RUNNING',version:'0.1.2',configurationVersion:2}};
 assert.equal(accessCollectionState(source,now).state,'RUNNING');
 assert.equal(accessCollectionState({...source,lastReportAt:new Date(now-180001)},now).state,'STALE');
 assert.equal(accessCollectionState({...source,enabled:false},now).state,'DISABLED');
 assert.equal(accessCollectionState({...source,credentialValid:false},now).state,'IDENTITY_INVALID');
 assert.equal(accessCollectionState({...source,credentialValid:false,credentialIssued:false},now).state,'CONFIG_REQUIRED');
 assert.equal(accessCollectionState({...source,lastReportAt:null},now).state,'AWAITING_PROBE');
 assert.equal(accessCollectionState({...source,health:{...source.health,configurationVersion:1}},now).state,'CONFIG_MISMATCH');
});
test('a plaintext process source requires an explicitly pinned process and runtime profile',()=>{
 const base={name:'tls-source',assetId:'6bc04a33-c4cf-48e3-8282-9833e52d0b97',protocol:'HTTP',mode:'PLAINTEXT_EVENTS',interface:'process',address:'127.0.0.1',port:443,enabled:false,rules:[]};
 assert.equal(accessSourceInput.safeParse(base).success,false);
 assert.equal(accessSourceInput.safeParse({...base,profile:{kind:'OPENSSL_DYNAMIC',libraryPath:'/usr/lib64/libssl.so.3',pid:1234,uid:1001,startTicks:'123456',executableSha256:'a'.repeat(64),librarySha256:'b'.repeat(64),executableIdentity:'1:2:3:4:5',libraryIdentity:'1:2:3:4:5'}}).success,true);
 for(const profile of [{kind:'ANY'},{kind:'OPENSSL_DYNAMIC',pid:0,uid:0,startTicks:'1',executableSha256:'a'.repeat(64),librarySha256:'b'.repeat(64)}])assert.equal(accessSourceInput.safeParse({...base,profile}).success,false);
});
import {storageInput} from '../src/storage';
test('effective access storage reuses managed quotas and index retention, distinct from fixed seven-day bodies',()=>{
 assert.equal(storageInput.safeParse({effectiveAccessLimit:200000,effectiveAccessDays:30,accessEvidenceQuotaGiB:10}).success,true);
 for(const value of [{effectiveAccessDays:0},{accessEvidenceQuotaGiB:0},{effectiveAccessLimit:1}])assert.equal(storageInput.safeParse(value).success,false);
});
