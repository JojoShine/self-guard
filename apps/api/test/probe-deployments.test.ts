import {test} from 'node:test';
import assert from 'node:assert/strict';
import {probeReadiness,probeDeploymentInput,accessInstallationConfig,assertProbeWriter} from '../src/probe-deployments';
const id='6bc04a33-c4cf-48e3-8282-9833e52d0b97';
test('probe scope rejects overrides and requires explicit network interface',()=>{
 assert.equal(probeDeploymentInput.safeParse({kind:'NETWORK',sourceId:id,action:'INSTALL'}).success,false);
 assert.equal(probeDeploymentInput.safeParse({kind:'NETWORK',sourceId:id,action:'INSTALL',interface:'eth0; reboot'}).success,false);
 assert.equal(probeDeploymentInput.safeParse({kind:'ACCESS',sourceId:id,action:'INSTALL',interface:'eth1'}).success,false);
 assert.equal(probeDeploymentInput.safeParse({kind:'ACCESS',sourceId:id,action:'INSTALL',version:2}).success,false);
 assert.equal(probeDeploymentInput.safeParse({kind:'ACCESS',sourceId:id,action:'STOP'}).success,true);
});
test('writes reject operators and disabled administrators',()=>{
 assert.throws(()=>assertProbeWriter({role:'OPERATOR',disabled:false,dataScope:{}}));
 assert.throws(()=>assertProbeWriter({role:'ADMIN',disabled:true,dataScope:{}}));
 assert.doesNotThrow(()=>assertProbeWriter({role:'ADMIN',disabled:false,dataScope:{}}));
});
test('network startup and replay cannot establish live engine readiness',()=>{
 const now=Date.now(),source={enabled:true,tokenHash:'token',lastReportedAt:new Date(now),lastMode:'LIVE',health:{status:'READING',detailCode:'OK',observedAt:new Date(now).toISOString(),invalidLines:0,skippedLines:0,rotationGaps:0,pendingEvents:0},lastStatsAt:null,ruleFile:null,expectedRuleSha256:null,stats:{}};
 assert.equal(probeReadiness({kind:'NETWORK',source},'asset',now).state,'WAITING');
 assert.equal(probeReadiness({kind:'NETWORK',source:{...source,lastStatsAt:new Date(now),lastMode:'REPLAY'}},'asset',now).state,'WAITING');
 assert.equal(probeReadiness({kind:'NETWORK',source:{...source,lastStatsAt:new Date(now)}},'asset',now).state,'READY');
 assert.equal(probeReadiness({kind:'NETWORK',source:{...source,lastStatsAt:new Date(now-180001)}},'asset',now).state,'WAITING');
 assert.equal(probeReadiness({kind:'NETWORK',source:{...source,lastStatsAt:new Date(now),expectedRuleSha256:'a'.repeat(64)}},'asset',now).state,'ERROR');
});
test('access readiness requires current identity and configuration heartbeat',()=>{
 const now=Date.now(),source={enabled:true,tokenHash:'token',issuedAssetTokenHash:'asset',version:2,lastReportAt:new Date(now),health:{state:'RUNNING',version:'0.1.6',configurationVersion:2}};
 assert.equal(probeReadiness({kind:'ACCESS',source},'asset',now).state,'READY');
 assert.equal(probeReadiness({kind:'ACCESS',source},'rotated',now).state,'ERROR');
 assert.equal(probeReadiness({kind:'ACCESS',source:{...source,version:3}},'asset',now).state,'ERROR');
 assert.equal(probeReadiness({kind:'ACCESS',source:{...source,lastReportAt:null}},'asset',now).state,'WAITING');
});
test('access installer uses exactly approved endpoint and bounded queue configuration',()=>{
 const source={id,assetId:id,maxQueueBytes:1048576,mode:'NETWORK',interface:'eth0',address:'192.0.2.1',port:5432,profile:{ignored:'not-for-network'}};
 const config=accessInstallationConfig(source,'secret',{server:'https://example.test',caCertificate:'CA'});
 assert.deepEqual(config.installation,{assetId:id,mode:'NETWORK',interface:'eth0',address:'192.0.2.1',port:5432});
 assert.equal(config.allowHTTP,false);assert.equal(config.maxQueueBytes,1048576);assert.equal(config.token,'secret');
});

test('engine dependency failure is not command success or readiness',async()=>{
 const {networkCommandResult}=await import('../src/probe-deployments');
 assert.equal(networkCommandResult(JSON.stringify({commandCompleted:false,error:'DOCKER_REQUIRED'}),'INSTALL')?.status,'FAILED');
 assert.equal(networkCommandResult(JSON.stringify({commandCompleted:false,error:'TimeoutExpired'}),'INSTALL')?.status,'UNKNOWN');
 assert.throws(()=>networkCommandResult('{}','INSTALL'));
 assert.equal(networkCommandResult(JSON.stringify({engineRunning:false,bridgeStatus:'inactive'}),'CHECK')?.status,'SUCCEEDED');
});

test('configured detection rules require successful live rule loading',()=>{
 const now=Date.now(),source={enabled:true,tokenHash:'token',lastReportedAt:new Date(now),lastMode:'LIVE',health:{status:'READING',detailCode:'OK',observedAt:new Date(now).toISOString(),invalidLines:0,skippedLines:0,rotationGaps:0,pendingEvents:0},lastStatsAt:new Date(now),ruleFile:'/approved.rules',expectedRuleSha256:null,stats:{}};
 for(const stats of [{},{rulesLoaded:0,rulesFailed:0},{rulesLoaded:3,rulesFailed:1},{rulesLoaded:3}])assert.equal(probeReadiness({kind:'NETWORK',source:{...source,stats}},'asset',now).state,'ERROR');
 assert.equal(probeReadiness({kind:'NETWORK',source:{...source,stats:{rulesLoaded:3,rulesFailed:0}}},'asset',now).state,'READY');
});

test('access check accepts only fixed environment results and never marks readiness',async()=>{
 const {accessCheckResult}=await import('../src/probe-deployments');
 for(const marker of ['NOT_INSTALLED','NOT_RUNNING','RUNNING']){
  const result=accessCheckResult('PROBE_CHECK_'+marker+'\n');assert.equal(result.status,'SUCCEEDED');assert.equal('readiness' in result,false);
 }
 for(const marker of ['ROOT_REQUIRED','SYSTEMD_REQUIRED'])assert.equal(accessCheckResult('PROBE_CHECK_'+marker).status,'FAILED');
 for(const output of ['active','constructor','PROBE_CHECK_RUNNING\nprivate text','PROBE_COMMAND_OK'])assert.throws(()=>accessCheckResult(output));
});
