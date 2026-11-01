import {test} from 'node:test';import assert from 'node:assert/strict';
import {networkDefinition,networkRule,networkSamples,networkResult} from '../src/scan-network-contracts';
const rule={id:'owned-network',description:'明确的只读服务条件',kind:'TCP_BANNER',value:'legacy-service'};
test('network rules accept only finite read-only check kinds and bounded parameters',()=>{
 assert.ok(networkRule.safeParse(rule).success);assert.ok(networkDefinition.safeParse({kind:'NETWORK',protocol:'tcp',rule}).success);assert.equal(networkDefinition.safeParse({kind:'NETWORK',protocol:'tls',rule}).success,false);
 for(const value of [{...rule,command:'uname -a'},{...rule,kind:'PORT_RANGE'},{...rule,value:'界'.repeat(512)},{...rule,kind:'TCP_CONNECT'},{...rule,kind:'TLS_WEAK_PROTOCOL',value:'TLS1.3'},{...rule,kind:'TLS_CERT_EXPIRING',value:'',days:0}])assert.equal(networkRule.safeParse(value).success,false);
 assert.ok(networkRule.safeParse({id:rule.id,description:rule.description,kind:'TLS_CERT_EXPIRING',days:30}).success);
});
test('network template samples require explicit positive and negative observations',()=>{
 const positive={name:'应命中',expectedMatched:true,connected:true,banner:'legacy-service\r\n'},negative={name:'应不命中',expectedMatched:false,connected:true,banner:'current-service\r\n'};assert.ok(networkSamples.safeParse([positive,negative]).success);assert.equal(networkSamples.safeParse([positive,positive]).success,false);assert.equal(networkSamples.safeParse([positive,{...negative,command:'whoami'}]).success,false);assert.equal(networkSamples.safeParse([positive,{...negative,banner:'界'.repeat(4096)}]).success,false);
});
test('network evidence keeps actual socket and observation separate from confirmed risk',()=>{
 const evidence={ruleId:rule.id,description:rule.description,checkKind:'TCP_CONNECT',hostname:'fixture.test',port:8080,protocol:'tcp',startedAt:'2026-11-01T00:00:00Z',durationMs:1,connections:[{source:'172.20.0.2:49152',destination:'172.20.0.3:8080',transport:'TCP'}],connectedPeers:['172.20.0.3:8080']};assert.ok(networkResult.safeParse({outcome:'OBSERVED',reason:'CONNECTION_OBSERVED',evidence}).success);assert.equal(networkResult.safeParse({outcome:'CONFIRMED',evidence}).success,false);assert.equal(networkResult.safeParse({outcome:'OBSERVED',evidence:{...evidence,connections:[]}}).success,false);assert.equal(networkResult.safeParse({outcome:'OBSERVED',evidence:{...evidence,connectedPeers:['172.20.0.4:8080']}}).success,false);
 assert.ok(networkResult.safeParse({outcome:'CONFIRMED',evidence:{...evidence,checkKind:'TCP_BANNER',bannerSha256:'a'.repeat(64),bannerBytes:16,bannerPreview:'legacy-service\r\n'}}).success);
});
