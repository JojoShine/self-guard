import 'reflect-metadata';import {test} from 'node:test';import assert from 'node:assert/strict';
import {validateNetworkSamples} from '../src/scan-network-worker';
const definition={kind:'NETWORK',protocol:'tcp',rule:{id:'owned-banner',description:'Only match an explicitly authored service marker',kind:'TCP_BANNER',value:'legacy-service'}},samples=[{name:'Should match',expectedMatched:true,connected:true,banner:'owned legacy-service\r\n'},{name:'Should not match',expectedMatched:false,connected:true,banner:'owned current-service\r\n'}];
test('network template validation runs actual bounded offline worker and preserves every sample',async()=>{
 const report=await validateNetworkSamples(definition,samples);assert.equal(report.passed,true);assert.equal(report.samples.length,2);assert.equal(report.engineVersion,'selfguard-network-v1');assert.deepEqual(report.samples.map(row=>row.actualMatched),[true,false]);assert.equal(report.samples.every(row=>row.observation===false),true);
 const contradicted=await validateNetworkSamples(definition,[{...samples[0],banner:'safe'},samples[1]]);assert.equal(contradicted.passed,false);
});
test('network template validation refuses protocol mismatch and malformed samples',async()=>{
 await assert.rejects(()=>validateNetworkSamples({...definition,protocol:'tls'},samples));await assert.rejects(()=>validateNetworkSamples(definition,[samples[0],{...samples[1],command:'uname -a'}]));
 await assert.rejects(()=>validateNetworkSamples({kind:'NETWORK',protocol:'tls',rule:{id:'owned-cert',description:'Explicit expired certificate sample',kind:'TLS_CERT_EXPIRED'}},[{name:'Missing dates',expectedMatched:true,connected:true,tlsVersion:'TLS1.3'},{name:'Disconnected',expectedMatched:false,connected:false}]));
});
