import {test} from 'node:test';import assert from 'node:assert/strict';
import {platformBaseURL,platformEndpoint,basePath} from '../src/platform-path';
test('preserves root and deployment prefix for all component endpoints',()=>{
 assert.equal(platformBaseURL('https://tbtparent.me/self-guard/'),'https://tbtparent.me/self-guard');
 assert.equal(platformEndpoint('https://tbtparent.me/self-guard','/api/agent/enroll'),'https://tbtparent.me/self-guard/api/agent/enroll');
 assert.equal(platformEndpoint('http://localhost:4000','/api/health/ready'),'http://localhost:4000/api/health/ready');
 assert.equal(basePath('/self-guard'),'/self-guard');assert.equal(basePath(''),'');
});
test('rejects ambiguous and unsafe platform paths',()=>{
 for(const value of ['https://x/a/../b','https://x/a//b','https://x/%2fadmin','https://x/a?b','https://u:p@x/a','https://x/a#b','https://x/api'])assert.throws(()=>platformBaseURL(value),value);
 for(const value of ['/a/','//a','/a/../b','/a%2fb'])assert.throws(()=>basePath(value),value);
});
