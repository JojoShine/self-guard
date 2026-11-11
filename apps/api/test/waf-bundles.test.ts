import {test} from 'node:test';import assert from 'node:assert/strict';
import {wafBundleInput,bundleDigest,compatibilityResultInput,wafFixtureInput} from '../src/waf-bundles';
test('WAF rule packages retain source and license, reject paths and require bounded textual files',()=>{
 const source={name:'CRS',version:'4.25.1',source:'https://github.com/coreruleset/coreruleset',license:'Apache-2.0',files:[{name:'rules/REQUEST-901.conf',source:'SecAction "id:1001,phase:1,pass"'}]};
 assert.equal(wafBundleInput.safeParse(source).success,true);
 for(const files of [[{name:'../../etc/passwd',source:'data'}],[{name:'/tmp/rule.conf',source:'data'}],[{name:'rules/rule.so',source:'data'}],[]])assert.equal(wafBundleInput.safeParse({...source,files}).success,false);
 assert.equal(wafBundleInput.safeParse({...source,license:''}).success,false);
 const files=[...source.files,{name:'rules/data.data',source:'pattern'}];assert.equal(bundleDigest(files),bundleDigest([...files].reverse()));assert.notEqual(bundleDigest(files),bundleDigest([{...files[0],source:'modified'},files[1]]));
});
test('WAF raw request fixtures are bounded, canonical and cannot override parsed variables',()=>{
 const requestBase64=Buffer.from('GET / HTTP/1.1\r\nHost: fixture.test\r\n\r\n').toString('base64');
 assert.equal(wafFixtureInput.safeParse({requestBase64}).success,true);
 assert.equal(wafFixtureInput.safeParse({variables:{ARGS:['test']}}).success,true);
 for(const value of [{},{requestBase64,variables:{ARGS:['override']}},{requestBase64:'@@@'},{requestBase64:'a'.repeat(350001)}])assert.equal(wafFixtureInput.safeParse(value).success,false);
});
test('compatibility results cannot report an unsupported active operator as publishable',()=>{
 assert.equal(compatibilityResultInput.safeParse({publishable:false,parsed:713,unsupported:['operator:detectsqli'],outsideProfile:165,engine:'selfguard-seclang-v1'}).success,true);
 assert.equal(compatibilityResultInput.safeParse({publishable:true,parsed:713,unsupported:['operator:detectsqli'],outsideProfile:165,engine:'selfguard-seclang-v1'}).success,false);
});

test('compatibility explains fixed-profile inactive branches separately from unsupported active semantics',()=>{
 const report={publishable:true,parsed:713,unsupported:[],outsideProfile:165,inactiveByConfiguration:2,engine:'selfguard-seclang-v1'};
 assert.equal(compatibilityResultInput.safeParse(report).success,true);
 assert.equal(compatibilityResultInput.safeParse({...report,inactiveByConfiguration:-1}).success,false);
});

import {WafBundlesController} from '../src/waf-bundles';
test('isolated check node uses its own token and preserves legacy fallback',async()=>{
 const previous={url:process.env.WAF_TEST_URL,token:process.env.WAF_TOKEN,testToken:process.env.WAF_TEST_TOKEN,fetch:globalThis.fetch};
 const report={publishable:true,parsed:1,unsupported:[],outsideProfile:0,engine:'selfguard-seclang-v1'};
 const tx={wafRuleBundle:{updateMany:async()=>({count:1})},audit:{create:async()=>({})}};
 const db={wafRuleBundle:{findUniqueOrThrow:async()=>({id:'candidate',files:[],sha256:'fixed',updatedAt:new Date()})},$transaction:async(work:(value:typeof tx)=>unknown)=>work(tx)};
 try{process.env.WAF_TEST_URL='http://127.0.0.1:18082';process.env.WAF_TOKEN='fixture-shared-token';process.env.WAF_TEST_TOKEN='fixture-check-only-token';let authorization='';globalThis.fetch=async(_url,options)=>{authorization=(options?.headers as Record<string,string>).authorization;return new Response(JSON.stringify(report))};
 const controller=new WafBundlesController(db as never),req={user:{role:'ADMIN',email:'fixture@example.test'}};
 await controller.check(req,'candidate');assert.equal(authorization,'Bearer fixture-check-only-token');delete process.env.WAF_TEST_TOKEN;await controller.check(req,'candidate');assert.equal(authorization,'Bearer fixture-shared-token');
 }finally{for(const[key,value]of Object.entries({WAF_TEST_URL:previous.url,WAF_TOKEN:previous.token,WAF_TEST_TOKEN:previous.testToken})){if(value===undefined)delete process.env[key];else process.env[key]=value}globalThis.fetch=previous.fetch}
});
