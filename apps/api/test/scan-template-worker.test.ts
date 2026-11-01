import {test} from 'node:test';import assert from 'node:assert/strict';import {validateRuleSamples} from '../src/scan-template-worker';
const definition={method:'GET',path:'/public',rule:{id:'sample',description:'实际响应标识检测',operator:'ALL',conditions:[{kind:'STATUS',status:200},{kind:'BODY_CONTAINS',value:'exposed'}]}};
const samples=[{name:'应命中',expectedMatched:true,status:200,headers:{},body:'exposed'},{name:'应不命中',expectedMatched:false,status:200,headers:{},body:'normal'}];
test('native template validation evaluates positive and negative offline samples in the real scanner',async()=>{
 const result=await validateRuleSamples(definition,samples);assert.equal(result.passed,true);assert.equal(result.samples.length,2);assert.deepEqual(result.samples.map(x=>x.actualMatched),[true,false]);assert.equal(result.samples[0].conditions.length,2);
 const mismatch=await validateRuleSamples(definition,[samples[0],{...samples[1],body:'exposed'}]);assert.equal(mismatch.passed,false);assert.equal(mismatch.samples[1].passed,false);
 await assert.rejects(()=>validateRuleSamples(definition,[samples[0]]));await assert.rejects(()=>validateRuleSamples({...definition,method:'POST'},samples));
 await assert.rejects(()=>validateRuleSamples({...definition,rule:{...definition.rule,conditions:[{kind:'BODY_REGEX',value:'(?=lookahead)'}]}},samples));
});

test('grouped native samples retain negative matcher semantics and the no-redirect profile',async()=>{
 const grouped={method:'GET',path:'/.git/config',rule:{id:'vendor-groups',description:'Frozen source matcher groups',operator:'ALL',maxRedirects:0,groups:[{operator:'ANY',conditions:[{kind:'BODY_CONTAINS',value:'[core]'},{kind:'BODY_CONTAINS',value:'[credentials]'}]},{operator:'ALL',conditions:[{kind:'BODY_REGEX',value:'(?i)<html',negative:true},{kind:'STATUS',status:200}]}]}};
 const result=await validateRuleSamples(grouped,[{name:'Actual marker',expectedMatched:true,status:200,headers:{},body:'[core]\n'},{name:'HTML false positive',expectedMatched:false,status:200,headers:{},body:'[core]<HTML'}]);assert.equal(result.passed,true);assert.equal(result.samples[0].groups?.length,2);
});

test('official frozen template features run in the self-developed offline evaluator without semantic shortcuts',async()=>{
 const {readFileSync}=await import('node:fs'),{convertNucleiHTTP}=await import('../src/nuclei-converter');
 const cases=[
  {name:'git-config',yes:'[core]\nurl=https://fixture:private@owned.invalid/repo',no:'[core]<HTML>',headers:{'Content-Type':['text/plain']}},
  {name:'exposed-gitignore',yes:'node_modules\n'+'.owned-fixture-ignore\n'.repeat(4),no:'node_modules\n'+'.owned-fixture-ignore\n'.repeat(4),headers:{'Content-Type':['text/plain']}},
  {name:'laravel-env',yes:'APP_NAME=OwnedFixture\nDB_HOST=owned.invalid',no:'<HTML>APP_NAME=OwnedFixture',headers:{'Content-Type':['text/plain']}}
 ];
 for(const row of cases){const converted=convertNucleiHTTP(readFileSync('rule-sources/nuclei/'+row.name+'.yaml','utf8'));assert.equal(converted.compatible,true);const request=converted.requests[0];const result=await validateRuleSamples({method:request.method,path:request.path,rule:{...request.rule,extractors:request.extractors}},[{name:'positive',expectedMatched:true,status:200,headers:row.headers,body:row.yes},{name:'negative',expectedMatched:false,status:200,headers:row.name==='exposed-gitignore'?{'Content-Type':['application/json']}:row.headers,body:row.no}]);assert.equal(result.passed,true,row.name);}
});
