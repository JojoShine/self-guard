import {test} from 'node:test';import assert from 'node:assert/strict';import {readFileSync} from 'node:fs';import {createHash} from 'node:crypto';import {convertNucleiHTTP} from '../src/nuclei-converter';
const source=(name:string)=>readFileSync('rule-sources/nuclei/'+name+'.yaml','utf8');
test('frozen upstream Git configuration retains grouping, exact original hash and no-redirect defaults',()=>{
 const raw=source('git-config'),result=convertNucleiHTTP(raw);assert.equal(result.id,'git-config');assert.equal(result.sourceSha256,createHash('sha256').update(raw).digest('hex'));assert.equal(result.requests.length,1);assert.equal(result.requests[0].path,'/.git/config');assert.equal(result.requests[0].rule.maxRedirects,0);assert.equal(result.requests[0].rule.operator,'ALL');assert.equal(result.requests[0].rule.groups.length,3);assert.equal(result.requests[0].rule.groups[0].operator,'ANY');assert.equal(result.requests[0].rule.groups[1].conditions[0].negative,true);assert.equal(result.requests[0].extractors.length,3);
});
test('real multiple-path, response-negative, body-length and domain-variable templates are all converted',()=>{
 const ignore=convertNucleiHTTP(source('exposed-gitignore'));assert.equal(ignore.requests.length,3);assert.equal(ignore.requests[0].rule.groups[1].negative,true);assert.ok(ignore.requests[0].rule.groups[0].conditions.some((value:any)=>value.kind==='BODY_LENGTH'));assert.ok(ignore.requests[0].rule.groups[1].conditions.every((value:any)=>value.kind==='RESPONSE_CONTAINS'));
 const environment=convertNucleiHTTP(source('laravel-env'));assert.equal(environment.requests.length,22);assert.ok(environment.requests.some((value:any)=>value.path==='/.env.{{DN}}'));assert.ok(environment.requests.some((value:any)=>value.path==='/.env.{{SD}}'));assert.equal(environment.issues.length,0,'the known official template semantics must be implemented rather than silently omitted');
});
test('source parsing rejects aliases, duplicate keys, unsupported requests and oversized structures explicitly',()=>{
 for(const raw of ['id: one\nid: two\n','x: &anchor [one]\ny: *anchor\n','---\na: b\n---\nc: d\n','x: !!js/function function(){}','x: '+'a'.repeat(65536)])assert.throws(()=>convertNucleiHTTP(raw));
 const post=source('git-config').replace('method: GET','method: POST');const report=convertNucleiHTTP(post);assert.equal(report.compatible,false);assert.ok(report.issues.some((issue:any)=>issue.code==='METHOD_UNSUPPORTED'));assert.equal(report.requests.length,0);
});

test('redirect sources preserve ten-hop defaults and independently evaluate actual redirect responses',()=>{
 const raw=source('git-config').replace('method: GET','method: GET\n    redirects: true'),report=convertNucleiHTTP(raw);assert.equal(report.compatible,true);assert.equal(report.requests[0].rule.maxRedirects,10);assert.equal(report.requests[0].rule.responseMode,'ANY_REDIRECT');const excessive=convertNucleiHTTP(raw.replace('redirects: true','redirects: true\n    max-redirects: 11'));assert.equal(excessive.compatible,false);assert.ok(excessive.issues.some(issue=>issue.code==='REDIRECT_LIMIT_UNSUPPORTED'));
});
