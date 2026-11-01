// Full frozen policy replay. This is separate from the small operator unit
// corpus and never publishes a policy or sends fixture traffic to a network.
const fs=require('node:fs'),assert=require('node:assert/strict'),{spawnSync}=require('node:child_process');
const files=JSON.parse(fs.readFileSync('.artifacts/results/expansion/crs-current-input.json')).files;
files.push({name:'crs-setup.conf',source:fs.readFileSync('third_party/crs/selfguard-inbound-PL1.conf','utf8')});
const results=[];
for(const id of [941100,942100]){
 const corpus=JSON.parse(fs.readFileSync('services/waf/testdata/crs-v4.25.1/'+id+'.json'));
 for(const test of corpus.tests){for(const [stageIndex,stage]of test.stages.entries()){
  const request=stage.input,headers={...request.headers},body=Buffer.from(request.data||'');if((request.method||'GET')==='POST'&&!Object.keys(headers).some(k=>k.toLowerCase()==='content-type'))headers['Content-Type']='application/x-www-form-urlencoded';
  if(body.length&&!Object.keys(headers).some(k=>k.toLowerCase()==='content-length'))headers['Content-Length']=String(body.length);
  const head=[`${request.method||'GET'} ${request.uri||'/'} ${request.version||'HTTP/1.1'}`,...Object.entries(headers).map(([k,v])=>k+': '+v),'',''].join('\r\n');const raw=Buffer.concat([Buffer.from(head),body]);
  const input=JSON.stringify({files,requestBase64:raw.toString('base64'),threshold:10000});
  const run=spawnSync('docker',['run','--rm','-i','selfguard-waf:crs-foundation','--test-seclang'],{input,encoding:'utf8',timeout:30000,maxBuffer:4*1024*1024});
  let result,error;try{assert.equal(run.status,0,run.stderr?.slice(-1000)||run.error?.message);result=JSON.parse(run.stdout);const ids=result.matches||[];for(const expected of stage.output.log.expect_ids||[])assert.ok(ids.includes(String(expected)),'expected rule '+expected+' absent; observed '+ids.join(','));for(const excluded of stage.output.log.no_expect_ids||[])assert.ok(!ids.includes(String(excluded)),'unexpected rule '+excluded);}catch(e){error=e.message;}
  results.push({id,testId:test.test_id,stage:stageIndex,passed:!error,...(error?{error}:{}),...(result?{matches:result.matches,incomplete:result.incomplete||[],score:result.score}:{})});console.log((error?'FAIL':'PASS')+' full policy '+id+'/'+test.test_id+(error?': '+error:''));
 }}
}
fs.writeFileSync('.artifacts/results/expansion/crs-whole-core-results.json',JSON.stringify({at:new Date().toISOString(),profile:'frozen inbound, observation replay threshold 10000',passed:results.filter(r=>r.passed).length,total:results.length,results},null,2));
if(results.some(r=>!r.passed))process.exitCode=1;
