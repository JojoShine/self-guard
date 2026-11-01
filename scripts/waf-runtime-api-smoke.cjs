const fs=require('node:fs'),{randomUUID}=require('node:crypto'),assert=require('node:assert/strict'),{createPrivateKey,createPublicKey,verify,createHash}=require('node:crypto');
const base=process.env.TEST_API_URL;assert.ok(base?.includes(':4400/'),'Use isolated HTTP runner only');
async function main(){
 const login=await fetch(base+'/auth/login',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({email:process.env.ADMIN_EMAIL||'admin@selfguard.local',password:process.env.ADMIN_PASSWORD})});assert.equal(login.status,200);const auth=await login.json(),headers={authorization:'Bearer '+auth.token,'content-type':'application/json'};
 async function call(path,body,method=body?'POST':'GET',want){const response=await fetch(base+path,{headers,method,...(body?{body:JSON.stringify(body)}:{})}),value=await response.json();if(want)assert.equal(response.status,want,JSON.stringify(value));else assert.ok(response.ok,path+': '+JSON.stringify(value));return value;}
 const bundle=await call('/waf-rule-bundles',{name:'真实节点 HTTP 样本发布验收',version:'1.0.0',source:'https://selfguard.example/runtime-acceptance',license:'Internal',files:[{name:'local.conf',source:'SecRule ARGS:q "@streq new-proof" "id:120001,phase:2,deny,status:451,msg:\'Actual local detection <中文>\'"'}]});
 await call('/waf-rule-bundles/'+bundle.id+'/check',{});
 const site=await call('/sites',{name:'隔离签名站点',hostname:'runtime-fixture.test',upstream:'http://127.0.0.1:8080',mode:'BLOCK',enabled:true,config:{}}),selection={siteIds:[site.id],threshold:5,reason:'仅在隔离验收站点观察发布，验证完整签名链路'};
 await call('/waf-rule-deployments/observe/'+bundle.id,selection,'POST',409);
 for(const [value,expectedBlocked]of [['new-proof',true],['normal',false]]){
  const fixture={requestBase64:Buffer.from('GET /?q='+value+' HTTP/1.1\r\nHost: runtime-fixture.test\r\n\r\n').toString('base64'),threshold:5};
  const result=await call('/waf-rule-bundles/'+bundle.id+'/validate',{fixture,expectedBlocked,...(expectedBlocked?{expectedStatus:451}:{})});assert.equal(result.validation.passed,true);assert.equal(result.result.blocked,expectedBlocked);
 }
 const mismatch=await call('/waf-rule-bundles/'+bundle.id+'/validate',{fixture:{requestBase64:Buffer.from('GET /?q=new-proof HTTP/1.1\r\nHost: runtime-fixture.test\r\n\r\n').toString('base64')},expectedBlocked:false});assert.equal(mismatch.validation.passed,false);
 const observed=(await call('/waf-rule-deployments/observe/'+bundle.id,selection)).items[0];assert.equal(observed.mode,'OBSERVE');assert.equal(observed.siteVersion,site.version+1);assert.equal(observed.envelope,undefined);
 await call('/waf-rule-deployments/'+observed.id+'/enforce',{reason:'节点尚未确认，应该拒绝切换'},'POST',409);
 await call('/sites/'+site.id,{mode:'BLOCK'},'PATCH',400);
 async function configuration(){const response=await fetch(base+'/waf/config',{headers:{authorization:'Bearer '+process.env.WAF_TOKEN}});assert.equal(response.status,200);return response.json();}
 const key=createPublicKey(createPrivateKey({key:Buffer.from(fs.readFileSync(process.env.WAF_RULE_SIGNING_KEY_FILE,'utf8'),'base64'),format:'der',type:'pkcs8'})),config=await configuration(),wire=config.sites.find(row=>row.id===site.id),raw=Buffer.from(wire.ruleRelease.payload,'base64');assert.ok(verify(null,raw,key,Buffer.from(wire.ruleRelease.signature,'base64')));assert.equal(JSON.parse(raw).site.mode,'OBSERVE');
 const digest=createHash('sha256').update(raw).digest('hex'),heartbeat=await fetch(base+'/waf/heartbeat',{method:'POST',headers:{authorization:'Bearer '+process.env.WAF_TOKEN,'content-type':'application/json'},body:JSON.stringify({nodeId:'synthetic-isolated-rule-ack',version:'acceptance-fixture',sites:[{id:site.id,version:observed.siteVersion,ruleReleaseSha256:digest}],droppedEvents:0,startedAt:new Date().toISOString()})});assert.ok(heartbeat.ok,await heartbeat.text());
 const acknowledged=(await call('/waf-rule-deployments')).items.find(row=>row.id===observed.id);assert.equal(acknowledged.status,'ACKNOWLEDGED');assert.deepEqual(acknowledged.acknowledgedNodes,['synthetic-isolated-rule-ack']);
 const enforced=await call('/waf-rule-deployments/'+observed.id+'/enforce',{reason:'隔离回执夹具准确确认后验证切换'});assert.equal(enforced.mode,'BLOCK');assert.equal(enforced.siteVersion,observed.siteVersion+1);
 const edited=await call('/sites/'+site.id,{name:'隔离签名站点重新绑定'},'PATCH');assert.equal(edited.version,enforced.siteVersion+1);assert.notEqual(edited.ruleDeploymentId,enforced.id);
 const rollback=await call('/waf-rule-deployments/'+observed.id+'/rollback',{reason:'验证回退会创建新版本而不覆盖历史'});assert.equal(rollback.mode,'OBSERVE');assert.equal(rollback.siteVersion,edited.version+1);
 const final=await configuration(),runId=randomUUID();fs.writeFileSync('.artifacts/results/expansion/waf-cross-language-runtime.json',JSON.stringify({runId,publicKey:key.export({format:'der',type:'spki'}).subarray(-32).toString('base64'),config:final}),{mode:0o600});
 if(process.env.WAF_RUNTIME_WAIT_EVENT==='true'){
  console.log('Waiting for actual Go HTTP event for run '+runId);let event;
  for(let attempt=0;attempt<180;attempt++){try{const frame=JSON.parse(fs.readFileSync('.artifacts/results/expansion/waf-cross-language-event.json'));if(frame.runId===runId){event=frame.event;break}}catch{}await new Promise(resolve=>setTimeout(resolve,500))}
  assert.ok(event,'Actual Go event was not received');assert.equal(event.siteId,site.id);assert.equal(event.inspection.bundleSha256,JSON.parse(Buffer.from(final.sites[0].ruleRelease.payload,'base64')).bundleSha256);assert.equal(event.action,'OBSERVE');
  const response=await fetch(base+'/waf/events',{method:'POST',headers:{authorization:'Bearer '+process.env.WAF_TOKEN,'content-type':'application/json'},body:JSON.stringify({events:[event]})});assert.ok(response.ok,await response.text());
  const detail=await call('/waf-events/'+event.id);assert.equal(detail.inspection.evidence[0].variable,'ARGS:q');assert.equal(detail.inspection.siteHostname,'runtime-fixture.test');assert.equal(detail.inspection.complete,true);console.log('PASS: actual management signature -> real Go HTTP request -> rule event -> isolated ingestion and readable persisted evidence');
 }
 const rows=await call('/waf-rule-deployments?page=1&pageSize=15');assert.equal(rows.total,5);assert.equal(rows.items.filter(row=>row.current).length,1);assert.ok(rows.items.every(row=>row.envelope===undefined));
 const baseline=rows.items.find(row=>row.bundleId===null);assert.ok(baseline,'Initial builtin baseline was not retained');assert.equal(observed.previousId,baseline.id);
 const basicRollback=await call('/waf-rule-deployments/'+baseline.id+'/rollback',{reason:'明确回退到首次发布前保留的内置防护基线'});assert.equal(basicRollback.mode,'BLOCK');assert.ok(basicRollback.siteVersion>rollback.siteVersion);const basicConfig=await configuration();assert.equal(JSON.parse(Buffer.from(basicConfig.sites[0].ruleRelease.payload,'base64')).builtin,true);

 console.log('PASS: actual node sample validation, signature/site binding, observation publication, missing/wrong promotion paths rejected, synthetic isolated acknowledgment, signed configuration edit and immutable rollback history. Public fixture saved for Go verification; shared business schema untouched.');
}
main().catch(error=>{console.error(error.message);process.exitCode=1});
