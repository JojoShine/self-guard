// Only the disposable HTTP runner invokes this; all sites and publications are fixtures.
const assert=require('node:assert/strict');
const base=process.env.TEST_API_URL;assert.ok(base?.includes(':4400/'),'Use isolated HTTP runner');
const nodes=['selfguard-runtime-acceptance-a','selfguard-runtime-acceptance-b'];
const upstream=process.env.WAF_ACCEPTANCE_UPSTREAM;assert.equal(upstream,process.env.WAF_ACCEPTANCE_NATIVE==='1'?'http://host.lima.internal:4401':'http://selfguard-runtime-acceptance-api:4401');
const upstreamServer=require('node:http').createServer((req,res)=>{req.resume();res.end('isolated upstream fixture')});
async function main(){
 await new Promise(resolve=>upstreamServer.listen(4401,'0.0.0.0',resolve));
 const login=await fetch(base+'/auth/login',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({email:process.env.ADMIN_EMAIL||'admin@selfguard.local',password:process.env.ADMIN_PASSWORD})});assert.ok(login.ok);const auth=await login.json();
 const headers={authorization:'Bearer '+auth.token,'content-type':'application/json'};
 async function call(path,body,method=body?'POST':'GET'){const r=await fetch(base+path,{headers,method,...(body?{body:JSON.stringify(body)}:{})});const value=await r.json();assert.ok(r.ok,path+': '+JSON.stringify(value));return value;}
 async function waitAck(id){for(let n=0;n<100;n++){const row=(await call('/waf-rule-deployments')).items.find(row=>row.id===id);if(row?.status==='ACKNOWLEDGED'&&row.expectedOnlineNodes===2){assert.deepEqual([...row.acknowledgedNodes].sort(),nodes);return row}await new Promise(r=>setTimeout(r,500))}throw Error('Both actual nodes did not confirm the exact policy');}
 const bundle=await call('/waf-rule-bundles',{name:'实际双节点发布验收',version:'1.0.0',source:'https://selfguard.example/multinode-acceptance',license:'Internal',files:[{name:'local.conf',source:'SecRule ARGS:q "@streq acceptance-attack" "id:120071,phase:2,deny,status:451,msg:\'Actual two-node inspection\'"'}]});await call('/waf-rule-bundles/'+bundle.id+'/check',{});
 const site=await call('/sites',{name:'实际双节点验收站点',hostname:'multinode.fixture.test',upstream,mode:'BLOCK',enabled:true,config:{}});
 for(const attack of [false,true]){const result=await call('/waf-rule-bundles/'+bundle.id+'/validate',{fixture:{requestBase64:Buffer.from('GET /api/health?q='+(attack?'acceptance-attack':'normal')+' HTTP/1.1\r\nHost: multinode.fixture.test\r\n\r\n').toString('base64'),threshold:5},expectedBlocked:attack,...(attack?{expectedStatus:451}:{})});assert.ok(result.validation.passed)}
 const observed=(await call('/waf-rule-deployments/observe/'+bundle.id,{siteIds:[site.id],threshold:5,reason:'仅在隔离夹具验证两个真实节点确认观察版本'})).items[0];await waitAck(observed.id);
 async function request(node,attack,invalid=false){return new Promise((resolve,reject)=>{const r=require('node:http').get((process.env.WAF_ACCEPTANCE_NATIVE==='1'?'http://127.0.0.1:'+String(18091+nodes.indexOf(node)):'http://'+node+':8081')+'/api/health?q='+(invalid?'%ZZ':attack?'acceptance-attack':'normal'),{headers:{Host:site.hostname}},response=>{response.resume();response.once('end',()=>resolve(response.statusCode))});r.once('error',reject);r.setTimeout(10000,()=>r.destroy(Error('Actual node request timed out')))});}
 for(const node of nodes){assert.equal(await request(node,true),200);assert.equal(await request(node,false),200)}
 for(const node of nodes)assert.equal(await request(node,false,true),503);
 let failures=[];for(let n=0;n<40;n++){failures=(await call('/waf-events?pageSize=100')).items.filter(row=>row.siteId===site.id&&!row.inspection?.complete);if(nodes.every(node=>failures.some(row=>row.inspection?.nodeId===node)))break;await new Promise(r=>setTimeout(r,250))}
 for(const node of nodes){const event=failures.find(row=>row.inspection?.nodeId===node);assert.ok(event,'missing actual incomplete-inspection event');assert.equal(event.inspection.failureKind,'REQUEST_INCOMPLETE');assert.equal(event.inspection.decisionStatus,503);assert.equal(event.ruleId,'INSPECTION_INCOMPLETE')}
 console.log('PASS two real Go nodes: exact signed observation acknowledgment, forwarded requests and actual classified incomplete-inspection events');
 const enforced=await call('/waf-rule-deployments/'+observed.id+'/enforce',{reason:'两个真实节点确认观察版本后切换为阻断'});await waitAck(enforced.id);
 for(const node of nodes){assert.equal(await request(node,true),451);assert.equal(await request(node,false),200)}
 let events=[];for(let n=0;n<40;n++){events=(await call('/waf-events?pageSize=100')).items.filter(row=>row.siteId===site.id&&row.action==='BLOCK'&&row.inspection?.complete);if(nodes.every(node=>events.some(row=>row.inspection?.nodeId===node)))break;await new Promise(r=>setTimeout(r,250))}
 for(const node of nodes){const event=events.find(row=>row.inspection?.nodeId===node);assert.ok(event,'missing actual node event '+node);const detail=await call('/waf-events/'+event.id);assert.equal(detail.inspection.siteVersion,enforced.siteVersion);assert.equal(detail.inspection.evidence[0].variable,'ARGS:q');assert.equal(detail.inspection.complete,true);assert.equal(detail.inspection.configuredUpstreamOrigin,upstream)}
 const rollback=await call('/waf-rule-deployments/'+observed.id+'/rollback',{reason:'回退到已经确认的观察内容，签发更高版本'});assert.ok(rollback.siteVersion>enforced.siteVersion);await waitAck(rollback.id);for(const node of nodes)assert.equal(await request(node,true),200);
 console.log('PASS actual dual-node blocking, durable event ingestion/readable evidence and higher-version observation rollback; no synthetic heartbeat');
}
main().catch(error=>{console.error(error.message);process.exitCode=1}).finally(()=>upstreamServer.close());
