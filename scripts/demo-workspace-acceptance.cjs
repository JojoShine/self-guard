// Uses the published demo credentials and normal login; never reads administrator configuration.
const assert=require('node:assert/strict');
const base=(process.env.DEMO_API_URL||'http://127.0.0.1:4400/api').replace(/\/$/,'');
async function call(path,body,token,expected=200){const r=await fetch(base+path,{method:body?'POST':'GET',headers:{'content-type':'application/json',...(token?{authorization:'Bearer '+token}:{})},...(body?{body:JSON.stringify(body)}:{})});const value=await r.json();assert.equal(r.status,expected,path+' status');return value;}
(async()=>{const credentials=await call('/auth/demo');assert.equal(credentials.enabled,true);const login=()=>call('/auth/login',{email:credentials.email,password:credentials.password});const sessions=[];
try{
 const first=await login();sessions.push(first.token);const second=await login();sessions.push(second.token);const[a,b]=sessions;
 let state=await call('/demo-workspace',undefined,a);const untouched=await call('/demo-workspace',undefined,b);assert.equal(state.assets.length,2);
 const command=async(values,expected=201)=>{const next=await call('/demo-workspace',{revision:state.revision,...values},a,expected);if(expected===201)state=next;return next};
 await command({action:'ADD_ASSET',name:'HTTP acceptance example',profile:'OUTDATED'});assert.equal(state.assets.length,3);assert.equal((await call('/demo-workspace',undefined,a)).assets.length,3);assert.deepEqual(await call('/demo-workspace',undefined,b),untouched);
 const races=await Promise.all(['one','two'].map(name=>fetch(base+'/demo-workspace',{method:'POST',headers:{'content-type':'application/json',authorization:'Bearer '+a},body:JSON.stringify({revision:state.revision,action:'ADD_ASSET',name:'race '+name,profile:'CURRENT'})}).then(r=>r.status)));assert.deepEqual(races.sort(),[201,409]);state=await call('/demo-workspace',undefined,a);assert.equal(state.assets.length,4);
 await command({action:'CREATE_SCAN',name:'HTTP sample check',assetIds:state.assets.map(asset=>asset.id)});const scanId=state.scans[0].id;await command({action:'EXECUTE_SCAN',id:scanId});assert.equal(state.scans[0].status,'DONE');assert.equal(state.findings.length,2);await command({action:'UPDATE_FINDING',id:state.findings[0].id,status:'CONFIRMED'});assert.equal(state.findings[0].status,'CONFIRMED');
 await command({action:'PARSE_SQL',sample:'PREPARED'});assert.equal(state.sqlSamples[0].statements[0].stage,'EXECUTE');assert.equal(state.sqlSamples[0].statements[0].sql,'SELECT $1::integer AS demo_value');
 await command({action:'PARSE_SQL',sample:'TLS'});assert.deepEqual(state.sqlSamples[1].reasons,['TLS_NO_PLAINTEXT']);
 await call('/demo-workspace',{revision:untouched.revision,action:'EXECUTE_SCAN',id:scanId},b,400);
 await call('/demo-workspace',{revision:0,action:'ADD_ASSET',name:'stale',profile:'CURRENT'},a,409);
 await command({action:'PARSE_SQL',sample:'SIMPLE',sql:'not-executed'},400);
 for(const path of ['/assets','/probe-deployments','/active-scans'])await call(path,{name:'must-be-denied'},a,403);
 await call('/settings',undefined,a,403);await call('/access-observations/00000000-0000-4000-8000-000000000001/sql',undefined,a,403);
 await command({action:'RESET'});assert.equal(state.assets.length,2);assert.equal(state.scans.length,0);assert.equal(state.findings.length,0);assert.equal(state.sqlSamples.length,0);assert.deepEqual(await call('/demo-workspace',undefined,b),untouched);
 console.log(JSON.stringify({normalDemoLogin:true,persistedEdits:true,twoSessionsIsolated:true,checkAndFindingWorkflow:true,sqlParserSample:true,invalidInputDenied:true,staleRevisionDenied:true,productionMutationsDenied:true,resetIsolated:true}));
}finally{for(const token of sessions)await call('/auth/logout',{},token,201)}})().catch(error=>{console.error(error.message);process.exitCode=1});
