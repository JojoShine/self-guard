// Exercises the public account through normal login; never reads administrator configuration.
const assert=require('node:assert/strict');
const base=(process.env.DEMO_API_URL||'http://127.0.0.1:4400/api').replace(/\/$/,'');
async function call(path,body,token,expected=200){const r=await fetch(base+path,{method:body?'POST':'GET',headers:{'content-type':'application/json',...(token?{authorization:'Bearer '+token}:{})},...(body?{body:JSON.stringify(body)}:{})});const value=await r.json();assert.equal(r.status,expected,path+' status');return value;}
(async()=>{const credentials=await call('/auth/demo');assert.equal(credentials.enabled,true);const login=await call('/auth/login',{email:credentials.email,password:credentials.password});const token=login.token;
try{
 const user=await call('/auth/me',undefined,token);assert.equal(user.role,'VIEWER');assert.equal(user.publicReadOnly,true);assert.equal(user.dataScope.canReadSqlEvidence,false);
 const paths=['/overview','/assets','/database-instances','/vulnerability-workspace','/probe-rule-library','/probe-templates','/active-scan-plans','/scan-endpoints','/data-security/policy','/data-security/classifications','/access-observations','/access-sources','/network-sensors','/operations/health','/users','/audit','/governance/notification-settings','/maintenance/backup','/governance/retention','/storage','/agent-platform','/agent-releases','/agent-installations'];
 const responses={};for(const path of paths)responses[path]=await call(path,undefined,token);
 const assets=responses['/assets'].items;if(assets.length){const a=await call('/assets/'+assets[0].id,undefined,token);assert.equal(a.id,assets[0].id);await call('/assets/'+a.id+'/resource-monitor',undefined,token);await call('/asset-remote/'+a.id+'/probe',{},token,403);}
 const instances=responses['/database-instances'].items;if(instances.length){for(const suffix of ['collection','runtime-monitor','onboarding'])await call('/database-instances/'+instances[0].id+'/'+suffix,undefined,token);}
 for(const method of ['PATCH','PUT','DELETE']){const response=await fetch(base+'/assets/00000000-0000-4000-8000-000000000001',{method,headers:{authorization:'Bearer '+token,'content-type':'application/json'},body:'{}'});assert.ok([403,404].includes(response.status),method+' mutation must be forbidden or unregistered');}
 for(const path of ['/assets','/rules','/active-scan-plans','/probe-deployments','/users','/demo-workspace'])await call(path,{name:'must-be-denied'},token,403);
 for(const path of ['/operations/credentials','/settings','/access-observations/00000000-0000-4000-8000-000000000001/sql'])await call(path,undefined,token,403);
 const serialized=JSON.stringify(responses);assert.ok(!/"(?:passwordHash|credential|tokenHash|privateKey|encryptionKey)"\s*:/.test(serialized));
 console.log(JSON.stringify({normalPublicLogin:true,viewerRolePreserved:true,fullNavigationReads:paths.length,realAssetsVisible:assets.length,realDatabasesVisible:instances.length,mutationsDenied:true,remoteExecutionDenied:true,sensitiveEvidenceDenied:true,credentialsRedacted:true}));
}finally{await call('/auth/logout',{},token,201)}})().catch(error=>{console.error(error.message);process.exitCode=1});
