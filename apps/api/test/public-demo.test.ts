import {test} from 'node:test';
import assert from 'node:assert/strict';
import {safeDemoAccount,demoRequestAllowed} from '../src/public-demo';
const id='11111111-1111-4111-8111-111111111111';
const setting={enabled:true,userId:id,email:'demo@selfguard.local',password:'public-demo-only',assetIds:[id]};
const scope={restricted:true,assetIds:[id],businesses:[],canReadEvidence:false,canReadSqlEvidence:false,canReadAccessEvidence:false,canExportAccessEvidence:false};
const user={id,email:setting.email,role:'VIEWER',disabled:false,dataScope:scope};
test('only exposes dedicated explicitly restricted matching demo accounts',()=>{
 assert.equal(safeDemoAccount(setting,user)?.email,setting.email);
 for(const bad of [{...user,role:'ADMIN'},{...user,disabled:true},{...user,email:'real@example.test'},{...user,dataScope:{...scope,restricted:false}},{...user,dataScope:{...scope,assetIds:[]}},{...user,dataScope:{...scope,businesses:['production']}},...['canReadEvidence','canReadSqlEvidence','canReadAccessEvidence','canExportAccessEvidence'].map(key=>({...user,dataScope:{...scope,[key]:true}}))])assert.equal(safeDemoAccount(setting,bad),null);
 assert.equal(safeDemoAccount({...setting,enabled:false},user),null);
 assert.equal(safeDemoAccount({...setting,userId:'different'},user),null);
});
test('allows only narrow read-only routes with exact deployment prefix',()=>{
 for(const path of ['/auth/me','/overview','/assets','/assets/'+id,'/findings','/findings/'+id])assert.equal(demoRequestAllowed('GET','/self-guard/api'+path,'/self-guard'),true,path);
 assert.equal(demoRequestAllowed('POST','/api/auth/logout',''),true);
 for(const [method,path] of [['POST','/api/assets'],['GET','/api/assets/export'],['GET','/api/findings/'+id+'/evidence'],['GET','/api/settings'],['GET','/api/assets/'+id+'/'],['GET','/evil/api/assets'],['DELETE','/api/auth/logout']])assert.equal(demoRequestAllowed(method,path,''),false,path);
 assert.equal(demoRequestAllowed('GET','/api/assets','/self-guard'),false);
});
const fullSetting={...setting,accessMode:'FULL_READ_ONLY',assetIds:[]};
const fullUser={...user,dataScope:{...scope,restricted:false,assetIds:[],databaseInstanceIds:[]}};
test('global read-only profile requires an enabled VIEWER and explicit empty unrestricted scope without evidence grants',()=>{
 assert.equal(safeDemoAccount(fullSetting,fullUser)?.accessMode,'FULL_READ_ONLY');
 for(const bad of [{...fullUser,role:'ADMIN'},{...fullUser,disabled:true},{...fullUser,email:'normal@example.test'},{...fullUser,dataScope:{...fullUser.dataScope,restricted:true}},{...fullUser,dataScope:{...fullUser.dataScope,databaseInstanceIds:undefined}},...['businesses','assetIds','databaseInstanceIds'].map(key=>({...fullUser,dataScope:{...fullUser.dataScope,[key]:[id]}})),...['canReadEvidence','canReadSqlEvidence','canReadAccessEvidence','canExportAccessEvidence'].map(key=>({...fullUser,dataScope:{...fullUser.dataScope,[key]:true}}))])assert.equal(safeDemoAccount(fullSetting,bad),null);
 assert.equal(safeDemoAccount({...fullSetting,assetIds:[id]},fullUser),null);
 assert.equal(safeDemoAccount(setting,fullUser),null);
});
test('global profile permits only enumerated metadata GETs and logout across the normal platform',()=>{
 for(const route of ['/agent-platform','/probe-deployments','/vulnerability-workspace','/vulnerability-workspace/lookup'])assert.equal(demoRequestAllowed('GET','/api'+route,'','FULL_READ_ONLY'),true,route);
 for(const route of ['/auth/me','/assets','/assets/'+id,'/assets/'+id+'/resource-monitor','/database-instances','/database-instances/'+id+'/runtime-monitor','/rules','/probe-rule-library','/probe-templates','/scan-plans','/active-scan-plans','/storage','/users','/audit','/governance/retention','/data-security/events/'+id,'/access-observations/'+id])assert.equal(demoRequestAllowed('GET','/self-guard/api'+route,'/self-guard','FULL_READ_ONLY'),true,route);
 for(const method of ['POST','PUT','PATCH','DELETE','HEAD','OPTIONS'])for(const route of ['/assets','/demo-workspace','/scan-plans/'+id+'/run','/auth/me'])assert.equal(demoRequestAllowed(method,'/api'+route,'','FULL_READ_ONLY'),false,method+route);
 assert.equal(demoRequestAllowed('POST','/api/auth/logout','','FULL_READ_ONLY'),true);
 for(const route of ['/demo-workspace','/operations/credentials','/agent/policy','/waf/config','/access-probe/configuration','/sensor-ingest/'+id+'/config','/data-security/events/'+id+'/sql','/access-observations/'+id+'/sql','/access-observations/'+id+'/chunks/'+id,'/agent-releases/'+id+'/download','/workflows/export','/reports/summary','/reports/detailed','/assets/'+id+'/attachments/'+id,'/vulnerability-feeds/'+id+'/snapshots/'+id+'/artifact','/active-scan-plans/checks/'+id,'/assets/'+id+'/','/assets/../users'])assert.equal(demoRequestAllowed('GET','/api'+route,'','FULL_READ_ONLY'),false,route);
 assert.equal(demoRequestAllowed('GET','/api/assets','/self-guard','FULL_READ_ONLY'),false);
});
