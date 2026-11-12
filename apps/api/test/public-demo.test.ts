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
