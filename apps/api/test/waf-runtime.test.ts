import {test} from 'node:test';import assert from 'node:assert/strict';import {generateKeyPairSync,verify,createHash} from 'node:crypto';import {mkdtempSync,writeFileSync,rmSync,chmodSync} from 'node:fs';import {tmpdir} from 'node:os';import {join} from 'node:path';
import {signWafRuntime,validateStoredWafEnvelope,wafRuntimeSelectionInput} from '../src/waf-runtime';

test('WAF release binds complete site, exact source bytes and engine using an independent Ed25519 key',()=>{
 const root=mkdtempSync(join(tmpdir(),'selfguard-waf-sign-')),path=join(root,'private'),before=process.env.WAF_RULE_SIGNING_KEY_FILE,{privateKey,publicKey}=generateKeyPairSync('ed25519');
 try{writeFileSync(path,privateKey.export({format:'der',type:'pkcs8'}).toString('base64'),{mode:0o600});process.env.WAF_RULE_SIGNING_KEY_FILE=path;
 const files=[{name:'test.conf',source:'SecAction "id:1,phase:1,pass"\n# <not-html> 中文'}],bundle={id:'fixture',files,sha256:createHash('sha256').update(JSON.stringify(files)).digest('hex')},site={id:'site',name:'业务',hostname:'fixture.test',upstream:'https://app.test',mode:'OBSERVE',enabled:true,version:2,config:{ratePerMinute:100}};
 const envelope=signWafRuntime(site,bundle,5),raw=Buffer.from(envelope.payload,'base64');assert.ok(verify(null,raw,publicKey,Buffer.from(envelope.signature,'base64')));const payload=validateStoredWafEnvelope(envelope);assert.deepEqual(payload.site,site);assert.deepEqual(payload.files,files);assert.equal(payload.bundleSha256,bundle.sha256);
 assert.throws(()=>signWafRuntime(site,{...bundle,sha256:'0'.repeat(64)},5));assert.throws(()=>signWafRuntime({...site,config:{maxBodyBytes:2000000}},bundle,5));assert.throws(()=>signWafRuntime({...site,config:{exceptions:[{ruleId:'1',path:'/'}]}},bundle,5));
 assert.throws(()=>validateStoredWafEnvelope({...envelope,payload:Buffer.from(raw.toString().replace('OBSERVE','BLOCK')).toString('base64')}));
 const rollback=validateStoredWafEnvelope(signWafRuntime({...site,version:3},null,5));assert.equal(rollback.builtin,true);assert.deepEqual(rollback.files,[]);
 chmodSync(path,0o644);assert.throws(()=>signWafRuntime(site,bundle,5));
 }finally{if(before===undefined)delete process.env.WAF_RULE_SIGNING_KEY_FILE;else process.env.WAF_RULE_SIGNING_KEY_FILE=before;rmSync(root,{recursive:true,force:true});}
});

test('WAF deployment requires explicit bounded site selection and understandable reason',()=>{
 const id='00000000-0000-4000-8000-000000000001';assert.equal(wafRuntimeSelectionInput.safeParse({siteIds:[id],reason:'验证正常业务后观察发布'}).success,true);
 for(const siteIds of [[],[id,id],Array(21).fill(id)])assert.equal(wafRuntimeSelectionInput.safeParse({siteIds,reason:'验证正常业务后观察发布'}).success,false);
 assert.equal(wafRuntimeSelectionInput.safeParse({siteIds:[id],reason:'短'}).success,false);
});
