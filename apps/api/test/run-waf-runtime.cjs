// The publication gate is enabled only for this disposable acceptance server.
const {generateKeyPairSync}=require('node:crypto'),{mkdtempSync,writeFileSync,rmSync}=require('node:fs'),{tmpdir}=require('node:os'),{join}=require('node:path'),{spawnSync}=require('node:child_process');
const directory=mkdtempSync(join(tmpdir(),'selfguard-waf-runtime-')),key=join(directory,'private');
try{
 const {privateKey}=generateKeyPairSync('ed25519');writeFileSync(key,privateKey.export({format:'der',type:'pkcs8'}).toString('base64'),{mode:0o600});
 const result=spawnSync(process.execPath,['test/run-isolated-http.cjs','/workspace/scripts/waf-runtime-api-smoke.cjs'],{stdio:'inherit',env:{...process.env,WAF_RULE_RUNTIME_ENABLED:'true',WAF_RULE_SIGNING_KEY_FILE:key}});process.exitCode=result.status??1;
}finally{rmSync(directory,{recursive:true,force:true});}
