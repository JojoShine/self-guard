const fs=require('node:fs'),assert=require('node:assert/strict');
process.env.AGENT_NATIVE_VM='native-ssh24';
const{call,shell,loginFixture}=require('./agent-native-smoke.cjs');
async function main(){
 await loginFixture();const prior=JSON.parse(fs.readFileSync('.artifacts/native-agent/ssh-result.json','utf8'));
 const identity=JSON.parse(await shell('sudo cat /var/lib/selfguard-agent/identity.json'));assert.equal(identity.assetId,prior.assetId);
 await shell('sudo systemctl stop selfguard-collector');
 for(const old of (await call('/tasks?assetId='+prior.assetId+'&pageSize=100')).items.filter(t=>t.title==='Native uninstall precheck fixture'&&['PENDING','APPROVED'].includes(t.status)))await call('/workflows/tasks/'+old.id+'/cancel',{reason:'Reconcile prior unused native uninstall fixture'});
 const task=await call('/tasks',{title:'Native uninstall precheck fixture',assetId:prior.assetId,template:'FILE_PERMISSION',parameters:{path:'/srv/selfguard-native/uninstall-fixture',mode:'0600'}});await call('/tasks/'+task.id+'/approve',{});
 await assert.rejects(()=>shell('sudo /opt/selfguard-agent/current --uninstall'),/platform blocked uninstall/);await shell('test -e /etc/systemd/system/selfguard-collector.service');
 await call('/workflows/tasks/'+task.id+'/cancel',{reason:'Cancel unused native uninstall guard fixture'});console.log('PASS: pending approved work blocks uninstall and keeps service files');
 await shell('sudo /opt/selfguard-agent/current --uninstall');await shell('! systemctl is-active --quiet selfguard-collector && sudo test -e /var/lib/selfguard-agent/identity.json && test -e /opt/selfguard-agent/current');
 const asset=await call('/assets/'+prior.assetId);assert.equal(asset.id,prior.assetId);await assert.rejects(()=>call('/agent/tasks',undefined,'GET',identity.token),/status 401/);assert.equal((await call('/tasks/'+task.id)).status,'CANCELLED');console.log('PASS: actual services removed, credential revoked, identity and platform asset/task history retained');
 fs.writeFileSync('.artifacts/native-agent/uninstall-result.json',JSON.stringify({at:new Date().toISOString(),assetId:prior.assetId,checks:['approved-task-precheck','actual-service-uninstall','credential-revoked','local-identity-retained','platform-history-retained']}),{mode:0o600});
}
main().catch(e=>{console.error(e.message);process.exitCode=1;});
