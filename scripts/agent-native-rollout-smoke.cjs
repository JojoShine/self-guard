// Real systemd upgrade, using the managed repository and target-scoped download grant.
const fs=require('node:fs'),path=require('node:path'),assert=require('node:assert/strict');
const {call,shell,loginFixture}=require('./agent-native-smoke.cjs');
const version=process.env.AGENT_ROLLOUT_VERSION||'0.2.8',architecture=process.env.AGENT_NATIVE_ARCH||'arm64';
const vm=process.env.AGENT_NATIVE_VM||'native-ubuntu24',server=process.env.AGENT_NATIVE_SERVER||'https://host.lima.internal:14410';
const resultFile=path.join('.artifacts/native-agent',vm==='native-ubuntu24'?'last-result.json':vm+'-result.json');
async function main(){
 await loginFixture();const previous=JSON.parse(fs.readFileSync(resultFile,'utf8'));assert.notEqual(previous.version,version,'run against a different signed version');
 const asset=await call('/assets/'+previous.assetId);assert.equal(asset.inventory.agentDiagnostics.managedReleaseDownload,true);assert.ok(asset.executorPublicKey);
 const envelope=JSON.parse(fs.readFileSync(path.join('.artifacts/releases',version,architecture,'release.json'),'utf8'));
 let release=(await call('/agent-releases?pageSize=100')).items.find(r=>r.version===version&&r.architecture===architecture);
 if(!release)release=await call('/agent-releases',envelope);
 if(release.status==='DRAFT'){await call('/agent-releases/'+release.id+'/artifact',fs.readFileSync(path.join('.artifacts/releases',version,architecture,'selfguard-agent')));release=await call('/agent-releases/'+release.id+'/publish',{});}
 const collectorPid=(await shell('systemctl show selfguard-collector --property=MainPID --value')).trim(),executorPid=(await shell('systemctl show selfguard-executor --property=MainPID --value')).trim();
 const rollout=await call('/rollouts',{managedReleaseId:release.id,manifestBytes:release.manifestBytes,signature:release.signature,artifactUrl:server+'/api/agent-releases/'+release.id+'/download',targetIds:[asset.id],batchSize:1});
 await call('/rollouts/'+rollout.id+'/approve',{targetIds:[asset.id]});
 console.log('Started managed upgrade on real systemd host: '+vm+' '+previous.version+' → '+version);
 let row;for(let i=0;i<100;i++){row=(await call('/rollouts')).find(r=>r.id===rollout.id);if(['COMPLETED','PAUSED','CANCELLED'].includes(row.status))break;await new Promise(r=>setTimeout(r,2500));}
 assert.equal(row.status,'COMPLETED',JSON.stringify(row.targets.map(t=>({status:t.status,evidence:t.evidence}))));
 const current=await call('/assets/'+asset.id);assert.equal(current.inventory.agentDiagnostics.version,version);assert.equal(current.id,asset.id);
 assert.equal((await shell('systemctl is-active selfguard-collector')).trim(),'active');assert.equal((await shell('systemctl is-active selfguard-executor')).trim(),'active');
 assert.notEqual((await shell('systemctl show selfguard-collector --property=MainPID --value')).trim(),collectorPid);assert.notEqual((await shell('systemctl show selfguard-executor --property=MainPID --value')).trim(),executorPid);
 const proof=JSON.parse(row.targets[0].evidence).executorResult;assert.equal(proof.success,true);assert.equal(proof.details.executorVersion,version);assert.notEqual(proof.details.executorProcess,proof.details.stageProcess);
 assert.equal((await shell('sha256sum /opt/selfguard-agent/current')).trim().split(/\s/)[0],release.sha256);
 const summary={at:new Date().toISOString(),vm,from:previous.version,to:version,assetId:asset.id,rolloutId:row.id,checks:['managed-artifact-grant','exact-program-sha256','root-executor-restart-proof','collector-restart','fresh-version-heartbeat','identity-retained']};
 fs.writeFileSync('.artifacts/native-agent/'+vm+'-rollout-result.json',JSON.stringify(summary),{mode:0o600});console.log('PASS: managed download, real executor and collector restarts, signed proof and fresh heartbeat');
}
main().catch(e=>{console.error(e.message);process.exitCode=1;});
