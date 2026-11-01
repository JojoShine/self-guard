// Exercise rollback on the exact current release, retaining each owned guest's
// real profile. Fault injection rejects only the candidate CPU limit.
const fs=require('node:fs'),assert=require('node:assert/strict');
const {call,shell,lima,loginFixture,ca}=require('./agent-native-smoke.cjs');
const vm=process.env.AGENT_NATIVE_VM||'native-ubuntu24',architecture=process.env.AGENT_NATIVE_ARCH||'arm64',version='0.4.0';
async function main(){
 assert.match(vm,/^native-(ubuntu24|ubuntu22-arm64|debian-(12|13)-arm64|rocky-9-arm64)$/);assert.equal(architecture,'arm64');
 await loginFixture();
 const config=JSON.parse(await shell('sudo cat /etc/selfguard-agent/collector.json')),executor=config.ExecutorSocket?JSON.parse(await shell('sudo cat /etc/selfguard-agent/executor.json')):null;
 assert.match(config.StateDir,/^\/var\/lib\/selfguard-agent(?:-profile)?$/);const identity=JSON.parse(await shell('sudo cat '+config.StateDir+'/identity.json'));assert.ok(identity.assetId);
 const asset=await call('/assets/'+identity.assetId);assert.equal(asset.business,'native-acceptance');assert.equal(asset.inventory.agentDiagnostics.version,version);
 const release=(await call('/agent-releases?pageSize=100')).items.find(row=>row.version===version&&row.architecture===architecture&&row.status==='PUBLISHED');assert.ok(release);
 const manifest=JSON.parse(Buffer.from(release.manifestBytes,'base64'));assert.equal((await shell('sudo sha256sum /opt/selfguard-agent/current')).split(/\s/)[0],manifest.sha256);
 const files=['/opt/selfguard-agent/current','/opt/selfguard-agent/installed.json','/opt/selfguard-agent/installation-slot.json','/etc/selfguard-agent/collector.json',...(executor?['/etc/selfguard-agent/executor.json']:[])],before={};
 for(const file of files)before[file]=(await shell('sudo sha256sum '+file)).split(/\s/)[0];
 assert.ok(Number.isInteger(config.CPUQuotaPercent)&&config.CPUQuotaPercent>=1&&config.CPUQuotaPercent<=100);const quota=config.CPUQuotaPercent>1?config.CPUQuotaPercent-1:2;
 const profile={releaseId:release.id,server:config.Server,business:'native-acceptance',caCertificate:ca,stateDir:config.StateDir,proxyUrl:config.ProxyURL||undefined,collectionRoot:config.AllowedRoot||undefined,fimPaths:config.FIMPaths,logPaths:config.LogPaths,maxCPUs:config.MaxCPUs,maxMemoryBytes:config.MaxMemoryBytes,maxQueueBytes:config.MaxQueueBytes,bytesPerSecond:config.BytesPerSecond,cpuQuotaPercent:quota,executorEnabled:!!executor,...(executor?{allowedRoot:executor.AllowedRoot,allowedServices:executor.AllowedServices||[]}: {})};
 const hookPath='/etc/systemd/system/selfguard-collector.service.d/owned-latest-failure.conf',local='.artifacts/native-agent/'+vm+'-latest-failure-hook.conf',hook='[Service]\nExecStartPre=/usr/bin/python3 -c "import json,sys; sys.exit(json.load(open(\'/etc/selfguard-agent/collector.json\'))[\'CPUQuotaPercent\'] == '+quota+')"\n';
 await shell('sudo test ! -e '+hookPath);fs.writeFileSync(local,hook,{mode:0o600});await lima(['copy',local,vm+':/tmp/owned-latest-failure.conf']);await shell('sudo install -d /etc/systemd/system/selfguard-collector.service.d && sudo install -m 0644 /tmp/owned-latest-failure.conf '+hookPath+' && sudo systemctl daemon-reload');
 try{
  const began=Date.now(),task=await call('/agent-installations',profile),{installationCommand}=await import('../apps/web/src/agent-installation.ts'),host=new URL(config.Server).hostname;assert.ok(['host.lima.internal','native-api'].includes(host));
  let failed=false;try{await shell(installationCommand({...task,release}).replace(/^sudo bash /,'sudo /usr/bin/env NO_PROXY='+host+',127.0.0.1 no_proxy='+host+',127.0.0.1 bash '),task.ticket+'\n')}catch{failed=true}assert.ok(failed,'Owned start hook did not reject candidate');
  const result=(await call('/agent-installations?q='+task.id)).items.find(row=>row.id===task.id);assert.ok(['FAILED','RECOVERED'].includes(result?.status));
  for(const file of files)assert.equal((await shell('sudo sha256sum '+file)).split(/\s/)[0],before[file],'Rollback changed '+file);
  assert.equal(JSON.parse(await shell('sudo cat '+config.StateDir+'/identity.json')).Identity,identity.Identity);assert.equal(JSON.parse(await shell('sudo cat /opt/selfguard-agent/highest-sequence.json')).sequence,manifest.sequence);assert.equal((await shell('systemctl is-active selfguard-collector')).trim(),'active');if(executor)assert.equal((await shell('systemctl is-active selfguard-executor')).trim(),'active');
  let fresh;for(let attempt=0;attempt<60;attempt++){fresh=await call('/assets/'+asset.id);if(Date.parse(fresh.lastSeen)>began)break;await new Promise(resolve=>setTimeout(resolve,2000))}assert.ok(Date.parse(fresh.lastSeen)>began);assert.equal(fresh.inventory.agentDiagnostics.version,version);
  fs.writeFileSync('.artifacts/native-agent/'+vm+'-latest-failure-040.json',JSON.stringify({at:new Date().toISOString(),vm,version,architecture,assetId:asset.id,installationId:task.id,sha256:manifest.sha256,checks:['real-candidate-systemd-start-failure','exact-program-and-profile-rollback','original-services-active','identity-and-highest-sequence-retained','fresh-original-version-heartbeat']},null,2),{mode:0o600});console.log('PASS latest real service-start rollback, profile, identity, sequence and fresh heartbeat: '+vm);
 }finally{await shell('sudo rm '+hookPath+' /tmp/owned-latest-failure.conf && sudo systemctl daemon-reload');fs.rmSync(local,{force:true})}
}
main().catch(error=>{console.error(error.message);process.exitCode=1});
