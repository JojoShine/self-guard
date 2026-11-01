// Latest-release contracts on a project-owned systemd guest; never a build-only
// substitute for actual package inventory, signed repair and fresh heartbeat.
const fs=require('node:fs'),assert=require('node:assert/strict');
const {call,shell,loginFixture}=require('./agent-native-smoke.cjs');
const vm=process.env.AGENT_NATIVE_VM||'native-ubuntu24',architecture=process.env.AGENT_NATIVE_ARCH||'arm64',version='0.4.0';
async function main(){
 assert.match(vm,/^(native-(ubuntu24|ubuntu22-arm64|debian-(12|13)-arm64|rocky-9-arm64)|qemu-(debian-(12|13)|ubuntu-(22\.04|24\.04)|rocky-9)-amd64)$/);assert.ok(['arm64','amd64'].includes(architecture));
 const previous=JSON.parse(fs.readFileSync('.artifacts/native-agent/'+vm+'-applications-040.json'));assert.equal(previous.version,version);assert.equal(previous.architecture,architecture);await loginFixture();
 const envelope=JSON.parse(fs.readFileSync('.artifacts/releases/'+version+'/'+architecture+'/release.json')),release=JSON.parse(Buffer.from(envelope.manifestBytes,'base64')),config=JSON.parse(await shell('sudo cat /etc/selfguard-agent/collector.json'));
 let asset=await call('/assets/'+previous.assetId);assert.equal(asset.business,'native-acceptance');assert.equal(asset.inventory.agentDiagnostics.version,version);assert.equal(asset.inventory.architecture,architecture);assert.equal((await shell('sudo sha256sum /opt/selfguard-agent/current')).split(/\s/)[0],release.sha256);
 assert.equal((await shell('systemctl show selfguard-collector --property=User --value')).trim(),'selfguard-agent');assert.equal((await shell('systemctl is-active selfguard-collector')).trim(),'active');assert.equal(asset.inventory.packageCollection.complete,true,asset.inventory.packageCollection.reason);assert.ok(asset.inventory.packages.length>0);
 const distro=asset.inventory.distribution.id;
 for(const pkg of asset.inventory.packages){assert.ok(pkg.architecture);if(['debian','ubuntu'].includes(distro)){assert.equal(pkg.manager,'dpkg');assert.ok(pkg.origin&&pkg.sourceVersion)}else if(distro==='rocky'){assert.equal(pkg.manager,'rpm');assert.match(pkg.epoch,/^\d+$/);assert.ok(pkg.version.startsWith(pkg.epoch+':'))}else assert.fail('Unapproved native distribution')}
 assert.ok(config.ExecutorSocket,'This contract requires an explicitly enabled executor');const executor=JSON.parse(await shell('sudo cat /etc/selfguard-agent/executor.json'));assert.equal(executor.AllowedRoot,'/srv/selfguard-native','Do not write outside the known owned repair fixture');
 const filename='/srv/selfguard-native/config-latest-040';await shell('sudo touch '+filename+' && sudo chmod 0666 '+filename);
 const task=await call('/tasks',{title:'Owned latest 0.4.0 native permission verification',assetId:asset.id,template:'FILE_PERMISSION',parameters:{path:filename,mode:'0600'}});await call('/tasks/'+task.id+'/approve',{});
 let completed;for(let attempt=0;attempt<96;attempt++){completed=await call('/tasks/'+task.id);if(['SUCCEEDED','FAILED','UNKNOWN','EXPIRED'].includes(completed.status))break;await new Promise(resolve=>setTimeout(resolve,1500))}
 assert.equal(completed.status,'SUCCEEDED');assert.equal(completed.verification.actor,'independent-agent-read');assert.equal((await shell('stat -c %a '+filename)).trim(),'600');
 const began=Date.now();await shell('sudo systemctl restart selfguard-collector');for(let attempt=0;attempt<60;attempt++){asset=await call('/assets/'+asset.id);if(Date.parse(asset.lastSeen)>began)break;await new Promise(resolve=>setTimeout(resolve,2000))}
 assert.ok(Date.parse(asset.lastSeen)>began);assert.equal(asset.inventory.agentDiagnostics.version,version);assert.equal(asset.id,previous.assetId);await shell('sudo rm -f '+filename);
 const report={at:new Date().toISOString(),vm,version,architecture,distribution:distro,assetId:asset.id,sha256:release.sha256,packages:asset.inventory.packages.length,taskId:task.id,checks:['actual-frozen-sha','nonroot-systemd','actual-package-metadata','signed-real-chmod','independent-agent-read','restart-fresh-version-identity']};fs.writeFileSync('.artifacts/native-agent/'+vm+'-latest-contract-040.json',JSON.stringify(report,null,2),{mode:0o600});console.log(JSON.stringify({...report,assetId:undefined,taskId:undefined}));
}
main().catch(error=>{console.error(error.message);process.exitCode=1});
