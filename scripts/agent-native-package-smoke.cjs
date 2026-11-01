// Real package-manager verification. Packages supply payload only; they must not
// restart an existing Agent or change its durable identity/configuration.
const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto'),assert=require('node:assert/strict');
const {shell}=require('./agent-native-smoke.cjs');
const version=process.env.AGENT_NATIVE_VERSION||'0.3.8',arch=process.env.AGENT_NATIVE_ARCH||'arm64',format=process.env.AGENT_PACKAGE_FORMAT||'deb',vm=process.env.AGENT_NATIVE_VM||'native-ubuntu24';
assert.match(version,/^\d+\.\d+\.\d+$/);assert.ok(['arm64','amd64'].includes(arch));assert.ok(['deb','rpm'].includes(format));
const quote=value=>"'"+value.replace(/'/g,"'\\''")+"'";
async function main(){
 const base=path.join('.artifacts/releases',version),metadata=JSON.parse(fs.readFileSync(path.join(base,'packages',arch,format+'.json'))),bytes=fs.readFileSync(path.join(base,metadata.filename)),raw=Buffer.from(metadata.envelope.manifestBytes,'base64'),manifest=JSON.parse(raw);
 const root=fs.readFileSync('.env','utf8').match(/^AGENT_UPGRADE_PUBLIC_KEY=(.+)$/m)[1].trim(),key=crypto.createPublicKey({key:Buffer.concat([Buffer.from('302a300506032b6570032100','hex'),Buffer.from(root,'base64')]),format:'der',type:'spki'});
 assert.ok(crypto.verify(null,raw,key,Buffer.from(metadata.envelope.signature,'base64')));assert.equal(crypto.createHash('sha256').update(bytes).digest('hex'),manifest.sha256);
 const snapshot=()=>shell('sudo sha256sum /var/lib/selfguard-agent/identity.json /etc/selfguard-agent/collector.json; systemctl show selfguard-collector --property=MainPID --value');
 const before=await snapshot(),temporary='/tmp/selfguard-native-package.'+format;
 await shell('umask 077; base64 -d > '+temporary,bytes.toString('base64'));
 assert.equal((await shell('sha256sum '+temporary)).trim().split(/\s/)[0],manifest.sha256);
 try {
  await shell(format==='deb'?'sudo dpkg --install '+temporary:'sudo rpm --upgrade --replacepkgs '+temporary);
  const info=(await shell(format==='deb'?"dpkg-query -W -f='${Version} ${Architecture}' selfguard-agent":"rpm -q --qf '%{VERSION} %{ARCH}' selfguard-agent")).trim();assert.equal(info,version+' '+(format==='deb'?arch:arch==='arm64'?'aarch64':'x86_64'));
  const target='/usr/lib/selfguard-agent/releases/'+version+'/selfguard-agent';assert.equal((await shell(quote(target)+' --self-test')).trim(),'selfguard-agent: healthy');assert.equal((await shell('sha256sum '+quote(target))).trim().split(/\s/)[0],manifest.executableSha256);
  assert.equal(await snapshot(),before,'package installation changed identity, configuration or process');
  await shell(format==='deb'?'sudo dpkg --remove selfguard-agent':'sudo rpm --erase selfguard-agent');assert.equal(await snapshot(),before,'package removal changed identity, configuration or process');
  fs.writeFileSync('.artifacts/native-agent/'+vm+'-package-result.json',JSON.stringify({at:new Date().toISOString(),version,arch,format,sha256:manifest.sha256,checks:['independent-package-signature','real-package-manager','version-and-architecture','exact-executable','self-test','service-config-identity-unchanged','payload-removal-retains-state']}),{mode:0o600});console.log('PASS: '+vm+' '+format+' signature, actual installation/removal, exact executable and unchanged running service/identity');
 } finally {await shell('rm -f '+temporary)}
}
main().catch(e=>{console.error(e.message);process.exitCode=1});
