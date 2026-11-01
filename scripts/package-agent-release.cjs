const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto'),{spawnSync}=require('node:child_process');
const {key}=require('./build-agent-release.cjs').releaseKey();
const project=path.resolve(__dirname,'..'),version=process.argv[2];if(!/^\d+\.\d+\.\d+(?:[-+][A-Za-z0-9.-]+)?$/.test(version||''))throw Error('Usage: package-agent-release.cjs VERSION');
function run(cmd,args){const result=spawnSync(cmd,args,{stdio:'inherit'});if(result.status!==0)throw Error(cmd+' failed');}
function arEntry(name,bytes){let header=name.padEnd(16)+'0'.padEnd(12)+'0'.padEnd(6)+'0'.padEnd(6)+'100644'.padEnd(8)+String(bytes.length).padEnd(10)+'`\n';return Buffer.concat([Buffer.from(header),bytes,bytes.length%2?Buffer.from('\n'):Buffer.alloc(0)]);}
for(const arch of (process.argv[3]?[process.argv[3]]:['amd64','arm64'])){
 const base=path.join(project,'.artifacts/releases',version),source=path.join(base,arch),work=path.join(base,'packaging-'+arch);fs.mkdirSync(work,{recursive:false});
 const content=path.join(work,'data/usr/lib/selfguard-agent/releases',version);fs.mkdirSync(content,{recursive:true});for(const file of ['selfguard-agent','release.json','manifest.json','manifest.sig','sbom.json'])fs.copyFileSync(path.join(source,file),path.join(content,file));fs.chmodSync(path.join(content,'selfguard-agent'),0o755);
 const control=path.join(work,'control');fs.mkdirSync(control);fs.writeFileSync(path.join(control,'control'),`Package: selfguard-agent\nVersion: ${version}\nArchitecture: ${arch}\nMaintainer: Self Guard local build\nDescription: Signed Self Guard Agent installation payload\n This package supplies a signed payload. Use the authorized installer to register and configure services.\n`);
 run('tar',['--uid','0','--gid','0','--no-xattrs','-czf',path.join(work,'control.tar.gz'),'-C',control,'.']);run('tar',['--uid','0','--gid','0','--no-xattrs','-czf',path.join(work,'data.tar.gz'),'-C',path.join(work,'data'),'.']);
 const deb=Buffer.concat([Buffer.from('!<arch>\n'),arEntry('debian-binary/',Buffer.from('2.0\n')),arEntry('control.tar.gz/',fs.readFileSync(path.join(work,'control.tar.gz'))),arEntry('data.tar.gz/',fs.readFileSync(path.join(work,'data.tar.gz')))]);
 fs.writeFileSync(path.join(base,`selfguard-agent_${version}_${arch}.deb`),deb,{flag:'wx'});
 const rpmRoot=path.join(work,'rpm');for(const folder of ['BUILD','BUILDROOT','RPMS','SOURCES','SPECS','SRPMS'])fs.mkdirSync(path.join(rpmRoot,folder),{recursive:true});
 const rpmArch=arch==='amd64'?'x86_64':'aarch64',spec=path.join(rpmRoot,'SPECS/agent.spec');
 fs.writeFileSync(spec,`Name: selfguard-agent\nVersion: ${version.split('-')[0]}\nRelease: 1\nSummary: Signed Self Guard Agent installation payload\nLicense: LicenseRef-SelfGuard-Internal\nAutoReqProv: no\n%description\nSigned Agent payload. Authorized installation separately registers identity and configures services.\n%prep\n%build\n%install\nmkdir -p %{buildroot}/usr/lib/selfguard-agent/releases/${version}\ncp -R "${content}/." %{buildroot}/usr/lib/selfguard-agent/releases/${version}/\n%files\n/usr/lib/selfguard-agent/releases/${version}\n`);
 run('rpmbuild',['--define','_topdir '+rpmRoot,'--define','_tmppath '+work,'--define','_build_id_links none','--define','__os_install_post %{nil}','--define','_target_os linux','--target',rpmArch+'-linux','-bb',spec]);
 const rpmFiles=fs.readdirSync(path.join(rpmRoot,'RPMS',rpmArch));for(const file of rpmFiles)fs.copyFileSync(path.join(rpmRoot,'RPMS',rpmArch,file),path.join(base,file),fs.constants.COPYFILE_EXCL);
 const metadata=path.join(base,'packages',arch);fs.mkdirSync(metadata,{recursive:true});const executable=JSON.parse(fs.readFileSync(path.join(source,'manifest.json'),'utf8'));
 for(const [format,filename]of [['tar.gz',`selfguard-agent-${version}-linux-${arch}.tar.gz`],['deb',`selfguard-agent_${version}_${arch}.deb`],['rpm',rpmFiles[0]]]){
  const bytes=fs.readFileSync(path.join(base,filename)),manifest={kind:'selfguard-agent-package-v1',version,architecture:arch,os:'linux',format,executableSha256:executable.sha256,sha256:crypto.createHash('sha256').update(bytes).digest('hex'),size:bytes.length,expiresAt:executable.expiresAt},raw=Buffer.from(JSON.stringify(manifest)),envelope={manifestBytes:raw.toString('base64'),signature:crypto.sign(null,raw,key).toString('base64')};fs.writeFileSync(path.join(metadata,format+'.json'),JSON.stringify({filename,envelope},null,2),{flag:'wx'});
 }
 console.log('Packaged deb/rpm for '+arch+'; native service installation remains a separate acceptance step.');
}
