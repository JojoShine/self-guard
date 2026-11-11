const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto'),{spawnSync}=require('node:child_process');
const root=path.resolve(__dirname,'..'),source=path.join(root,'services/suricata-bridge');
function run(cmd,args){const result=spawnSync(cmd,args,{cwd:root,stdio:'inherit'});if(result.status!==0)throw new Error(cmd+' failed');}
function sha(bytes){return crypto.createHash('sha256').update(bytes).digest('hex');}
function main(){
 const files=fs.readdirSync(source).filter(n=>n.endsWith('.go')||n==='go.mod').sort(),digest=crypto.createHash('sha256');for(const f of files){digest.update(f+'\0');digest.update(fs.readFileSync(path.join(source,f)));}
 const sourceDigest=digest.digest('hex'),version='0.1.0+'+sourceDigest.slice(0,12),directory=path.join(root,'.artifacts/releases/suricata-bridge',version),cache=path.join(root,'.artifacts/suricata-bridge-go-cache');
 if(fs.existsSync(directory))throw new Error('Package already exists; refusing to overwrite');fs.mkdirSync(directory,{recursive:true});fs.mkdirSync(cache,{recursive:true});
 const artifacts=[];for(const architecture of ['amd64','arm64']){const output=path.join(directory,'linux-'+architecture);fs.mkdirSync(output);run('docker',['run','--rm','--network','none','--cpus','2','--memory','1g','-v',source+':/src:ro','-v',output+':/out','-v',cache+':/cache','-w','/src','-e','GOTOOLCHAIN=local','-e','GOCACHE=/cache/build','-e','GOOS=linux','-e','GOARCH='+architecture,'-e','CGO_ENABLED=0','golang:1.25.5','go','build','-buildvcs=false','-trimpath','-ldflags','-s -w -X main.version='+version,'-o','/out/selfguard-suricata-bridge','.']);const file='linux-'+architecture+'/selfguard-suricata-bridge',bytes=fs.readFileSync(path.join(directory,file));artifacts.push({file,architecture,os:'linux',sha256:sha(bytes),bytes:bytes.length});}
 for(const name of ['README.md','LICENSE.golang'])fs.copyFileSync(path.join(source,name),path.join(directory,name));fs.cpSync(path.join(root,'deploy/suricata'),path.join(directory,'deploy'),{recursive:true});
 fs.writeFileSync(path.join(directory,'manifest.json'),JSON.stringify({component:'selfguard-suricata-bridge',version,sourceDigest,toolchain:'go1.25.5',channel:'local-validation',signed:false,artifacts},null,2)+'\n');
 const packaged=['README.md','LICENSE.golang','manifest.json',...artifacts.map(a=>a.file),...fs.readdirSync(path.join(directory,'deploy')).sort().map(n=>'deploy/'+n)];fs.writeFileSync(path.join(directory,'SHA256SUMS'),packaged.map(f=>sha(fs.readFileSync(path.join(directory,f)))+'  '+f).join('\n')+'\n');
 const archive=path.join(path.dirname(directory),'selfguard-suricata-bridge-'+version+'-linux.tar.gz');run('tar',['-czf',archive,'-C',directory,...packaged,'SHA256SUMS']);fs.writeFileSync(archive+'.sha256',sha(fs.readFileSync(archive))+'  '+path.basename(archive)+'\n');console.log('Built local validation package: '+archive);
}
try{main();}catch(error){console.error(error.message);process.exitCode=1;}
