const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto'),{spawnSync}=require('node:child_process');
const root=path.resolve(__dirname,'..'),source=path.join(root,'services/access-probe');
function run(command,args,options={}){const result=spawnSync(command,args,{cwd:root,stdio:'inherit',...options});if(result.status!==0)throw new Error(command+' failed');return result;}
function sha(bytes){return crypto.createHash('sha256').update(bytes).digest('hex');}
function main(){
 const version=fs.readFileSync(path.join(source,'main.go'),'utf8').match(/const probeVersion = "([0-9]+\.[0-9]+\.[0-9]+)"/)?.[1];if(!version)throw new Error('Missing probe version');
 const directory=path.join(root,'.artifacts/releases/access-probe',version);if(fs.existsSync(directory))throw new Error('Package output already exists; refusing to overwrite');
 const cache=path.join(root,'.artifacts/access-probe-go-cache');fs.mkdirSync(cache,{recursive:true});fs.mkdirSync(directory,{recursive:true});
 const files=fs.readdirSync(source).filter(name=>name.endsWith('.go')||['go.mod','go.sum'].includes(name)).sort(),digest=crypto.createHash('sha256');for(const name of files){digest.update(name+'\0');digest.update(fs.readFileSync(path.join(source,name)));}
 const artifacts=[];
 for(const architecture of ['amd64','arm64']){
  const output=path.join(directory,'linux-'+architecture);fs.mkdirSync(output);
  run('docker',['run','--rm','--network','none','--cpus','2','--memory','1g','-v',source+':/src:ro','-v',output+':/out','-v',cache+':/cache','-w','/src','-e','GOMODCACHE=/cache/mod','-e','GOCACHE=/cache/build','-e','GOTOOLCHAIN=local','-e','GOOS=linux','-e','GOARCH='+architecture,'-e','CGO_ENABLED=0','golang:1.25.5','go','build','-buildvcs=false','-trimpath','-ldflags','-s -w','-o','/out/selfguard-access-probe','.']);
  const file='linux-'+architecture+'/selfguard-access-probe',bytes=fs.readFileSync(path.join(directory,file));artifacts.push({file,architecture,os:'linux',sha256:sha(bytes),bytes:bytes.length});
 }
 fs.copyFileSync(path.join(source,'README.md'),path.join(directory,'README.md'));
 const licenses=['LICENSE.golang','LICENSE.gopacket','LICENSE.go-x-sys','LICENSE.go-x-net'];for(const name of licenses)fs.copyFileSync(path.join(source,name),path.join(directory,name));
 fs.writeFileSync(path.join(directory,'manifest.json'),JSON.stringify({component:'selfguard-access-probe',version,channel:'local-validation',signed:false,sourceDigest:digest.digest('hex'),toolchain:'go1.25.5',artifacts},null,2)+'\n');
 const packaged=['README.md','manifest.json',...licenses,...artifacts.map(a=>a.file)];fs.writeFileSync(path.join(directory,'SHA256SUMS'),packaged.map(file=>sha(fs.readFileSync(path.join(directory,file)))+'  '+file).join('\n')+'\n');
 const archive=path.join(path.dirname(directory),'selfguard-access-probe-'+version+'-linux.tar.gz');run('tar',['-czf',archive,'-C',directory,...packaged,'SHA256SUMS'],{env:{...process.env,COPYFILE_DISABLE:'1'}});fs.writeFileSync(archive+'.sha256',sha(fs.readFileSync(archive))+'  '+path.basename(archive)+'\n');
 console.log('Built local validation package: '+archive+' (not a signed production promotion)');
}
try{main();}catch(error){console.error(error.message);process.exitCode=1;}
