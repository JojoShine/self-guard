const fs=require('node:fs'),path=require('node:path'),{spawnSync}=require('node:child_process');
const api=path.resolve(__dirname,'..'),root=path.resolve(api,'../..');
function run(command,args,options={}){
 const result=spawnSync(command,args,{cwd:api,stdio:'inherit',...options});
 if(result.error)throw new Error(command+' 无法启动：'+result.error.message);
 if(result.status!==0)throw new Error(command+' 执行失败（'+(result.status??result.signal)+'）');
}
function executable(file){try{fs.accessSync(file,fs.constants.X_OK);return true}catch{return false}}
function prepareScanner(){
 if(process.env.SCAN_WORKER_BINARY){const file=path.resolve(api,process.env.SCAN_WORKER_BINARY);if(!executable(file))throw new Error('SCAN_WORKER_BINARY 不存在或不可执行');return file;}
 for(const file of ['/opt/selfguard/scanner','/usr/local/bin/selfguard-scanner'])if(executable(file))return file;
 const source=path.join(root,'services/scanner');if(!fs.existsSync(path.join(source,'go.mod')))throw new Error('未找到扫描器源码，请在容器中配置 SCAN_WORKER_BINARY 指向已交付的扫描器');
 const goos={darwin:'darwin',linux:'linux',win32:'windows'}[process.platform],goarch={x64:'amd64',arm64:'arm64'}[process.arch];
 if(!goos||!goarch)throw new Error('请为当前系统配置可执行的 SCAN_WORKER_BINARY');
 const output=path.join(root,'.artifacts/bin'),cache=path.join(root,'.artifacts/scanner-test-cache');fs.mkdirSync(output,{recursive:true});fs.mkdirSync(cache,{recursive:true});
 const file=path.join(output,'scanner-'+process.platform+'-'+process.arch+(process.platform==='win32'?'.exe':'')),candidate=file+'.pending-'+process.pid;
 const args=['build','-buildvcs=false','-trimpath','-o',candidate,'./cmd/scanner'];
 const go=spawnSync('go',['version'],{encoding:'utf8'});
 try{
  if(go.status===0)run('go',args,{cwd:source,env:{...process.env,GOOS:goos,GOARCH:goarch,CGO_ENABLED:'0',GOTOOLCHAIN:'local',GOCACHE:cache}});
  else{
   // Cross-compile a host-native worker; Linux executables cannot run in macOS tests.
   const image=process.env.SCAN_TEST_GO_IMAGE||'golang:1.25.5-alpine';
   run('docker',['run','--rm','--pull','never','--network','none','--cpus','2','--memory','1g','-v',source+':/src:ro','-v',output+':/out','-v',cache+':/cache','-w','/src','-e','GOOS='+goos,'-e','GOARCH='+goarch,'-e','CGO_ENABLED=0','-e','GOTOOLCHAIN=local','-e','GOCACHE=/cache','-e','GOMAXPROCS=2',image,'go',...args.slice(0,4),'/out/'+path.basename(candidate),'./cmd/scanner']);
  }
  fs.chmodSync(candidate,0o755);fs.renameSync(candidate,file);
 }finally{if(fs.existsSync(candidate))fs.unlinkSync(candidate)}
 return file;
}
try{
 const scanner=prepareScanner(),args=process.argv.slice(2);
 if(args.length===1&&args[0]==='--prepare-only'){console.log(scanner);}
 else{
  const files=args.some(arg=>/\.test\.(?:ts|js|cjs|mjs)$/.test(arg))?[]:fs.readdirSync(path.join(api,'test')).filter(name=>name.endsWith('.test.ts')).sort().map(name=>'test/'+name);
  const result=spawnSync(process.execPath,['--import','tsx','--test','--test-concurrency=1',...args,...files],{cwd:api,env:{...process.env,SCAN_WORKER_BINARY:scanner},stdio:'inherit'});
  if(result.error)throw result.error;process.exitCode=result.status??1;
 }
}catch(error){console.error(error.message);process.exitCode=1;}
