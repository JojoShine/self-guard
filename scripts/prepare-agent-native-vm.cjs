const fs=require('node:fs'),path=require('node:path'),{createHash}=require('node:crypto'),{spawnSync}=require('node:child_process');
const root=path.resolve(__dirname,'..'),tools=path.join(root,'.artifacts/tools'),directory=path.join(root,'.artifacts/native-agent');
function verify(name,expected){const actual=createHash('sha256').update(fs.readFileSync(path.join(tools,name))).digest('hex');if(actual!==expected)throw Error(name+' checksum mismatch');}
function run(command,args,env){const r=spawnSync(command,args,{cwd:root,env:env||process.env,stdio:'inherit'});if(r.status!==0)throw Error(command+' failed');}
try{
 if(process.platform!=='darwin'||process.arch!=='arm64')throw Error('This fixture uses native macOS ARM virtualization');
 verify('lima-2.2.1-Darwin-arm64.tar.gz','9e9eacce88f37e185c346bad73aa6136f738d8cdf8c3bb23cd42b071824bc66e');
 verify('ubuntu-24.04-minimal-arm64.img','fbf6b15c50c474dc6dee5b3c74da212bb687a2625e877227828e6492d88dc151');
 const toolRoot=path.join(tools,'lima');fs.mkdirSync(toolRoot,{recursive:true});run('tar',['-xzf',path.join(tools,'lima-2.2.1-Darwin-arm64.tar.gz'),'-C',toolRoot]);
 fs.mkdirSync(directory,{recursive:true,mode:0o700});const vmFile=path.join(directory,'ubuntu24.yaml');fs.writeFileSync(vmFile,fs.readFileSync(path.join(root,'scripts/native-ubuntu24.yaml'),'utf8').replace('../.artifacts/tools/ubuntu-24.04-minimal-arm64.img',JSON.stringify(path.join(tools,'ubuntu-24.04-minimal-arm64.img'))));
 const env={...process.env,LIMA_HOME:path.join(root,'.artifacts/lima'),XDG_CACHE_HOME:path.join(root,'.artifacts/lima-cache')};
 const binary=path.join(toolRoot,'bin/limactl');run(binary,['validate',vmFile],env);
 if(!fs.existsSync(path.join(env.LIMA_HOME,'native-ubuntu24'))){run(binary,['create','--name=native-ubuntu24','--tty=false',vmFile],env);}
 run(binary,['start','--tty=false','native-ubuntu24'],env);
}catch(e){console.error(e.message);process.exitCode=1;}
