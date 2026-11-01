const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto'),{spawnSync}=require('node:child_process');
const root=path.resolve(__dirname,'..'),id=process.argv[2]||'debian-12-amd64';if(!/^(debian-(12|13)|ubuntu-(22\.04|24\.04)|rocky-9|alpine-3\.23)-amd64$/.test(id))throw Error('Frozen amd64 image ID required');
const dir=path.join(root,'.artifacts/native-qemu',id);fs.mkdirSync(dir,{recursive:true,mode:0o700});
function run(command,args){const r=spawnSync(command,args,{cwd:root,encoding:'utf8'});if(r.status!==0)throw Error(command+' failed: '+r.stderr);return r.stdout;}
async function main(){
 const entry=JSON.parse(fs.readFileSync('docs/implementation/Linux验收镜像.json','utf8')).entries.find(e=>e.id===id);if(!entry)throw Error('Pinned image metadata missing');const [algorithm,expected]=entry.digest.split(':'),hash=crypto.createHash(algorithm);for await(const b of fs.createReadStream(path.join(root,'.artifacts/tools',entry.filename)))hash.update(b);if(hash.digest('hex')!==expected)throw Error('Image not fully downloaded or checksum mismatch');
 run('docker',['exec','selfguard-qemu-fixture','test','-f','/vm/toolchain-ready']);
 run('docker',['exec','selfguard-qemu-fixture','python3','-c',`import pathlib
for p in pathlib.Path('/proc').iterdir():
 if not p.name.isdigit():continue
 try:
  if (p/'exe').resolve().name=='qemu-system-x86_64':assert b'file=/vm/${id}/disk.qcow2,if=virtio,format=qcow2' not in (p/'cmdline').read_bytes().split(bytes([0])),'Owned guest already running; preserve its PID, disk and configuration'
 except OSError:pass
`]);
 if(fs.realpathSync(dir)!==dir)throw Error('Owned guest directory must not be a symlink');
 const monitorFile=path.join(dir,'monitor.sock');if(fs.existsSync(monitorFile)){if(!fs.lstatSync(monitorFile).isSocket())throw Error('Unexpected monitor endpoint; retained');fs.unlinkSync(monitorFile);}
 const serialFile=path.join(dir,'serial.log');if(fs.existsSync(serialFile)&&fs.statSync(serialFile).size)fs.copyFileSync(serialFile,path.join(dir,'serial-'+Date.now()+'.log'),fs.constants.COPYFILE_EXCL);
 const hostKey=path.join(dir,'host_ed25519');if(!fs.existsSync(hostKey))run('ssh-keygen',['-q','-t','ed25519','-N','','-f',hostKey]);
 const client=fs.readFileSync('.artifacts/lima/_config/user.pub','utf8').trim(),hostPublic=fs.readFileSync(hostKey+'.pub','utf8').trim();
 const apiIP=run('docker',['inspect','--format','{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}','selfguard-native-api']).trim();if(!/^\d+\.\d+\.\d+\.\d+$/.test(apiIP))throw Error('Isolated API address missing');
 const userData={hostname:'qemu-'+id,manage_etc_hosts:true,disable_root:true,ssh_pwauth:false,users:[{name:'fixture',shell:'/bin/bash',lock_passwd:true,sudo:'ALL=(ALL) NOPASSWD:ALL',ssh_authorized_keys:[client]}],ssh_keys:{ed25519_private:fs.readFileSync(hostKey,'utf8'),ed25519_public:hostPublic},package_update:false,package_upgrade:false,runcmd:[['sh','-c',`echo '${apiIP} native-api' >> /etc/hosts`]]};
 const firmware=[];if(id==='alpine-3.23-amd64'){run('docker',['exec','selfguard-qemu-fixture','test','-f','/usr/share/OVMF/OVMF_CODE.fd']);firmware.push('-bios','/usr/share/OVMF/OVMF_CODE.fd');userData.runcmd.unshift(['apk','add','--no-progress','bash','curl','coreutils','ca-certificates','sudo','python3','openssh']);userData.users[0].lock_passwd=false;userData.runcmd.push(['rc-update','add','cgroups','sysinit'],['rc-service','cgroups','start'],['sh','-c',"(printf 'fixture:'; head -c 48 /dev/urandom | base64) | chpasswd"],['rc-update','add','sshd','default'],['rc-service','sshd','start']);}
 fs.writeFileSync(path.join(dir,'user-data'),'#cloud-config\n'+JSON.stringify(userData,null,2)+'\n',{mode:0o600});fs.writeFileSync(path.join(dir,'meta-data'),JSON.stringify({'instance-id':'selfguard-'+id+(id==='alpine-3.23-amd64'?'-ssh-v2':''),'local-hostname':'qemu-'+id}),{mode:0o600});fs.writeFileSync(path.join(dir,'known_hosts'),'[127.0.0.1]:22224 '+hostPublic.split(' ').slice(0,2).join(' ')+'\n',{mode:0o600});
 const inside='/vm/'+id;if(!fs.existsSync(path.join(dir,'disk.qcow2')))run('docker',['exec','selfguard-qemu-fixture','qemu-img','create','-f','qcow2','-F','qcow2','-b','/images/'+entry.filename,inside+'/disk.qcow2','16G']);
 run('docker',['exec','selfguard-qemu-fixture','cloud-localds',inside+'/seed.iso',inside+'/user-data',inside+'/meta-data']);
 run('docker',['exec','selfguard-qemu-fixture','qemu-system-x86_64','-machine','q35',...firmware,'-accel','tcg,thread=multi','-cpu','max','-smp','2','-m','1536','-drive','file='+inside+'/disk.qcow2,if=virtio,format=qcow2','-drive','file='+inside+'/seed.iso,if=virtio,format=raw,readonly=on','-netdev','user,id=net0,hostfwd=tcp:0.0.0.0:2222-:22','-device','virtio-net-pci,netdev=net0','-display','none','-serial','file:'+inside+'/serial.log','-monitor','unix:'+inside+'/monitor.sock,server=on,wait=off','-pidfile',inside+'/qemu.pid','-daemonize']);
 console.log('Started complete amd64 Linux guest '+id+' using software CPU emulation; no hardware-performance claim');
}
main().catch(e=>{console.error(e.message);process.exitCode=1;});
