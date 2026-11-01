import {installationDiagnostic} from './ssh-install-progress';
import {spawn} from 'node:child_process';import {mkdtemp,writeFile,rm} from 'node:fs/promises';import {join,resolve} from 'node:path';import {tmpdir} from 'node:os';import {passwordSshArguments} from './asset-remote-contract';
export class RemoteSshError extends Error{constructor(message:string,readonly uncertain=false){super(message)}}
export async function runPasswordSsh(access:{address:string;port:number;hostKey:string},password:string,command:string,input='',timeoutMs=30000){
 const directory=await mkdtemp(join(tmpdir(),'selfguard-remote-'));
 try{const passwordFile=join(directory,'password'),knownHosts=join(directory,'known_hosts');await writeFile(passwordFile,password,{mode:0o600});await writeFile(knownHosts,(access.port===22?access.address:'['+access.address+']:'+access.port)+' '+access.hostKey+'\n',{mode:0o600});
 return await new Promise<string>((resolveResult,reject)=>{const child=spawn(process.env.SSH_CLIENT_BINARY||'/usr/bin/ssh',passwordSshArguments(access.address,access.port,knownHosts,command),{stdio:['pipe','pipe','pipe'],env:{PATH:'/usr/local/bin:/usr/bin:/bin',LANG:'C',HOME:directory,DISPLAY:':0',SSH_ASKPASS_REQUIRE:'force',SSH_ASKPASS:resolve(__dirname,'../scripts/ssh-askpass.cjs'),SELFGUARD_SSH_PASSWORD_FILE:passwordFile}});let stdout='',diagnostic='',settled=false;
 const finish=(error?:Error)=>{if(settled)return;settled=true;clearTimeout(timer);error?reject(error):resolveResult(stdout)};
 const timer=setTimeout(()=>{child.kill('SIGKILL');finish(new RemoteSshError('连接或任务超时，执行结果需核对；未自动重复执行',true))},timeoutMs);
 child.stdout.on('data',part=>{stdout+=part.toString();if(Buffer.byteLength(stdout)>2*1048576){child.kill('SIGKILL');finish(new RemoteSshError('远程结果超出上限，需核对实际任务状态',true))}});child.stderr.on('data',part=>{if(diagnostic.length<16384)diagnostic+=part.toString().slice(0,16384-diagnostic.length)});child.once('error',()=>finish(new RemoteSshError('SSH 客户端无法启动，请联系平台管理员检查运行环境')));child.once('close',code=>{if(code===0)finish();else if(/Host key verification failed|REMOTE HOST IDENTIFICATION HAS CHANGED/.test(diagnostic))finish(new RemoteSshError('SSH 主机公钥不匹配，未信任该连接；请核对云主机身份'));
 else if(/Permission denied/.test(diagnostic))finish(new RemoteSshError('root 账号密码无效或主机未允许密码登录'));
 else if(/Connection refused|Connection timed out|No route to host/.test(diagnostic))finish(new RemoteSshError('SSH 连接不可用，请检查 IP、端口、网络及安全组'));
 else{const failure=installationDiagnostic(diagnostic);finish(failure?new RemoteSshError(failure.detail,failure.uncertain):new RemoteSshError('远程操作未确认完成，请检查 Agent 版本、安装路径、管理权限及目标主机结果',true));}});child.stdin.on('error',()=>{});child.stdin.end(input);
 });}finally{await rm(directory,{recursive:true,force:true})}
}
export const remoteProbeCommand=`bash -c 'set -euo pipefail
[ "$(id -u)" = 0 ]
printf "SELFGUARD_ROOT_OK\\n"
if [ -x /opt/selfguard-agent/current ]; then printf "SELFGUARD_AGENT_PRESENT\\n"; fi
for file in /sys/class/net/*; do name=$(basename "$file"); printf "INTERFACE:%s\\n" "$name"; done
'`;
