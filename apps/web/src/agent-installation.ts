import {platformURL} from './urls';
export function supportsPlatformAgent(version:string,server?:string){const match=/^(\d+)\.(\d+)\.(\d+)/.exec(version);if(!match)return false;const[,major,minor,patch]=match.map(Number);if(server&&new URL(server).pathname.replace(/\/$/,'')&&!(major>0||minor>4||minor===4&&patch>=11))return false;return !server?.startsWith('http:')||supportsHTTPAgent(version);}
export function supportsHTTPAgent(version:string){const match=/^(\d+)\.(\d+)\.(\d+)/.exec(version);if(!match)return false;const[,major,minor,patch]=match.map(Number);return major>0||minor>4||minor===4&&patch>=10;}
export function offlineInstallationProfile(task:any):Record<string,unknown>|undefined{
 const [major,minor]=task.release.version.split('.').map(Number);
 if(!(major>0||major===0&&minor>=4))return undefined;
 const fields=['server','stateDir','proxyMode','proxyUrl','collectionRoot','applicationInputs','fimPaths','logPaths','logIncludeMessage','maxCPUs','maxMemoryBytes','maxQueueBytes','bytesPerSecond','cpuQuotaPercent','executorEnabled','allowedRoot','allowedServices','caCertificate'];
 return Object.fromEntries(fields.filter(name=>task.profile[name]!==undefined).map(name=>[name,task.profile[name]]));
}

export function installationCommand(task:any){
 const {id,profile,release,trustRoot}=task;
 if(!/^[a-f0-9-]{36}$/.test(id)||!/^[a-f0-9]{64}$/.test(release?.sha256)||!/^[A-Za-z0-9+/=_-]+$/.test(trustRoot))throw new Error('安装参数不完整');
 const server=new URL(profile.server);if(!['http:','https:'].includes(server.protocol)||server.username||server.password||server.search||server.hash||!platformURL(profile.server))throw new Error('安装需要 HTTP 或 HTTPS 平台根地址');
 if(profile.stateDir&&!/^\/var\/lib\/selfguard-agent(?:-[a-z0-9][a-z0-9-]{0,40})?$/.test(profile.stateDir))throw new Error('状态目录不在允许范围');
 if(profile.proxyUrl){const proxy=new URL(profile.proxyUrl);if(!['http:','https:'].includes(proxy.protocol)||proxy.username||proxy.password||proxy.search||proxy.hash||proxy.pathname!=='/')throw new Error('代理需要不含凭据的 HTTP(S) 根地址');}
 const proxyMode=profile.proxyMode||(profile.proxyUrl?'EXPLICIT':'ENVIRONMENT');if(!['DIRECT','EXPLICIT','ENVIRONMENT'].includes(proxyMode)||(proxyMode==='EXPLICIT')!==!!profile.proxyUrl)throw new Error('代理方式与代理地址不一致');
 const quote=(s:string)=>"'"+s.replace(/'/g,"'\\''")+"'";
 // Credentials travel through stdin, including curl's config stream. No secret
 // appears in the generated command, process arguments or shell history.
 return `sudo bash -c ${quote(`set -euo pipefail
umask 077
read -r -s -p '请输入一次性安装票据: ' ticket
printf '\\n'
[[ \"$ticket\" =~ ^[A-Za-z0-9_-]{43}$ ]] || { printf '安装票据格式无效\\n' >&2; exit 1; }
file=$(mktemp)
ca_file=''
curl_ca=()
install_env=(/usr/bin/env ${quote("AGENT_PROXY_MODE="+proxyMode)})
curl_proxy=()
${proxyMode==='DIRECT'?`curl_proxy=(--noproxy '*' --proxy '')`:''}
${profile.stateDir?`install_env+=( ${quote("AGENT_INSTALL_STATE_DIR="+profile.stateDir)} )`:""}
${profile.proxyUrl?`curl_proxy=(--noproxy '' --proxy ${quote(profile.proxyUrl)})
install_env+=( ${quote("AGENT_PROXY_URL="+profile.proxyUrl)} )`:""}
trap 'rm -f "$file" "${'$'}{ca_file}"; unset ticket' EXIT
${profile.caCertificate?`ca_file=$(mktemp)
printf '%s' ${quote(btoa(profile.caCertificate))} | base64 -d > "$ca_file"
curl_ca=(--cacert "$ca_file")
install_env+=("AGENT_CA_FILE=$ca_file")`:''}
printf 'header = "Authorization: Bearer %s"\\n' "$ticket" | curl --config - "${'$'}{curl_ca[@]}" "${'$'}{curl_proxy[@]}" --connect-timeout 15 --max-time 300 --fail --silent --show-error --proto ${quote('='+server.protocol.slice(0,-1))} --tlsv1.2 ${quote(platformURL(profile.server)+'/api/agent/install/'+id+'/artifact')} -o "$file"
printf '%s  %s\\n' ${quote(release.sha256)} "$file" | sha256sum -c -
chmod 700 "$file"
printf '%s\\n' "$ticket" | "${'$'}{install_env[@]}" "$file" --install ${quote(platformURL(profile.server))} ${quote(id)} ${quote(trustRoot)}`)}`;
}
