import {z} from 'zod';import {isIP} from 'node:net';import {BadRequestException} from '@nestjs/common';
export const sshHostKey=z.string().max(8192).regex(/^(ssh-ed25519|ecdsa-sha2-nistp(?:256|384|521)|ssh-rsa) [A-Za-z0-9+/]+={0,2}$/);
export const sshAccessInput=z.object({username:z.literal('root').default('root'),port:z.number().int().min(1).max(65535).default(22),password:z.string().min(1).max(4096).refine(s=>!/[\x00\r\n]/.test(s),'密码不能包含换行'),hostKey:sshHostKey,hostKeyConfirmed:z.literal(true)}).strict();
export const remoteCaptureInput=z.object({interface:z.string().regex(/^[A-Za-z0-9_.:-]{1,15}$/),protocol:z.enum(['TCP','UDP','TCP_UDP']).default('TCP_UDP'),ports:z.array(z.number().int().min(1).max(65535)).min(1).max(16),cidrs:z.array(z.string().refine(s=>{const[ip,prefix,...rest]=s.split('/');const family=isIP(ip);return rest.length===0&&!!family&&/^\d+$/.test(prefix||'')&&Number(prefix)<=(family===4?32:128);},'需要有效 CIDR 网段')).max(16).default([]),durationSeconds:z.number().int().min(1).max(600).default(30),maxPackets:z.number().int().min(1).max(100000).default(10000),maxBytes:z.number().int().min(4096).max(67108864).default(1048576),snapLen:z.literal(128).default(128),includePayload:z.literal(false).default(false),retentionHours:z.literal(0).default(0)}).strict();
export function passwordSshArguments(address:string,port:number,knownHosts:string,command:string){if(!isIP(address)||!Number.isInteger(port)||port<1||port>65535)throw new BadRequestException('SSH 地址或端口无效');return ['-F','/dev/null','-o','BatchMode=no','-o','StrictHostKeyChecking=yes','-o','GlobalKnownHostsFile=/dev/null','-o','VerifyHostKeyDNS=no','-o','UpdateHostKeys=no','-o','PasswordAuthentication=yes','-o','PreferredAuthentications=password','-o','PubkeyAuthentication=no','-o','KbdInteractiveAuthentication=no','-o','NumberOfPasswordPrompts=1','-o','PermitLocalCommand=no','-o','ClearAllForwardings=yes','-o','ConnectTimeout=10','-o','ServerAliveInterval=10','-o','ServerAliveCountMax=2','-o','UserKnownHostsFile='+knownHosts,'-p',String(port),'--','root@'+address,command];}
export function remoteCaptureCommand(id:string){if(!/^[a-f0-9-]{36}$/.test(id))throw new BadRequestException('捕获任务标识无效');return `bash -c 'set -euo pipefail
umask 077
[ "$(id -u)" = 0 ]
[ -x /opt/selfguard-agent/current ]
base=/var/lib/selfguard-traffic
[ ! -L "$base" ]
mkdir -p "$base"
[ "$(stat -c %u "$base")" = 0 ]
chmod 700 "$base"
work=$(mktemp -d "$base/remote-${id}.XXXXXX")
cat > "$work/config.json"
mkdir -m 700 "$work/output"
/opt/selfguard-agent/current --capture-traffic "$work/config.json" "$work/output" >/dev/null
/opt/selfguard-agent/current --publish-traffic "$work/output/summary.json" >/dev/null
cat "$work/output/summary.json"
'`;}
