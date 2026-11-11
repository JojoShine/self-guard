import {createHash} from 'node:crypto';
import {readFile} from 'node:fs/promises';
import {join} from 'node:path';
import {z} from 'zod';

export const probeKind=z.enum(['NETWORK','ACCESS']);
const architecture=z.enum(['amd64','arm64']);
const sourceId=z.string().uuid();
export type ProbeKind=z.infer<typeof probeKind>;
const quote=(value:string)=>"'"+value.replace(/'/g,"'\\''")+"'";
export const probeArchitectureCommand="sh -c 'test \"$(id -u)\" = 0 && test -d /run/systemd/system && case $(uname -m) in x86_64) echo amd64;; aarch64) echo arm64;; *) exit 1;; esac'";
export async function bundledProbe(kind:ProbeKind,arch:string){
 const name=probeKind.parse(kind)==='NETWORK'?'selfguard-suricata-bridge':'selfguard-access-probe';
 const bytes=await readFile(join(process.env.PROBE_ARTIFACT_DIR||'/opt/selfguard-probes',name+'-linux-'+architecture.parse(arch)));
 if(!bytes.length||bytes.length>64*1024*1024)throw new Error('探针发行文件大小无效');
 return {bytes,sha256:createHash('sha256').update(bytes).digest('hex'),name};
}
// The bytes and private configuration travel through pinned SSH stdin, never argv or job records.
export function probeTransfer(kind:ProbeKind,id:string,artifact:{bytes:Buffer;sha256:string},configuration:unknown){
 const name=probeKind.parse(kind)==='NETWORK'?'selfguard-suricata-bridge':'selfguard-access-probe';
 const directory='/opt/selfguard-probes/'+sourceId.parse(id);
 if(!/^[a-f0-9]{64}$/.test(artifact.sha256)||createHash('sha256').update(artifact.bytes).digest('hex')!==artifact.sha256)throw new Error('探针发行摘要不匹配');
 const script=`set -eu
umask 077
test "$(id -u)" = 0
test -d /run/systemd/system
for path in /opt /opt/selfguard-probes ${quote(directory)}; do
 test ! -L "$path"
 if [ -e "$path" ]; then test -d "$path"; else mkdir "$path"; fi
done
chmod 700 ${quote(directory)}
work=$(mktemp -d ${quote(directory+'/transfer.XXXXXX')})
trap 'rm -rf "$work"' EXIT HUP INT TERM
IFS= read -r binary
printf '%s' "$binary" | base64 -d > "$work/probe"
printf '%s  %s\\n' ${quote(artifact.sha256)} "$work/probe" | sha256sum -c - >/dev/null
IFS= read -r config
printf '%s' "$config" | base64 -d > "$work/config.json"
chmod 700 "$work/probe"
chmod 600 "$work/config.json"
mv "$work/probe" ${quote(directory+'/'+name)}
mv "$work/config.json" ${quote(directory+'/config.json')}
printf 'TRANSFER_OK\\n'`;
 return {command:'sh -c '+quote(script),input:artifact.bytes.toString('base64')+'\n'+Buffer.from(JSON.stringify(configuration)).toString('base64')+'\n'};
}
export function accessProbeCommand(id:string,action:'INSTALL'|'STOP'|'CHECK'){
 const valid=sourceId.parse(id),unit='selfguard-access-'+valid,directory='/opt/selfguard-probes/'+valid;
 const command=action==='INSTALL'?`${quote(directory+'/selfguard-access-probe')} --install-config ${quote(directory+'/config.json')} >/dev/null 2>&1
systemctl restart ${quote(unit+'.service')} ${quote(unit+'-capture.service')}`:action==='STOP'?`for suffix in '' '-capture'; do
 unit=${quote(unit)}"$suffix.service"
 if [ -f "/etc/systemd/system/$unit" ]; then systemctl disable --now "$unit"; fi
done`:`present=0
running=0
for suffix in '' '-capture'; do
 unit=${quote(unit)}"$suffix.service"
 if [ -f "/etc/systemd/system/$unit" ]; then
  present=$((present+1))
  if systemctl is-active --quiet "$unit" >/dev/null 2>&1; then running=$((running+1)); fi
 fi
done
if [ "$present" = 0 ]; then printf 'PROBE_CHECK_NOT_INSTALLED\\n';
elif [ "$running" = 2 ]; then printf 'PROBE_CHECK_RUNNING\\n';
else printf 'PROBE_CHECK_NOT_RUNNING\\n'; fi`;
 const guard=`for suffix in '' '-capture'; do
 unit=${quote(unit)}"$suffix.service"
 path="/etc/systemd/system/$unit"
 if [ -e "$path" ] || [ -L "$path" ]; then
  test -f "$path" && test ! -L "$path"
  test "$(stat -c %u "$path")" = 0
  grep -F ${quote('/etc/selfguard-probe/'+valid+'/')} "$path" >/dev/null
  grep -F 'ExecStart=/usr/local/libexec/selfguard-access-probe-' "$path" >/dev/null
 fi
done`;
 const preflight=action==='CHECK'?`if [ "$(id -u)" != 0 ]; then printf 'PROBE_CHECK_ROOT_REQUIRED\\n'; exit 0; fi
if [ ! -d /run/systemd/system ] || ! command -v systemctl >/dev/null 2>&1; then printf 'PROBE_CHECK_SYSTEMD_REQUIRED\\n'; exit 0; fi
`:'';
 return 'sh -c '+quote('set -eu\n'+preflight+guard+'\n'+command+(action==='CHECK'?'':'\nprintf "PROBE_COMMAND_OK\\n"'));
}
