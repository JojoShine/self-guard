import {test} from 'node:test';
import assert from 'node:assert/strict';
import {spawnSync} from 'node:child_process';
import {networkProbeCommand} from '../src/network-probe-deploy';
const id='6bc04a33-c4cf-48e3-8282-9833e52d0b97';
const options={interface:'eth0',image:'jasonish/suricata@sha256:'+'a'.repeat(64),evePath:'/var/lib/selfguard-network/'+id+'/eve/eve.json'};
test('rejects unpinned images, shell inputs, mismatched paths and incomplete rule authorization',()=>{
 for(const bad of [{image:'jasonish/suricata:latest'},{interface:'eth0;reboot'},{evePath:'/etc/passwd'},{ruleFile:'/tmp/rules'},{expectedRuleSha256:'a'.repeat(64)}])assert.throws(()=>networkProbeCommand(id,'INSTALL',{...options,...bad}));
 assert.throws(()=>networkProbeCommand(';reboot','STOP',options));
 assert.throws(()=>networkProbeCommand(id,'INSTALL',{...options,image:'evil/suricata@sha256:'+'a'.repeat(64)}));
});
test('produces valid Python and protects ownership, passive capture and private configuration',()=>{
 const command=networkProbeCommand(id,'INSTALL',options);
 const script=command.split("<<'SELFGUARD_NETWORK_PY'\n")[1]?.split('\nSELFGUARD_NETWORK_PY')[0];assert.ok(script);
 const syntax=spawnSync('python3',['-c','import ast,sys; ast.parse(sys.stdin.read())'],{input:script,encoding:'utf8'});assert.equal(syntax.status,0,syntax.stderr);
 for(const required of ['--cap-drop=ALL','--cap-add=NET_RAW','--pcap=','--runmode','single','--network=host','noApprovedRules','selfguard.source','User=selfguard-agent','os.path.islink','sha256','commandCompleted'])assert.ok(script.includes(required),required);
 assert.ok(!script.includes('NET_ADMIN'));assert.ok(!script.includes('pip install'));assert.ok(!script.includes('iptables'));
});
test('STOP targets the source engine and bridge and preserves evidence',()=>{
 const command=networkProbeCommand(id,'STOP',options);
 assert.ok(command.includes('systemctl'));assert.ok(command.includes('docker'));assert.ok(!command.includes('shutil.rmtree'));
});
test('generated ownership guard rejects foreign containers and daemon failures',()=>{
 const script=networkProbeCommand(id,'CHECK',options).split("<<'SELFGUARD_NETWORK_PY'\n")[1].split('\ntry:\n')[0];
 const execution=spawnSync('python3',['-c',script+`
from types import SimpleNamespace
calls=[]
def run(args,check=True):
 calls.append(args)
 return SimpleNamespace(returncode=0,stdout=json.dumps([{'Config':{'Labels':{'selfguard.source':'foreign'}}}]))
try: owned('existing')
except RuntimeError as e: assert str(e)=='CONTAINER_NOT_OWNED'
else: raise AssertionError('foreign container accepted')
def run(args,check=True):
 if args==['docker','info']: raise RuntimeError('DAEMON_FAILED')
 return SimpleNamespace(returncode=1,stdout='')
try: owned('missing')
except RuntimeError as e: assert str(e)=='DAEMON_FAILED'
else: raise AssertionError('daemon error treated as absent container')
import tempfile
with tempfile.TemporaryDirectory() as directory:
 os.symlink('/etc',directory+'/link')
 try: safe(directory+'/link/file')
 except RuntimeError as e: assert str(e)=='SYMLINK_REJECTED'
 else: raise AssertionError('symlink accepted')
`],{encoding:'utf8'});
 assert.equal(execution.status,0,execution.stderr);
});
test('isolates private bridge configuration from engine and rotates EVE with limited retention',()=>{
 const script=networkProbeCommand(id,'INSTALL',options);
 assert.ok(script.includes("'type=bind,src='+engineconf+',dst=/etc/selfguard,readonly'"));
 assert.ok(!script.includes("'type=bind,src='+conf+"));
 for(const text of ['copytruncate','rotate 3','size 20M','OnUnitActiveSec=60',"'payload':False","'packet':False","'extended':False","'promisc':False"])assert.ok(script.includes(text),text);
});
function generated(action:'CHECK'|'INSTALL'|'STOP',overrides:Partial<typeof options>={}){
 return networkProbeCommand(id,action,{...options,...overrides}).split("<<'SELFGUARD_NETWORK_PY'\n")[1].split('\nSELFGUARD_NETWORK_PY')[0];
}
test('CHECK and STOP accept an unmanaged legacy EVE path',()=>{
 for(const action of ['CHECK','STOP'] as const)assert.doesNotThrow(()=>generated(action,{evePath:'/var/log/suricata/eve.json'}));
});
test('executed STOP disables boot activation and removes container restart policy before stopping',()=>{
 const [prefix,body]=generated('STOP').split('\ntry:\n');
 const mocked=`
from types import SimpleNamespace
from io import StringIO
calls=[]
os.geteuid=lambda: 0
os.path.isdir=lambda path: True
os.path.exists=lambda path: True
os.path.islink=lambda path: False
os.stat=lambda path: SimpleNamespace(st_uid=0)
shutil.which=lambda name: '/usr/bin/'+name
open=lambda path: StringIO(marker+'\\n')
def run(args,check=True):
 calls.append(args)
 data=[{'Config':{'Labels':{'selfguard.source':sid}}}]
 return SimpleNamespace(returncode=0,stdout=json.dumps(data))
`;
 const execution=spawnSync('python3',['-c',prefix+mocked+'\ntry:\n'+body+"\nprint(json.dumps(calls))"],{encoding:'utf8'});
 assert.equal(execution.status,0,execution.stderr);
 const calls: string[][]=JSON.parse(execution.stdout.trim().split('\n').at(-1)!);
 const name='selfguard-network-'+id;
 assert.ok(calls.some(c=>JSON.stringify(c)===JSON.stringify(['systemctl','disable','--now',name+'-bridge.service'])));
 assert.ok(calls.some(c=>JSON.stringify(c)===JSON.stringify(['systemctl','disable','--now',name+'-rotate.timer'])));
 const update=calls.findIndex(c=>c.join(' ')==='docker update --restart=no '+name),stop=calls.findIndex(c=>c.join(' ')==='docker stop '+name);
 assert.ok(update>=0&&stop>update);
});
test('executed generated writer expressions produce real YAML and systemd line breaks',()=>{
 const script=generated('INSTALL');
 const harness=`import ast,json,sys
from types import SimpleNamespace
nodes=ast.parse(sys.stdin.read())
files={}
values={'marker':'# selfguard.source=test','engineconf':'/engine','conf':'/config','unitpath':'/etc/systemd/system/test-bridge.service','rotation':'test-rotate','eve':'/data/eve','base':'/data','state':'/state','engine':{},'yaml':SimpleNamespace(safe_dump=lambda value:'outputs: []\\n'),'shutil':SimpleNamespace(which=lambda name:'/usr/sbin/'+name),'write':lambda path,data,*args:files.update({path:data.decode()})}
for node in ast.walk(nodes):
 if isinstance(node,ast.Assign) and isinstance(node.targets[0],ast.Name) and node.targets[0].id in ['text','rotate']:
  exec(compile(ast.Module(body=[node],type_ignores=[]),'generated','exec'),values)
 if isinstance(node,ast.Expr) and isinstance(node.value,ast.Call) and isinstance(node.value.func,ast.Name) and node.value.func.id=='write':
  path=eval(compile(ast.Expression(node.value.args[0]),'generated','eval'),values)
  if path.endswith(('.yaml','.service','.timer','logrotate.conf')):
   exec(compile(ast.Module(body=[node],type_ignores=[]),'generated','exec'),values)
print(json.dumps(files))`;
 const execution=spawnSync('python3',['-c',harness],{input:script,encoding:'utf8'});
 assert.equal(execution.status,0,execution.stderr);
 const files:Record<string,string>=JSON.parse(execution.stdout);
 assert.equal(Object.keys(files).length,5);
 assert.ok(files['/engine/suricata.yaml'].startsWith('%YAML 1.1\n---\noutputs: []\n'));
 assert.ok(files['/etc/systemd/system/test-bridge.service'].includes('\n[Service]\nUser=selfguard-agent\n'));
 assert.ok(files['/config/logrotate.conf'].includes('\n size 20M\n'));
 for(const body of Object.values(files))assert.ok(!body.includes('\\n'));
});
test('defaults to verified pinned image and explicitly bypasses vendor entrypoint',()=>{
 const command=networkProbeCommand(id,'INSTALL',{interface:'eth0',evePath:options.evePath});
 assert.ok(command.includes("'--entrypoint','/usr/bin/suricata'"));
});
test('generated image resolution reuses exact cached image, verifies offline amd64 identity and only then pulls',()=>{
 const script=networkProbeCommand(id,'INSTALL',{interface:'eth0',evePath:options.evePath}).split("<<'SELFGUARD_NETWORK_PY'\n")[1].split('\ntry:\n')[0];
 const execution=spawnSync('python3',['-c',script+`
from types import SimpleNamespace
ref='jasonish/suricata@sha256:d5a3a1785299ab40918d465e54fedf8e3afeeedba76bb64b0cc74dbc20bda2c3'
offline='sha256:c297ff467e7681dd594a0cde2b076e7fc5adfcb4381c6ba7ffc85600d7ca22a4'
assert p['image']==ref
calls=[]
scenario='cached'
def run(args,check=True):
 calls.append(args)
 if args[:3]==['docker','image','inspect']:
  target=args[3]
  if scenario=='cached' and target==ref: return SimpleNamespace(returncode=0,stdout='[]')
  if target==offline and scenario in ['offline','wrong-id','arm64']:
   return SimpleNamespace(returncode=0,stdout=json.dumps([{'Id':offline if scenario!='wrong-id' else 'sha256:wrong','Architecture':'arm64' if scenario=='arm64' else 'amd64'}]))
  return SimpleNamespace(returncode=1,stdout='')
 return SimpleNamespace(returncode=0,stdout='')
assert resolve_image(ref)==ref
assert not any(c[:2]==['docker','pull'] for c in calls)
for scenario in ['offline','wrong-id','arm64','missing']:
 calls.clear()
 selected=resolve_image(ref)
 assert selected==(offline if scenario=='offline' else ref)
 assert (['docker','pull',ref] in calls)==(scenario!='offline')
scenario='offline'; calls.clear()
other='jasonish/suricata@sha256:'+'b'*64
assert resolve_image(other)==other
assert ['docker','pull',other] in calls
assert not any(c[:3]==['docker','image','inspect'] and c[3]==offline for c in calls)
`],{encoding:'utf8'});
 assert.equal(execution.status,0,execution.stderr);
});
test('copies required vendor files as private root-owned regular files and rejects symlinks',()=>{
 const script=generated('INSTALL').split('\ntry:\n')[0];
 const execution=spawnSync('python3',['-c',script+`
from types import SimpleNamespace
import stat
calls=[]
mode=stat.S_IFREG|0o600
safe=lambda path: None
os.lstat=lambda path: SimpleNamespace(st_mode=mode)
os.chown=lambda *args: calls.append(('chown',)+args)
os.chmod=lambda *args: calls.append(('chmod',)+args)
run=lambda args: calls.append(('run',args))
copy_vendor('export','classification.config','/engine/classification.config')
assert ('run',['docker','cp','export:/etc/suricata/classification.config','/engine/classification.config']) in calls
assert ('chown','/engine/classification.config',0,0) in calls
assert ('chmod','/engine/classification.config',0o600) in calls
for bad in [stat.S_IFLNK,stat.S_IFDIR]:
 mode=bad; calls.clear()
 try: copy_vendor('export','reference.config','/engine/reference.config')
 except RuntimeError as e: assert str(e)=='VENDOR_FILE_INVALID'
 else: raise AssertionError('nonregular vendor file accepted')
 assert not any(c[0]=='chown' for c in calls)
`],{encoding:'utf8'});
 assert.equal(execution.status,0,execution.stderr);
 const install=generated('INSTALL');
 for(const name of ['classification.config','reference.config']){
  assert.ok(install.includes("copy_vendor(export,'"+name+"',engineconf+'/"+name+"')"));
  assert.ok(install.includes("'/etc/selfguard/"+name+"'"));
 }
 assert.ok(install.includes("copy_vendor(export,'suricata.yaml',vendor)"));
 assert.ok(!install.includes('DAC_OVERRIDE'));
});
