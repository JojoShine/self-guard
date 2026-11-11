import {z} from 'zod';
export const DEFAULT_NETWORK_PROBE_IMAGE='jasonish/suricata@sha256:d5a3a1785299ab40918d465e54fedf8e3afeeedba76bb64b0cc74dbc20bda2c3';
const DEFAULT_AMD64_IMAGE_ID='sha256:c297ff467e7681dd594a0cde2b076e7fc5adfcb4381c6ba7ffc85600d7ca22a4';
type Options={interface?:string;image?:string;evePath:string;ruleFile?:string|null;expectedRuleSha256?:string|null};
export function networkProbeCommand(id:string,action:'CHECK'|'INSTALL'|'STOP',options:Options):string{
 const source=z.string().uuid().parse(id);z.enum(['CHECK','INSTALL','STOP']).parse(action);
 if(action==='INSTALL'&&options.evePath!==`/var/lib/selfguard-network/${source}/eve/eve.json`)throw new Error('网络探针日志路径必须属于该采集源');
 if(options.interface!==undefined&&!/^[a-zA-Z0-9][a-zA-Z0-9_.:-]{0,14}$/.test(options.interface))throw new Error('镜像网卡名称无效');
 if(action==='INSTALL'&&!options.interface)throw new Error('请选择镜像网卡');
 const image=options.image??DEFAULT_NETWORK_PROBE_IMAGE,allowed=(process.env.NETWORK_PROBE_ALLOWED_IMAGES||'').split(',').map(s=>s.trim());
 if((action==='INSTALL'||image)&&(!image||!/^[-a-zA-Z0-9./_:]+@sha256:[a-f0-9]{64}$/.test(image)||(!image.startsWith('jasonish/suricata@sha256:')&&!allowed.includes(image))))throw new Error('流量引擎必须使用允许的摘要固定镜像');
 if(Boolean(options.ruleFile)!==Boolean(options.expectedRuleSha256))throw new Error('规则文件与授权摘要必须同时提供');
 if(options.ruleFile&&(!/^\/[a-zA-Z0-9_./-]+$/.test(options.ruleFile)||options.ruleFile.split('/').includes('..')||! /^[a-f0-9]{64}$/.test(options.expectedRuleSha256||'')))throw new Error('授权规则路径或摘要无效');
 const input=Buffer.from(JSON.stringify({...options,image,id:source,action})).toString('base64');
 return `python3 - <<'SELFGUARD_NETWORK_PY'
import os,sys,json,base64,subprocess,pwd,hashlib,shutil,stat
p=json.loads(base64.b64decode('${input}'))
sid=p['id']; action=p['action']; name='selfguard-network-'+sid
base='/var/lib/selfguard-network/'+sid; conf='/etc/selfguard-network/'+sid
stage='/opt/selfguard-probes/'+sid; state='/var/lib/selfguard-suricata/'+sid
unit=name+'-bridge.service'; rotation=name+'-rotate'; unitpath='/etc/systemd/system/'+unit; marker='# selfguard.source='+sid

def run(args,check=True):
 r=subprocess.run(args,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,timeout=180)
 if check and r.returncode: raise RuntimeError('COMMAND_FAILED:'+args[0])
 return r

def resolve_image(image):
 if run(['docker','image','inspect',image],False).returncode==0: return image
 # This verified amd64 image may have been imported offline without a registry digest tag.
 if image=='${DEFAULT_NETWORK_PROBE_IMAGE}':
  offline='${DEFAULT_AMD64_IMAGE_ID}'
  inspected=run(['docker','image','inspect',offline],False)
  if inspected.returncode==0:
   data=json.loads(inspected.stdout)
   if len(data)==1 and data[0].get('Id')==offline and data[0].get('Architecture')=='amd64': return offline
 run(['docker','pull',image])
 return image

def safe(path):
 current='/'
 for part in path.strip('/').split('/'):
  current=os.path.join(current,part)
  if os.path.islink(current): raise RuntimeError('SYMLINK_REJECTED')

def copy_vendor(container,filename,target):
 safe(target)
 run(['docker','cp',container+':/etc/suricata/'+filename,target])
 if not stat.S_ISREG(os.lstat(target).st_mode): raise RuntimeError('VENDOR_FILE_INVALID')
 safe(target)
 os.chown(target,0,0); os.chmod(target,0o600)

def owned(container):
 r=run(['docker','inspect',container],False)
 if r.returncode:
  run(['docker','info']); return None
 data=json.loads(r.stdout)[0]
 if data.get('Config',{}).get('Labels',{}).get('selfguard.source')!=sid: raise RuntimeError('CONTAINER_NOT_OWNED')
 return data

def write(path,data,uid=0,gid=0,mode=0o600):
 safe(path)
 fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_TRUNC|os.O_NOFOLLOW,mode)
 with os.fdopen(fd,'wb') as f: f.write(data)
 os.chown(path,uid,gid); os.chmod(path,mode)

try:
 if os.geteuid()!=0: raise RuntimeError('ROOT_REQUIRED')
 if not os.path.isdir('/run/systemd/system'): raise RuntimeError('SYSTEMD_REQUIRED')
 if not shutil.which('docker'): raise RuntimeError('DOCKER_REQUIRED')
 for checked in [unitpath,'/etc/systemd/system/'+rotation+'.service','/etc/systemd/system/'+rotation+'.timer']:
  safe(checked)
  if os.path.exists(checked) and (os.stat(checked).st_uid!=0 or marker not in open(checked).read().splitlines()): raise RuntimeError('UNIT_NOT_OWNED')
 existing=owned(name)
 if action=='CHECK':
  print(json.dumps({'commandCompleted':True,'enginePresent':existing is not None,'engineRunning':bool(existing and existing.get('State',{}).get('Running')),'bridgeStatus':run(['systemctl','is-active',unit],False).stdout.strip(),'image':existing.get('Config',{}).get('Image') if existing else None,'rules':'approvedRules' if p.get('ruleFile') else 'noApprovedRules'}))
 elif action=='STOP':
  if os.path.exists(unitpath): run(['systemctl','disable','--now',unit])
  if existing:
   run(['docker','update','--restart=no',name]); run(['docker','stop',name])
  if os.path.exists('/etc/systemd/system/'+rotation+'.timer'): run(['systemctl','disable','--now',rotation+'.timer'])
  print(json.dumps({'commandCompleted':True,'action':'STOP','evidencePreserved':True}))
 else:
  import yaml
  if not shutil.which('logrotate'): raise RuntimeError('LOGROTATE_REQUIRED')
  iface=p['interface']
  if not os.path.exists('/sys/class/net/'+iface): raise RuntimeError('INTERFACE_NOT_FOUND')
  account=pwd.getpwnam('selfguard-agent'); uid=account.pw_uid; gid=account.pw_gid
  for path in [base,conf,state,stage]: safe(path)
  for path in [base,conf,state]: os.makedirs(path,mode=0o750,exist_ok=True)
  os.chown(conf,0,gid); os.chmod(conf,0o750)
  os.chown(state,uid,gid); os.chmod(state,0o700)
  eve=base+'/eve'; safe(eve); os.makedirs(eve,mode=0o750,exist_ok=True); os.chown(eve,0,gid); os.chmod(eve,0o750)
  os.chown(base,0,gid); os.chmod(base,0o750)
  safe(stage+'/config.json'); safe(stage+'/selfguard-suricata-bridge')
  cfg=json.load(open(stage+'/config.json'))
  if cfg.get('sensorId')!=sid or cfg.get('evePath')!=p['evePath'] or cfg.get('stateDir')!=state or cfg.get('identityPath')!='/var/lib/selfguard-agent/identity.json': raise RuntimeError('CONFIG_BINDING_INVALID')
  rules=b''
  if p.get('ruleFile'):
   safe(p['ruleFile'])
   with open(p['ruleFile'],'rb') as f: rules=f.read(32*1024*1024+1)
   if len(rules)>32*1024*1024 or hashlib.sha256(rules).hexdigest()!=p['expectedRuleSha256']: raise RuntimeError('RULE_DIGEST_MISMATCH')
  engineconf=conf+'/engine'; safe(engineconf); os.makedirs(engineconf,mode=0o700,exist_ok=True)
  image=resolve_image(p['image'])
  export=name+'-export'
  if owned(export): run(['docker','rm',export])
  run(['docker','create','--name',export,'--label','selfguard.source='+sid,image])
  vendor=engineconf+'/vendor.yaml'; safe(vendor)
  try:
   copy_vendor(export,'suricata.yaml',vendor)
   copy_vendor(export,'classification.config',engineconf+'/classification.config')
   copy_vendor(export,'reference.config',engineconf+'/reference.config')
  finally: run(['docker','rm',export],False)
  with open(vendor) as f: engine=yaml.safe_load(f)
  if not isinstance(engine,dict): raise RuntimeError('VENDOR_CONFIG_INVALID')
  engine['outputs']=[{'eve-log':{'enabled':True,'filetype':'regular','filename':'eve.json','filemode':'0640','threaded':False,'types':[{'alert':{'payload':False,'payload-printable':False,'packet':False,'tagged-packets':False}},{'http':{'extended':False}},'dns',{'tls':{'extended':False}},'flow','anomaly',{'stats':{'totals':True,'threads':False}}]}}]
  engine['classification-file']='/etc/selfguard/classification.config'
  engine['reference-config-file']='/etc/selfguard/reference.config'
  engine['stats']={'enabled':True,'interval':8}; engine['default-log-dir']='/var/log/suricata'
  engine['default-rule-path']='/etc/selfguard'; engine['rule-files']=['approved.rules'] if rules else []
  engine['pcap']=[{'interface':iface,'promisc':False}]; engine['unix-command']={'enabled':False}
  engine.pop('run-as',None)
  engine['logging']={'default-log-level':'notice','outputs':[{'console':{'enabled':True}}]}
  write(engineconf+'/suricata.yaml',('%YAML 1.1\\n---\\n'+yaml.safe_dump(engine)).encode())
  write(engineconf+'/approved.rules',rules); write(conf+'/config.json',json.dumps(cfg).encode(),uid,gid)
  write(conf+'/bridge',open(stage+'/selfguard-suricata-bridge','rb').read(),0,gid,0o750)
  docker=['docker','run','--name',name,'--label','selfguard.source='+sid,'--network=host','--user=0:'+str(gid),'--cap-drop=ALL','--cap-add=NET_RAW','--security-opt=no-new-privileges','--read-only','--tmpfs','/tmp:rw,noexec,nosuid,size=64m','--memory=512m','--cpus=1','--pids-limit=128','--entrypoint','/usr/bin/suricata','--log-opt','max-size=10m','--log-opt','max-file=3','--mount','type=bind,src='+engineconf+',dst=/etc/selfguard,readonly','--mount','type=bind,src='+eve+',dst=/var/log/suricata',image,'-c','/etc/selfguard/suricata.yaml','--pcap='+iface,'--runmode','single']
  validate=docker.copy(); validate[validate.index(name)]=name+'-validate'; validate.insert(2,'--rm'); validate.append('-T')
  if owned(name+'-validate'): run(['docker','rm',name+'-validate'])
  run(validate)
  if existing: run(['docker','rm','-f',name])
  docker.insert(2,'--detach'); docker.insert(3,'--restart=unless-stopped'); run(docker)
  text=marker+'\\n[Unit]\\nDescription=SelfGuard passive network bridge\\nAfter=network-online.target docker.service\\n[Service]\\nUser=selfguard-agent\\nGroup=selfguard-agent\\nExecStart='+conf+'/bridge --config '+conf+'/config.json\\nRestart=on-failure\\nRestartSec=5\\nNoNewPrivileges=true\\nProtectSystem=strict\\nProtectHome=true\\nPrivateTmp=true\\nReadWritePaths='+state+'\\n[Install]\\nWantedBy=multi-user.target\\n'
  write(unitpath,text.encode(),0,0,0o644)
  rotate=conf+'/logrotate.conf'
  write(rotate,(eve+'/eve.json {\\n size 20M\\n rotate 3\\n missingok\\n notifempty\\n copytruncate\\n}\\n').encode())
  write('/etc/systemd/system/'+rotation+'.service',(marker+'\\n[Service]\\nType=oneshot\\nExecStart='+shutil.which('logrotate')+' -s '+base+'/logrotate.state '+rotate+'\\n').encode(),0,0,0o644)
  write('/etc/systemd/system/'+rotation+'.timer',(marker+'\\n[Timer]\\nOnBootSec=60\\nOnUnitActiveSec=60\\n[Install]\\nWantedBy=timers.target\\n').encode(),0,0,0o644)
  run(['systemctl','daemon-reload']); run(['systemctl','enable','--now',rotation+'.timer']); run(['systemctl','enable',unit]); run(['systemctl','restart',unit])
  print(json.dumps({'commandCompleted':True,'action':'INSTALL','rules':'approvedRules' if rules else 'noApprovedRules','health':'awaitingSourceHeartbeat'}))
except Exception as e:
 code=str(e) if isinstance(e,RuntimeError) else type(e).__name__
 print(json.dumps({'commandCompleted':False,'error':code})); sys.exit(0)
SELFGUARD_NETWORK_PY`;
}
