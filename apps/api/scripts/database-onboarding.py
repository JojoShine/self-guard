#!/usr/bin/env python3
"""Fixed SSH runner. Private request on stdin; only bounded metadata on stdout."""
import base64, datetime, hashlib, json, os, pathlib, re, shutil, stat, subprocess, sys, tempfile, time, uuid

class Failure(Exception):
 def __init__(self,code):self.code=code
def require(value,code):
 if not value:raise Failure(code)
def run(args,body=None,timeout=30):
 try:p=subprocess.run(args,input=body,text=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=timeout)
 except (OSError,subprocess.TimeoutExpired):raise Failure('INSTALLATION_FAILED')
 require(p.returncode==0,'LOCAL_ADMIN_REQUIRED')
 require(len(p.stdout.encode())<=1048576,'INSTALLATION_FAILED')
 return p.stdout.strip()
def safe_path(path,allow_missing=False):
 p=pathlib.Path(path)
 require(p.is_absolute() and '..' not in p.parts and not any(ord(c)<32 or ord(c)==127 for c in str(p)),'INVALID_REQUEST')
 for parent in [*reversed(p.parents),p]:
  if parent.is_symlink():raise Failure('SYMLINK_REJECTED')
  if not parent.exists():
   require(allow_missing,'SOURCE_UNREADABLE');continue
 return p
def private_json(path):
 p=safe_path(path);s=p.stat();require(stat.S_ISREG(s.st_mode) and not s.st_mode&0o077 and s.st_size<131072,'AGENT_REQUIRED')
 try:return json.loads(p.read_text())
 except (OSError,ValueError):raise Failure('AGENT_REQUIRED')
def validate(r):
 require(isinstance(r,dict) and r.get('action') in ['CHECK','PREPARE','INSTALL','STOP'],'INVALID_REQUEST')
 for k in ['instanceId','assetId']:
  try:require(str(uuid.UUID(r[k]))==r[k],'INVALID_REQUEST')
  except (ValueError,KeyError,TypeError):raise Failure('INVALID_REQUEST')
 t=r.get('target',{});require(isinstance(t,dict) and t.get('deployment') in ['HOST','DOCKER','FILE'],'INVALID_REQUEST')
 require(isinstance(t.get('port'),int) and not isinstance(t['port'],bool) and 1<=t['port']<=65535,'INVALID_REQUEST')
 database=t.get('database')
 # psql treats a URI or '=' as a connection string; ordinary identifier bytes stay data.
 require(isinstance(database,str) and 0<len(database.encode())<=63 and '=' not in database and not database.startswith(('postgresql://','postgres://')) and not any(ord(c)<32 or ord(c)==127 for c in database),'INVALID_REQUEST')
 if t['deployment']=='DOCKER':require(re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,127}',str(t.get('container',''))),'INVALID_REQUEST')
 elif t.get('container'):raise Failure('INVALID_REQUEST')
 if t['deployment']=='FILE':
  safe_path(t.get('sourcePath',''),allow_missing=True)
  require(re.fullmatch(r'[a-z0-9-]{1,64}',str(t.get('format',''))),'INVALID_REQUEST')
 else:require(r.get('engine')=='postgresql','UNSUPPORTED_ENGINE')
 return r
def activation_state(settings,action):
 if settings.get('logging_collector')!='on':return ('CHECKED' if action=='CHECK' else 'WAITING_RESTART','COLLECTOR_OFF')
 return ('CHECKED','READY')
def sql_command(t):
 if t['deployment']=='DOCKER':
  return ['docker','exec','-i','--user','postgres',t['container'],'sh','-c','exec psql -X -q -A -t -v ON_ERROR_STOP=1 -U "${POSTGRES_USER:-postgres}" --dbname="$1"','selfguard',t['database']]
 return ['runuser','-u','postgres','--','psql','-X','-q','-A','-t','-v','ON_ERROR_STOP=1','--port='+str(t['port']),'--dbname='+t['database']]
SETTING_NAMES=['logging_collector','log_destination','log_min_duration_statement','log_statement','log_error_verbosity','log_parameter_max_length','log_parameter_max_length_on_error','log_connections','log_disconnections','log_directory','log_rotation_age','log_rotation_size','log_timezone']
RETENTION_SCRIPT='''import datetime,json,os,pathlib,re,stat,sys,time
# The root-owned configuration pins the original directory inode across renames.
instance=sys.argv[3]
if not re.fullmatch(r"[0-9a-f-]{36}",instance):raise SystemExit(1)
config=pathlib.Path('/opt/selfguard-database')/instance/'retention.json'
if config.is_symlink() or config.stat().st_uid!=0 or config.stat().st_mode&0o077:raise SystemExit(1)
c=json.loads(config.read_text());source=sys.argv[2]
if c['sourcePath']!=source:raise SystemExit(1)
fd=os.open(source,os.O_DIRECTORY|os.O_NOFOLLOW)
try:
 s=os.fstat(fd)
 if [s.st_dev,s.st_ino]!=c['sourceIdentity']:raise SystemExit(1)
 cutoff=time.time()-(7*86400-2*3600)
 files=[]
 for name in os.listdir(fd):
  m=re.fullmatch(r'selfguard-(\\d{14})\\.csv',name)
  if not m:continue
  try:at=datetime.datetime.strptime(m[1],'%Y%m%d%H%M%S').replace(tzinfo=datetime.timezone.utc).timestamp()
  except ValueError:continue
  metadata=os.stat(name,dir_fd=fd,follow_symlinks=False)
  if not stat.S_ISREG(metadata.st_mode):continue
  if at<cutoff:os.unlink(name,dir_fd=fd)
  else:files.append((name,metadata.st_size))
 files.sort()
 total=sum(size for _,size in files);pruned=0
 for name,size in files[:-1]:
  if total<=256*1024*1024:break
  os.unlink(name,dir_fd=fd);total-=size;pruned+=1
 statefd=os.open('/var/lib/selfguard-database/'+instance,os.O_DIRECTORY|os.O_NOFOLLOW)
 try:
  previous={}
  try:
   statusfd=os.open('source-retention.json',os.O_RDONLY|os.O_NOFOLLOW,dir_fd=statefd)
   with os.fdopen(statusfd) as stream:previous=json.load(stream)
  except FileNotFoundError:pass
  result={'capacityPrunedFiles':int(previous.get('capacityPrunedFiles',0))+pruned,'budgetExceeded':total>256*1024*1024}
  try:os.unlink('source-retention.new',dir_fd=statefd)
  except FileNotFoundError:pass
  output=os.open('source-retention.new',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=statefd)
  try:
   with os.fdopen(output,'w') as stream:json.dump(result,stream);stream.flush();os.fsync(stream.fileno())
   os.rename('source-retention.new','source-retention.json',src_dir_fd=statefd,dst_dir_fd=statefd);os.fsync(statefd)
  finally:
   try:os.unlink('source-retention.new',dir_fd=statefd)
   except FileNotFoundError:pass
 finally:os.close(statefd)
finally:os.close(fd)
'''
def postgres(t):
 info=None
 if t['deployment']=='DOCKER':
  require(shutil.which('docker'),'DOCKER_REQUIRED')
  try:info=json.loads(run(['docker','inspect',t['container']]))[0]
  except (ValueError,IndexError):raise Failure('TARGET_MISMATCH')
  require(info.get('Name')=='/'+t['container'] and info.get('State',{}).get('Running'),'TARGET_MISMATCH')
 else:require(shutil.which('psql') and shutil.which('runuser'),'POSTGRES_REQUIRED')
 query="SELECT json_build_object('database',current_database(),'version',current_setting('server_version'),'dataDirectory',current_setting('data_directory'),'startedAt',pg_postmaster_start_time(),'startedEpoch',extract(epoch from pg_postmaster_start_time())::text,'port',current_setting('port')::int,'superuser',(SELECT rolsuper FROM pg_roles WHERE rolname=current_user),'settings',(SELECT json_object_agg(name,setting) FROM pg_settings WHERE name IN ("+','.join("'"+s+"'" for s in SETTING_NAMES)+")));"
 try:p=json.loads(run(sql_command(t),query))
 except ValueError:raise Failure('TARGET_MISMATCH')
 require(p.get('database')==t['database'] and p.get('superuser') is True,'LOCAL_ADMIN_REQUIRED')
 require(re.match(r'^(1[4-9]|[2-9][0-9])\.',p.get('version','')),'UNSUPPORTED_ENGINE')
 if info:
  mappings=info.get('HostConfig',{}).get('PortBindings') or {}
  mapped=[int(b['HostPort']) for b in mappings.get(str(p['port'])+'/tcp',[]) or [] if b.get('HostPort','').isdigit()]
  require(t['port']==p['port'] or t['port'] in mapped,'TARGET_MISMATCH')
  data=pathlib.PurePosixPath(p['dataDirectory']);matches=[]
  for m in info.get('Mounts',[]):
   try:relative=data.relative_to(m['Destination'])
   except (ValueError,KeyError):continue
   if m.get('RW'):matches.append((len(m['Destination']),pathlib.Path(m['Source'])/str(relative)))
  require(matches,'SOURCE_UNREADABLE');host_data=max(matches,key=lambda m:m[0])[1]
 else:
  require(t['port']==p['port'],'TARGET_MISMATCH');host_data=pathlib.Path(p['dataDirectory'])
 safe_path(host_data)
 require(host_data.is_dir(),'SOURCE_UNREADABLE')
 p['hostData']=str(host_data);p['containerId']=info['Id'] if info else None
 fingerprint={k:p[k] for k in ['database','version','dataDirectory','startedAt','port','containerId']}
 p['fingerprint']=hashlib.sha256(json.dumps(fingerprint,sort_keys=True).encode()).hexdigest()
 return p
def owned_directory(path,marker,uid=0,gid=0):
 p=safe_path(path,allow_missing=True)
 if p.exists():
  require(p.is_dir() and (p/'.selfguard-owner').is_file() and not (p/'.selfguard-owner').is_symlink() and (p/'.selfguard-owner').read_text()==marker,'UNIT_NOT_OWNED')
 else:
  p.mkdir(parents=True,mode=0o700);(p/'.selfguard-owner').write_text(marker)
 os.chmod(p,0o700);os.chown(p,uid,gid);os.chmod(p/'.selfguard-owner',0o600)
 return p
def atomic_private(path,body,mode=0o600):
 p=safe_path(path,allow_missing=True);fd,name=tempfile.mkstemp(prefix='.selfguard-',dir=p.parent)
 try:
  with os.fdopen(fd,'wb') as f:f.write(body if isinstance(body,bytes) else body.encode());f.flush();os.fsync(f.fileno())
  os.chmod(name,mode);os.replace(name,p)
  d=os.open(p.parent,os.O_DIRECTORY);os.fsync(d);os.close(d)
 finally:
  if os.path.exists(name):os.unlink(name)
def unit_quote(value):return '"'+str(value).replace('\\','\\\\').replace('"','\\"').replace('%','%%')+'"'
def service_units(instance,source):
 root='/opt/selfguard-database/'+instance;state='/var/lib/selfguard-database/'+instance;prefix='selfguard-database-'+instance
 common='NoNewPrivileges=true\nProtectSystem=strict\nProtectHome=read-only\nPrivateTmp=true\nPrivateDevices=true\nRestrictSUIDSGID=true\nLockPersonality=true\nRestrictAddressFamilies=AF_UNIX AF_INET AF_INET6\n'
 marker='# SelfGuard database monitor '+instance+'\n'
 service=marker+'[Unit]\nDescription=SelfGuard database audit collector\nAfter=network-online.target\nWants=network-online.target\n[Service]\nType=simple\nUser=root\nUMask=0077\n'+common+'CapabilityBoundingSet=CAP_DAC_READ_SEARCH\nReadWritePaths='+unit_quote(state)+'\nExecStart='+unit_quote(root+'/probe')+' --database-monitor '+unit_quote(root+'/config.json')+'\nRestart=on-failure\nRestartSec=15\nTimeoutStopSec=30\nMemoryMax=128M\nCPUQuota=20%\n[Install]\nWantedBy=multi-user.target\n'
 expire=marker+'[Unit]\nDescription=SelfGuard database SQL expiry\n[Service]\nType=oneshot\nUser=root\nUMask=0077\n'+common+'CapabilityBoundingSet=CAP_DAC_OVERRIDE CAP_DAC_READ_SEARCH\nReadWritePaths='+unit_quote(state)+' '+unit_quote(source)+'\nExecStart='+unit_quote(root+'/probe')+' --database-monitor-expire '+unit_quote(root+'/config.json')+'\n'
 # FILE sources are not owned by this service. Their retention is checked separately.
 cleanup=marker+'[Unit]\nDescription=SelfGuard owned PostgreSQL log expiry\n[Service]\nType=oneshot\nUser=root\nUMask=0077\n'+common+'CapabilityBoundingSet=CAP_DAC_OVERRIDE CAP_DAC_READ_SEARCH\nReadWritePaths='+unit_quote(source)+' '+unit_quote(state)+'\nExecStart=/usr/bin/python3 '+unit_quote(root+'/runner.py')+' --expire '+unit_quote(source)+' '+instance+'\n'
 timer=marker+'[Unit]\nDescription=SelfGuard SQL expiry schedule\n[Timer]\nOnCalendar=minutely\nPersistent=true\nUnit='+prefix+'-expire.service\n[Install]\nWantedBy=timers.target\n'
 logs_timer=timer.replace(prefix+'-expire.service',prefix+'-logs.service')
 return {prefix+'.service':service,prefix+'-expire.service':expire,prefix+'-expire.timer':timer,prefix+'-logs.service':cleanup,prefix+'-logs.timer':logs_timer}
def expire_logs(source,instance,now=None):
 p=safe_path(source);require(p.is_dir() and (p/'.selfguard-owner').is_file() and not (p/'.selfguard-owner').is_symlink() and (p/'.selfguard-owner').read_text()==instance,'UNIT_NOT_OWNED')
 now=time.time() if now is None else now;expired=0
 # Rotate hourly; remove before seven days even when the five-minute timer runs late.
 cutoff=now-(7*86400-2*3600)
 for f in p.iterdir():
  m=re.fullmatch(r'selfguard-(\d{14})\.csv',f.name)
  if not m or f.is_symlink() or not f.is_file():continue
  try:started=datetime.datetime.strptime(m[1],'%Y%m%d%H%M%S').replace(tzinfo=datetime.timezone.utc).timestamp()
  except ValueError:continue
  if started<cutoff:f.unlink();expired+=1
 return {'expiredFiles':expired}
def identity(r):
 c=private_json('/etc/selfguard-agent/collector.json');i=private_json('/var/lib/selfguard-agent/identity.json')
 require(i.get('assetId')==r['assetId'] and isinstance(i.get('token'),str) and i['token'],'AGENT_IDENTITY_MISMATCH')
 return c,i
def assert_existing_binding(before,after):
 # Pending events and cursors belong to one source and one platform. Rotating
 # a credential is safe; silently reusing them for a different target is not.
 require(all(before.get(k)==after.get(k) for k in ['instanceId','assetId','sourcePath','engine','format','server']),'CONFIGURATION_CHANGED')
def target_result(r,p=None):
 if r['target']['deployment']=='FILE':
  source=safe_path(r['target']['sourcePath']);require(source.is_file() or source.is_dir(),'SOURCE_UNREADABLE')
  s=source.stat();fingerprint=hashlib.sha256(json.dumps([str(source),s.st_dev,s.st_ino,r['engine'],r['target']['format']]).encode()).hexdigest()
  return {'state':'CHECKED','detailCode':'READY','sourcePath':str(source),'format':r['target']['format'],'requiresRestart':False,'targetFingerprint':fingerprint}
 p=postgres(r['target']) if p is None else p;state,code=activation_state(p['settings'],r['action'])
 return {'state':state,'detailCode':code,'sourcePath':str(pathlib.Path(p['hostData'])/('selfguard-audit-'+r['instanceId'])),'format':'postgresql-csv-sql','requiresRestart':p['settings']['logging_collector']!='on','version':p['version'],'targetFingerprint':p['fingerprint'],'databaseIdentity':hashlib.sha256((p['database']+'|'+p['startedEpoch']).encode()).hexdigest(),'settings':p['settings']}
def stop(r):
 prefix='selfguard-database-'+r['instanceId'];directory=pathlib.Path('/etc/systemd/system')
 unit=directory/(prefix+'.service')
 if unit.exists() or unit.is_symlink():
  safe_path(unit);require(unit.is_file() and unit.read_text().startswith('# SelfGuard database monitor '+r['instanceId']+'\n'),'UNIT_NOT_OWNED')
  run(['systemctl','disable','--now',prefix+'.service'])
 # Expiry timers intentionally remain active while collection is stopped.
 return {'state':'STOPPED','detailCode':'STOPPED','requiresRestart':False}
def execute(r):
 validate(r);require(os.geteuid()==0,'ROOT_REQUIRED');os.umask(0o077)
 if r['action']=='STOP':return stop(r)
 c,i=identity(r);p=None
 if r['target']['deployment']!='FILE':p=postgres(r['target'])
 result=target_result(r,p)
 if r['action']=='CHECK':return result
 require(r.get('expectedTargetFingerprint')==result['targetFingerprint'],'TARGET_CHANGED')
 if r['action']=='PREPARE':
  if result['requiresRestart']:
   run(sql_command(r['target']),"ALTER SYSTEM SET logging_collector='on';")
   result.update(state='WAITING_RESTART',detailCode='PREPARED_RESTART')
  return result
 if result['requiresRestart']:return result
 # No SQL log configuration or installation begins before self-capture isolation is verified.
 require(r.get('selfAuditSafe') is True,'SELF_AUDIT_ISOLATION_REQUIRED')
 artifact=r.get('artifact',{});require(isinstance(artifact.get('base64'),str) and len(artifact['base64'])<90*1024*1024,'INSTALLATION_FAILED')
 try:binary=base64.b64decode(artifact['base64'],validate=True)
 except ValueError:raise Failure('INSTALLATION_FAILED')
 require(0<len(binary)<=64*1024*1024 and hashlib.sha256(binary).hexdigest()==artifact.get('sha256'),'INSTALLATION_FAILED')
 require(binary[:4]==b'\x7fELF' and len(binary)>20,'INSTALLATION_FAILED')
 machine=int.from_bytes(binary[18:20],'little');require((os.uname().machine,machine) in [('x86_64',62),('aarch64',183)],'TARGET_MISMATCH')
 platform=r.get('platform',{});require(platform.get('server')==c.get('Server'),'CONFIGURATION_CHANGED')
 root=owned_directory('/opt/selfguard-database/'+r['instanceId'],r['instanceId']);state=owned_directory('/var/lib/selfguard-database/'+r['instanceId'],r['instanceId'])
 source=pathlib.Path(result['sourcePath'])
 if p:
  ownership=pathlib.Path(p['hostData']).stat();owned_directory(source,r['instanceId'],ownership.st_uid,ownership.st_gid)
 units=service_units(r['instanceId'],source)
 if not p:
  units={k:v for k,v in units.items() if '-logs.' not in k}
 for name in units:
  existing=pathlib.Path('/etc/systemd/system')/name
  if existing.exists() or existing.is_symlink():
   safe_path(existing);require(existing.is_file() and existing.read_text().startswith('# SelfGuard database monitor '+r['instanceId']+'\n'),'UNIT_NOT_OWNED')
 config={'schema':'selfguard-database-monitor-v1','instanceId':r['instanceId'],'assetId':r['assetId'],'sourcePath':str(source),'engine':r['engine'],'format':result['format'],'stateDir':str(state),'server':c['Server'],'token':i['token']}
 if (root/'config.json').exists():assert_existing_binding(private_json(root/'config.json'),config)
 source_stat=source.stat()
 # Kept separately so the collector's strict config need not accept expiry internals.
 retention={'sourcePath':str(source),'sourceIdentity':[source_stat.st_dev,source_stat.st_ino]}
 for src,dst in [('CACertificate','caCertificate'),('ProxyMode','proxyMode'),('ProxyURL','proxyUrl')]:
  if c.get(src):config[dst]=c[src]
 atomic_private(root/'probe',binary,0o700);atomic_private(root/'config.json',json.dumps(config));atomic_private(root/'retention.json',json.dumps(retention));atomic_private(root/'runner.py',RETENTION_SCRIPT)
 for name,text in units.items():atomic_private(pathlib.Path('/etc/systemd/system')/name,text,0o644)
 run(['systemctl','daemon-reload'])
 prefix='selfguard-database-'+r['instanceId']
 # Expiry must be installed before any original SQL is emitted.
 run(['systemctl','enable','--now',prefix+'-expire.timer'])
 if p:
  run(['systemctl','enable','--now',prefix+'-logs.timer'])
  run(['systemctl','start',prefix+'-logs.service'])
  log_directory=str(pathlib.PurePosixPath(p['dataDirectory'])/('selfguard-audit-'+r['instanceId']))
  settings={'log_directory':log_directory,'log_destination':'csvlog','log_filename':'selfguard-%Y%m%d%H%M%S.log','log_file_mode':'0600','log_rotation_age':'60min','log_rotation_size':'10MB','log_error_verbosity':'verbose','log_parameter_max_length':'0','log_parameter_max_length_on_error':'0','log_timezone':'UTC','log_statement':'none','log_min_duration_sample':'-1','log_transaction_sample_rate':'0','log_duration':'off','log_connections':'on','log_disconnections':'on','log_min_error_statement':'error','log_min_duration_statement':'0'}
  # Values are generated locally, never arbitrary SQL from the HTTP request.
  statements='\n'.join("ALTER SYSTEM SET "+k+"='"+v.replace("'","''")+"';" for k,v in settings.items())
  run(sql_command(r['target']),statements+'\nSELECT pg_reload_conf();')
  for _ in range(20):
   after=postgres(r['target'])
   require(after['startedAt']==p['startedAt'],'TARGET_CHANGED')
   if all(after['settings'].get(k)==v for k,v in {'log_destination':'csvlog','log_min_duration_statement':'0','log_error_verbosity':'verbose','log_directory':log_directory,'log_timezone':'UTC'}.items()):break
   time.sleep(.1)
  else:raise Failure('CONFIGURATION_CHANGED')
 run(['systemctl','enable',prefix+'.service']);run(['systemctl','restart',prefix+'.service'])
 require(run(['systemctl','is-active',prefix+'.service'])=='active','COLLECTOR_NOT_RUNNING')
 return {**result,'state':'INSTALLED','detailCode':'INSTALLED'}
def main():
 try:
  if len(sys.argv)==4 and sys.argv[1]=='--expire':
   print(json.dumps(expire_logs(pathlib.Path(sys.argv[2]),sys.argv[3])));return
  raw=sys.stdin.buffer.read(90*1024*1024+1);require(len(raw)<=90*1024*1024,'INVALID_REQUEST')
  print(json.dumps(execute(json.loads(raw))))
 except Failure as e:print(json.dumps({'state':'BLOCKED','detailCode':e.code,'requiresRestart':False}))
 except Exception:print(json.dumps({'state':'BLOCKED','detailCode':'INTERNAL_ERROR','requiresRestart':False}))
if __name__=='__main__':main()
