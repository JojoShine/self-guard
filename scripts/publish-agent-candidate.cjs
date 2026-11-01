const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto'),assert=require('node:assert/strict');
const version=process.argv[2];assert.match(version||'',/^\d+\.\d+\.\d+$/);
const env=Object.fromEntries(fs.readFileSync('.env','utf8').split(/\r?\n/).filter(s=>s.includes('=')).map(s=>{const i=s.indexOf('=');return[s.slice(0,i),s.slice(i+1)]}));
async function main(){
 const base='http://127.0.0.1:4010/api';const login=await fetch(base+'/auth/login',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({email:env.ADMIN_EMAIL||'admin@selfguard.local',password:env.ADMIN_PASSWORD})});assert.ok(login.ok);const{token}=await login.json(),proof=[];
 async function call(url,body,raw=false){const r=await fetch(base+url,{method:body!==undefined?'POST':'GET',headers:{authorization:'Bearer '+token,'content-type':raw?'application/octet-stream':'application/json'},...(body!==undefined?{body:raw?body:JSON.stringify(body)}:{})});if(!r.ok)throw Error(url+': '+await r.text());return r.json()}
 async function verify(url,file,metadata){const r=await fetch(base+url,{headers:{authorization:'Bearer '+token}});assert.ok(r.ok);const bytes=Buffer.from(await r.arrayBuffer()),expected=fs.readFileSync(file);assert.ok(bytes.equals(expected));proof.push({...metadata,bytes:bytes.length,sha256:crypto.createHash('sha256').update(bytes).digest('hex')})}
 for(const arch of ['amd64','arm64']){
 const dir=path.join('.artifacts/releases',version),definition=JSON.parse(fs.readFileSync(path.join(dir,arch,'release.json')));assert.equal(definition.channel,'canary');
 let release=(await call('/agent-releases?q='+version+'&pageSize=100')).items.find(r=>r.version===version&&r.architecture===arch);
 if(!release)release=await call('/agent-releases',definition);
 if(release.status==='DRAFT'){await call('/agent-releases/'+release.id+'/artifact',fs.readFileSync(path.join(dir,arch,'selfguard-agent')),true);release=await call('/agent-releases/'+release.id+'/publish',{})}
 assert.equal(release.status,'PUBLISHED');assert.equal(release.channel,'canary');await verify('/agent-releases/'+release.id+'/download',path.join(dir,arch,'selfguard-agent'),{version,architecture:arch,format:'raw'});
 release=(await call('/agent-releases?q='+version+'&pageSize=100')).items.find(r=>r.id===release.id);
 for(const format of ['tar.gz','deb','rpm']){
 const meta=JSON.parse(fs.readFileSync(path.join(dir,'packages',arch,format+'.json')));let pkg=release.packages?.find(p=>p.format===format);
 if(!pkg)pkg=await call('/agent-releases/'+release.id+'/packages',meta.envelope);
 if(pkg.status==='DRAFT'){await call('/agent-releases/packages/'+pkg.id+'/artifact',fs.readFileSync(path.join(dir,meta.filename)),true);pkg=await call('/agent-releases/packages/'+pkg.id+'/publish',{})}
 assert.equal(pkg.status,'PUBLISHED');await verify('/agent-releases/packages/'+pkg.id+'/download',path.join(dir,meta.filename),{version,architecture:arch,format});
 }
 }
 fs.writeFileSync('.artifacts/results/expansion/agent-'+version+'-downloads.json',JSON.stringify(proof,null,2));console.log('PASS signed canary '+version+': 8 raw/tar/deb/rpm downloads exactly match local artifacts; no installation or rollout created');
}
main().catch(e=>{console.error(e.message);process.exitCode=1});
