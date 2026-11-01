// Actual owned inventory and official branch data; no installed-version mutation.
const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto'),assert=require('node:assert/strict'),{spawn}=require('node:child_process');
process.env.AGENT_NATIVE_VM='native-alpine-3.23-arm64';const{call,shell,loginFixture}=require('./agent-native-smoke.cjs');
const quote=s=>"'"+s.replace(/'/g,"'\\''")+"'";
async function download(url,file){await new Promise((resolve,reject)=>{const p=spawn('curl',['--fail','--silent','--show-error','--proto','=https','--tlsv1.2','--connect-timeout','15','--max-time','60','--output',file,url],{stdio:['ignore','ignore','pipe']});let error='';p.stderr.on('data',b=>error+=b);p.on('error',reject);p.on('exit',code=>code===0?resolve():reject(Error(error)))});}
async function main(){
 await loginFixture();const accepted=JSON.parse(fs.readFileSync('.artifacts/native-agent/alpine-openrc-result.json')),asset=await call('/assets/'+accepted.assetId),inventory=asset.inventory;
 assert.equal(asset.business,'native-acceptance');assert.equal(inventory.distribution.id,'alpine');assert.equal(inventory.distribution.versionId,'3.23.4');assert.equal(inventory.packageCollection.complete,true);assert.ok(Date.now()-Date.parse(asset.lastSeen)<120000);
 const folder=fs.mkdtempSync('.artifacts/intelligence-inputs/alpine-native-');fs.chmodSync(folder,0o700);const sources=[];
 await Promise.all(['main','community'].map(async repository=>{const url='https://secdb.alpinelinux.org/v3.23/'+repository+'.json',file=path.join(folder,repository+'.json');await download(url,file);const bytes=fs.readFileSync(file),document=JSON.parse(bytes);assert.equal(document.distroversion,'v3.23');assert.equal(document.reponame,repository);assert.ok(document.packages.length);sources.push({repository,url,file,sourceSha256:crypto.createHash('sha256').update(bytes).digest('hex')});}));sources.sort((a,b)=>a.repository.localeCompare(b.repository));
 const pairs=[],indexes=new Map(),groups=new Map();
 for(const source of sources)for(const entry of JSON.parse(fs.readFileSync(source.file)).packages){const pkg=entry.pkg;for(const installed of inventory.packages.filter(row=>row.origin===pkg.name||row.name===pkg.name))for(const[fixed,ids]of Object.entries(pkg.secfixes||{})){
  const key=JSON.stringify([installed.version,fixed]);if(!indexes.has(key)){indexes.set(key,pairs.length);pairs.push([installed.version,fixed]);}
  for(const id of ids){assert.equal(typeof id,'string');assert.ok(id.trim()&&id.length<=500);const groupKey=JSON.stringify([installed.name,source.repository,pkg.name,id]);if(!groups.has(groupKey))groups.set(groupKey,{name:installed.name,origin:pkg.name,repository:source.repository,cve:id,pairs:[]});groups.get(groupKey).pairs.push(indexes.get(key));}
 }}
 assert.ok(pairs.length&&pairs.length<=5000);
 const python="import sys,json,subprocess\npairs=json.load(sys.stdin);out=[]\nfor a,b in pairs:\n p=subprocess.run(['apk','version','-t','--',a,b],capture_output=True,text=True,timeout=2)\n if p.returncode or p.stdout.strip() not in ['<','=','>']: raise RuntimeError('Native APK comparison failed')\n out.append(p.stdout.strip())\nprint(json.dumps(out))\n";
 const comparisons=JSON.parse(await shell('python3 -c '+quote(python),JSON.stringify(pairs)));assert.equal(comparisons.length,pairs.length);
 const expected=[...new Set([...groups.values()].filter(row=>row.pairs.every(i=>comparisons[i]==='<')).map(row=>JSON.stringify([row.name,row.cve])))].sort();
 const file=path.join(folder,'actual-native-input.json');fs.writeFileSync(file,JSON.stringify({at:new Date().toISOString(),assetId:asset.id,inventoryAt:asset.lastSeen,inventory,oracle:{command:'native apk version -t, no shell argument interpolation',pairs,comparisons,expected},sources},null,2),{mode:0o600});
 fs.writeFileSync('.artifacts/results/expansion/alpine-native-source-input.json',JSON.stringify({file,sources:sources.map(({file,...row})=>row)},null,2),{mode:0o600});console.log(JSON.stringify({input:file,packages:inventory.packages.length,nativeComparisonPairs:pairs.length,expectedAffectedPackageAdvisories:expected.length,sources:sources.map(({file,...row})=>row)}));
}
main().catch(error=>{console.error(error.message);process.exitCode=1});
