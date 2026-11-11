const fs=require('node:fs'),path=require('node:path'),assert=require('node:assert/strict'),{createHash}=require('node:crypto'),{execFileSync}=require('node:child_process');
const root=path.resolve(__dirname,'..'),base=process.env.SECURITY_API_URL||'http://127.0.0.1:5180/api';
async function main(){
 const archive=path.join(root,'third_party/crs/v4.25.1.tar.gz');assert.equal(createHash('sha256').update(fs.readFileSync(archive)).digest('hex'),'0539e66e7627fe71c160a644d8fb7ab6e450d53c9de208be5f95a35c70e1a154','Pinned official CRS archive changed');
 const members=execFileSync('tar',['-tf',archive],{encoding:'utf8'}).split('\n');const files=[];
 for(const name of fs.readdirSync(path.join(root,'third_party/crs/v4.25.1/rules')).filter(name=>/\.(conf|data)$/.test(name)).sort()){
  const member=members.find(item=>item.endsWith('/rules/'+name));assert.ok(member,'Original CRS member missing');const original=execFileSync('tar',['-xOf',archive,member],{maxBuffer:2*1024*1024});assert.deepEqual(fs.readFileSync(path.join(root,'third_party/crs/v4.25.1/rules',name)),original,'CRS working file differs from official archive: '+name);files.push({name:'rules/'+name,source:original.toString('utf8')});
 }
 const login=await fetch(base+'/auth/login',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({email:process.env.ADMIN_EMAIL,password:process.env.ADMIN_PASSWORD})});assert.ok(login.ok,'Login failed');const{token}=await login.json(),headers={'content-type':'application/json',authorization:'Bearer '+token};
 async function call(route,body){const response=await fetch(base+route,{method:body?'POST':'GET',headers,...(body?{body:JSON.stringify(body)}:{}),signal:AbortSignal.timeout(90000)});const value=await response.json();if(!response.ok)throw Error(route+': '+response.status+' '+value.message);return value}
 async function all(route){const items=[];for(let page=1;;page++){const data=await call(route+'?page='+page+'&pageSize=100');items.push(...data.items);if(items.length>=data.total)return items}}
 try{
  const definitions=[
   {name:'CISA KEV 官方在野利用目录',provider:'CISA_KEV',config:{},enabled:true},
   {name:'Alpine 3.23 main 官方修复库',provider:'ALPINE',config:{branch:'v3.23',repository:'main'},enabled:true},
   {name:'Debian 12 官方安全跟踪',provider:'DEBIAN',config:{release:'bookworm'},enabled:false},
   {name:'OSV PyPI 官方生态库',provider:'OSV',config:{mode:'ECOSYSTEM',ecosystem:'PyPI',syncMode:'AUTO'},enabled:false},
   {name:'NVD '+new Date().getUTCFullYear()+' 官方年度库',provider:'NVD',config:{mode:'YEAR',year:new Date().getUTCFullYear(),syncMode:'AUTO'},enabled:false},
  ];
  const existing=await all('/vulnerability-feeds'),feeds=[];const canonical=value=>JSON.stringify(Object.entries(value).sort(([a],[b])=>a.localeCompare(b)));
  for(const definition of definitions){let row=existing.find(row=>row.provider===definition.provider&&canonical(row.config)===canonical(definition.config));if(!row){row=await call('/vulnerability-feeds',{...definition,intervalSeconds:86400,staleAfterHours:72});existing.push(row)}feeds.push(row);console.log('Official source ready:',row.name,row.enabled?'enabled':'awaiting full-feed activation')}
  const bundles=await all('/waf-rule-bundles');const source='https://github.com/coreruleset/coreruleset/releases/tag/v4.25.1';let bundle=bundles.find(row=>row.source===source&&row.version==='4.25.1');if(!bundle)bundle=await call('/waf-rule-bundles',{name:'OWASP CRS 官方规则库',version:'4.25.1',source,license:'Apache-2.0',files});console.log('Official CRS candidate ready:',files.length,'original files');
  const synchronization=[];for(const feed of feeds.filter(feed=>feed.enabled&&['CISA_KEV','ALPINE'].includes(feed.provider))){try{const result=await call('/vulnerability-feeds/'+feed.id+'/sync',{});synchronization.push({provider:feed.provider,status:result.snapshot?.status||result.feed?.status||'QUEUED',recordCount:result.snapshot?.recordCount});console.log('Official source synchronization:',feed.provider,JSON.stringify(synchronization.at(-1)))}catch(error){synchronization.push({provider:feed.provider,error:error.message});console.log('Official source synchronization requires attention:',feed.provider,error.message)}}
  let compatibility;try{const result=await call('/waf-rule-bundles/'+bundle.id+'/check',{});compatibility={status:result.status,report:result.report};console.log('CRS compatibility:',JSON.stringify(compatibility))}catch(error){compatibility={error:error.message};console.log('CRS candidate retained; compatibility pending:',error.message)}
  const report={at:new Date().toISOString(),feeds:feeds.map(({id,name,provider,enabled,config})=>({id,name,provider,enabled,config})),bundle:{id:bundle.id,version:bundle.version,fileCount:files.length},synchronization,compatibility,runtimePublished:false};const folder=path.join(root,'.artifacts/results/security-foundations');fs.mkdirSync(folder,{recursive:true});fs.writeFileSync(path.join(folder,'official-library-initialization.json'),JSON.stringify(report,null,2));
 }finally{await fetch(base+'/auth/logout',{method:'POST',headers})}
}
main().catch(error=>{console.error(error.message);process.exitCode=1});
