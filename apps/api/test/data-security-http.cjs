const assert=require('node:assert/strict'),fs=require('node:fs');
async function main(){
 const base=process.env.TEST_API_URL;assert.ok(base&&base.includes(':4400'));
 const login=await fetch(base+'/auth/login',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({email:process.env.ADMIN_EMAIL||'admin@selfguard.local',password:process.env.ADMIN_PASSWORD})});assert.ok(login.ok);const token=(await login.json()).token;
 async function call(path,body,auth=token){const r=await fetch(base+path,{method:body?'POST':'GET',headers:{authorization:'Bearer '+auth,'content-type':'application/json'},...(body?{body:JSON.stringify(body)}:{})});const v=await r.json();assert.ok(r.ok,path+': '+JSON.stringify(v));return v}
 const catalog=await call('/rule-tools/catalog/database');assert.ok(catalog.items.length>=25);
 const asset=await call('/assets',{hostname:'isolated-db',os:'linux'});
 const rule=await call('/rules',{name:'数据库疑似口令爆破',kind:'LOG',severity:'HIGH',enabled:true,config:{type:'DATABASE_AUTH',service:'postgresql',path:'/db/log.json',threshold:3,windowSeconds:60,applicability:{assetIds:[asset.id]}}});
 const lines=Array.from({length:3},(_,i)=>JSON.stringify({timestamp:new Date(Date.now()-i*1000).toISOString(),remote_host:'192.0.2.10',remote_port:'54000',user:'probe-'+i,dbname:'app',state_code:'28P01',message:'password=must-not-retain'}));
 const result=await call('/rule-tools/'+rule.id+'/test',{assetId:asset.id,fixture:{lines,source:'/db/log.json'}});assert.equal(result.matched,true);assert.equal(result.readOnly,true);assert.ok(!JSON.stringify(result).includes('must-not-retain'));assert.equal((await call('/findings')).total,0);
 const mysqlRule=await call('/rules',{name:'MySQL格式样本',kind:'LOG',severity:'HIGH',enabled:true,config:{type:'DATABASE_AUTH',service:'mysql',path:'/db/mysql.log',threshold:3,windowSeconds:60}});
 const mysqlLines=Array.from({length:3},(_,i)=>new Date(Date.now()-i*1000).toISOString()+" 1 [Warning] [MY-010926] [Server] Access denied for user 'audit_user'@'192.0.2.5' (using password: YES)");
 assert.equal((await call('/rule-tools/'+mysqlRule.id+'/test',{assetId:asset.id,fixture:{lines:mysqlLines,source:'/db/mysql.log'}})).matched,true);
 const site=await call('/sites',{name:'隔离站点',hostname:'isolated.test',upstream:'http://127.0.0.1:1',enabled:true,mode:'BLOCK'});
 const context={requestId:'isolated-request',peerIp:'192.0.2.1',clientIp:'192.0.2.1',sourceBasis:'SOCKET_PEER',incomingTls:false,requestTargetSha256:'a'.repeat(64),pathRetention:'SANITIZED_PATH_QUERY_VALUES_NOT_RETAINED',queryKeys:['password'],queryKeysOmitted:0,forwarded:false,action:'BLOCK',ruleId:'SQLI',outcome:'BLOCKED_BY_WAF',banState:'NO_PERSISTENT_BAN'};
 const access={id:context.requestId,siteId:site.id,method:'GET',path:'/api/orders',status:403,timestamp:new Date().toISOString(),durationMicros:1200,context};
 await call('/telemetry/access',{nodeId:'isolated-node',events:[access]},process.env.WAF_TOKEN);
 await call('/telemetry/access',{nodeId:'isolated-node',events:[access]},process.env.WAF_TOKEN);
 await call('/waf/heartbeat',{nodeId:'isolated-node',version:'fixture',sites:[],droppedEvents:0,startedAt:new Date().toISOString(),accessHistory:[{...access,id:'unknown-site-request',siteId:''}]},process.env.WAF_TOKEN);
 const saved=await call('/waf-access/'+context.requestId);assert.equal(saved.context.requestId,context.requestId);assert.equal(saved.path,'/api/orders');assert.equal((await call('/waf-access')).total,2);
 await call('/waf/events',{events:[{id:'isolated-event',siteId:site.id,ruleId:'SQLI',path:'/api/orders',method:'GET',action:'BLOCK',remoteIp:'192.0.2.1',timestamp:access.timestamp,context}]},process.env.WAF_TOKEN);
 const event=await call('/waf-events/isolated-event');assert.deepEqual(event.context,context);assert.equal(event.context.requestId,saved.id);
 if(process.env.TEST_WAF_URL){
 const target='/__owned_trace_'+Date.now()+'__',response=await fetch(process.env.TEST_WAF_URL+target+'?diagnostic=not-retained');assert.equal(response.status,404);
 let observed;for(let i=0;i<60;i++){observed=(await call('/waf-access?q='+encodeURIComponent(target))).items.find(row=>row.path===target);if(observed)break;await new Promise(r=>setTimeout(r,250))}
 assert.ok(observed?.context);assert.equal(observed.context.requestId,observed.id);assert.equal(observed.context.forwarded,false);assert.equal(observed.context.outcome,'NOT_FORWARDED');assert.ok(observed.context.peerIp);assert.ok(!JSON.stringify(observed).includes('not-retained'));
 console.log('PASS actual final WAF process -> durable queue -> isolated running API -> access detail, real peer and matching request ID');
 }
 console.log('PASS isolated actual Go database rule engine, no fixture findings, durable trace/access/event linkage and idempotent retry');
}
main().catch(e=>{console.error(e);process.exitCode=1});
