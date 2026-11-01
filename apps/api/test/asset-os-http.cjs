const assert=require('node:assert/strict'),{randomUUID}=require('node:crypto');
async function main(){const base=process.env.TEST_API_URL;assert.ok(base,'Use isolated HTTP runner');
 async function request(path,token,body,method='GET',status=200){const r=await fetch(base+path,{method,headers:{'Content-Type':'application/json',...(token?{Authorization:'Bearer '+token}:{})},...(body?{body:JSON.stringify(body)}:{})});const data=await r.json();assert.equal(r.status,status,path+': '+JSON.stringify(data));return data;}
 const admin=(await request('/auth/login',null,{email:process.env.ADMIN_EMAIL||'admin@selfguard.local',password:process.env.ADMIN_PASSWORD},'POST')).token;
 const created=await request('/assets',admin,{hostname:'owned-distro-manual',os:'linux',osDistribution:'uos',osVersion:'20'},'POST',201);assert.equal(created.osDistribution,'uos');assert.equal(created.os,'linux');
 await request('/assets/'+created.id,admin,{os:'windows',osDistribution:'ubuntu'},'PATCH',400);
 const a=await request('/agent/enroll',process.env.ENROLLMENT_TOKEN,{hostname:'owned-distro-agent',os:'linux',agentVersion:'0.4.9',identity:randomUUID()},'POST',201);
 await request('/assets/'+a.assetId,admin,{osDistribution:'uos',osVersion:'20'},'PATCH');
 const inventory={distribution:{id:'ubuntu',versionId:'24.04'},distributionCollection:{complete:true}};
 await request('/agent/heartbeat',a.token,{inventory},'POST',201);
 const updated=await request('/assets/'+a.assetId,admin);assert.equal(updated.os,'linux');assert.equal(updated.osDistribution,'uos');assert.equal(updated.osVersion,'20');assert.deepEqual(updated.inventory.distribution,inventory.distribution);
 await request('/assets/'+a.assetId,admin,{owner:'owned-operator'},'PATCH');assert.equal((await request('/assets/'+a.assetId,admin)).osDistribution,'uos');
 const changed=await request('/assets/'+created.id,admin,{os:'windows'},'PATCH');assert.equal(changed.osDistribution,null);assert.equal(changed.osVersion,null);
 const list=await request('/assets?pageSize=15',admin);assert.ok(list.items.some(row=>row.id===a.assetId&&row.osDistribution==='uos'&&row.inventory.distribution.id==='ubuntu'));
 console.log('PASS: separate OS family and registration; invalid mismatch rejected; heartbeat keeps registration and actual evidence separate; list/detail round trip; family switch clears stale metadata');
}main().catch(e=>{console.error(e.message);process.exitCode=1});
