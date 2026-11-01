const fs=require('fs'),{execFileSync}=require('child_process'),assert=require('assert/strict');
const root=process.cwd(),env=Object.fromEntries(fs.readFileSync('.env','utf8').trim().split('\n').map(l=>{const i=l.indexOf('=');return[l.slice(0,i),l.slice(i+1)]}));
const base=process.env.RUNTIME_URL||'http://127.0.0.1:5182';const delay=ms=>new Promise(r=>setTimeout(r,ms));
async function waitHealth(count){for(let i=0;i<90;i++){try{const r=await fetch(base+'/health');const h=await r.json();if(h.healthy===count)return h}catch{}await delay(1000)}throw Error('Runtime readiness timeout')}
function compose(...args){execFileSync('docker',['compose','-f','compose.runtime.yaml',...args],{cwd:root,stdio:'pipe'})}
(async()=>{await waitHealth(2);const login=await fetch(base+'/api/auth/login',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({email:env.ADMIN_EMAIL,password:env.ADMIN_PASSWORD})});assert.equal(login.status,200);const {token}=await login.json();
 async function authenticated(){const r=await fetch(base+'/api/auth/me',{headers:{authorization:'Bearer '+token}});assert.equal(r.status,200);assert.equal((await r.json()).email,env.ADMIN_EMAIL)}
 for(let i=0;i<6;i++)await authenticated();
 try{compose('stop','api');await waitHealth(1);for(let i=0;i<8;i++)await authenticated();console.log('API node failover passed: existing session survived node loss.')}finally{compose('start','api');await waitHealth(2)}
 const start=Date.now();let ok=0;await Promise.all(Array.from({length:10},async()=>{for(let i=0;i<20;i++){await authenticated();ok++}}));const seconds=(Date.now()-start)/1000;fs.writeFileSync('.artifacts/results/runtime-benchmark.json',JSON.stringify({requests:ok,concurrency:10,seconds,requestsPerSecond:ok/seconds,scope:'Local Docker reference only; not a production SLA',time:new Date().toISOString()},null,2));console.log('Reference concurrency check passed: '+ok+' authenticated requests, no failures.');
})().catch(e=>{console.error(e.message);process.exit(1)});
