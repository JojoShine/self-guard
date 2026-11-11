import assert from 'node:assert/strict';
import {createServer} from 'node:net';
import {mkdtempSync,writeFileSync,mkdirSync,rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join,resolve} from 'node:path';
import {databaseRuntimeInput} from '../src/database-runtime-contract';
import {readVendorDatabaseMetrics} from '../src/database-vendor-metrics';
async function main(){
 const folder=mkdtempSync(join(tmpdir(),'sg-vendor-deadline-'));let connected=false,closed=false;
 const server=createServer(socket=>{connected=true;socket.on('close',()=>{closed=true;});});await new Promise<void>(resolve=>server.listen(0,'127.0.0.1',resolve));
 const old=process.env.SELFGUARD_DM_DRIVER_PATH;
 try{
  const address=server.address();assert.ok(address&&typeof address==='object');
  // Deliberately hung test-only driver ignores every timeout option. It never supplies metrics or a vendor identity.
  const module=join(folder,'hung.cjs');writeFileSync(module,`exports.getConnection=async()=>{require('node:net').connect(${address.port},'127.0.0.1');await new Promise(()=>{});};`);process.env.SELFGUARD_DM_DRIVER_PATH=module;
  const config=databaseRuntimeInput.parse({address:'127.0.0.1',port:address.port,database:'fixture',username:'fixture',tls:false});const started=Date.now();
  await assert.rejects(readVendorDatabaseMetrics('dm',config,'fixture-password',1),/DATABASE_COLLECTION_TIMEOUT/);const elapsedMs=Date.now()-started;
  for(let attempt=0;attempt<20&&!closed;attempt++)await new Promise(resolve=>setTimeout(resolve,50));
  assert.ok(connected);assert.ok(closed,'terminating the collector must close its socket');assert.ok(elapsedMs>=9500&&elapsedMs<13000);
  const output=resolve(__dirname,'../../../.artifacts/results/database-vendor-acceptance');mkdirSync(output,{recursive:true});const result={capturedAt:new Date().toISOString(),scope:'deliberately hung synthetic driver; no vendor acceptance',elapsedMs,socketClosed:'PASS'};writeFileSync(join(output,'deadline-result.json'),JSON.stringify(result,null,2)+'\n');console.log(JSON.stringify(result));
 }finally{if(old===undefined)delete process.env.SELFGUARD_DM_DRIVER_PATH;else process.env.SELFGUARD_DM_DRIVER_PATH=old;await new Promise<void>(resolve=>server.close(()=>resolve()));rmSync(folder,{recursive:true,force:true});}
}
void main().catch(()=>{console.error('VENDOR_DEADLINE_ACCEPTANCE_FAILED');process.exitCode=1;});
