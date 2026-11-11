import assert from 'node:assert/strict';
import {readFileSync,writeFileSync,mkdirSync} from 'node:fs';
import {resolve} from 'node:path';
import {databaseRuntimeInput} from '../src/database-runtime-contract';
import {readVendorDatabaseMetrics} from '../src/database-vendor-metrics';
async function main(){
 const envFile=process.env.SG_VENDOR_ACCEPT_ENV,caFile=process.env.SG_VENDOR_ACCEPT_CA;
 if(!envFile||!caFile)throw new Error('FIXTURE_FILES_REQUIRED');
 const password=readFileSync(envFile,'utf8').split('\n').find(line=>line.startsWith('ORACLE_PASSWORD='))?.slice('ORACLE_PASSWORD='.length);
 if(!password)throw new Error('FIXTURE_PASSWORD_REQUIRED');
 const config=databaseRuntimeInput.parse({address:'localhost',port:21521,database:'FREEPDB1',username:process.env.SG_VENDOR_ACCEPT_USER||'system',tls:true,caCertificate:readFileSync(caFile,'utf8')});
 const sample=await readVendorDatabaseMetrics('oracle',config,password,1);
 await assert.rejects(readVendorDatabaseMetrics('oracle',{...config,caCertificate:''},password,1),/DATABASE_CONNECTION_FAILED/);
 await assert.rejects(readVendorDatabaseMetrics('oracle',{...config,address:'127.0.0.1'},password,1),/DATABASE_CONNECTION_FAILED/);
 await assert.rejects(readVendorDatabaseMetrics('oracle',config,password+'-wrong',1),/DATABASE_CONNECTION_FAILED/);
 const noStats=process.env.SG_VENDOR_ACCEPT_NO_STATS_USER;
 if(noStats)await assert.rejects(readVendorDatabaseMetrics('oracle',{...config,username:noStats},password,1),/DATABASE_STATISTICS_UNAVAILABLE/);
 assert.equal((await readVendorDatabaseMetrics('oracle',config,password,1)).engine,'oracle','fixture must remain reachable after negative checks');
 const result={dedicatedReadOnlyAccount:!!process.env.SG_VENDOR_ACCEPT_USER,wrongPasswordRejected:'PASS',...(noStats?{missingStatisticsPermissionRejected:'PASS'}:{}),capturedAt:new Date().toISOString(),scope:'isolated-oracle-fixture',trustedCAAndHostname:'PASS',untrustedCARejected:'PASS',wrongHostnameRejected:'PASS',sample};
 const output=resolve(__dirname,'../../../.artifacts/results/database-vendor-acceptance');mkdirSync(output,{recursive:true});writeFileSync(resolve(output,'tls-result.json'),JSON.stringify(result,null,2)+'\n');console.log(JSON.stringify(result,null,2));
}
void main().catch(error=>{console.error(error instanceof Error&&/^[A-Z_]+$/.test(error.message)?error.message:'TLS_ACCEPTANCE_FAILED');process.exitCode=1;});
