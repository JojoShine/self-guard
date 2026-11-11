import assert from 'node:assert/strict';
import {createServer} from 'node:tls';
import {readFileSync,writeFileSync,mkdirSync} from 'node:fs';
import {resolve} from 'node:path';
import {databaseRuntimeInput} from '../src/database-runtime-contract';
import {readVendorDatabaseMetrics} from '../src/database-vendor-metrics';
async function main(){
 const cert=readFileSync('/private/tmp/sg-vendor-tls-cert.pem','utf8'),key=readFileSync('/private/tmp/sg-vendor-tls-key.pem','utf8');let handshakes=0;
 const server=createServer({cert,key},socket=>{handshakes++;socket.destroy();});server.on('tlsClientError',()=>{});
 await new Promise<void>(resolve=>server.listen(0,'127.0.0.1',resolve));
 try{
  const address=server.address();assert.ok(address&&typeof address==='object');
  const config=databaseRuntimeInput.parse({address:'localhost',port:address.port,database:'FREEPDB1',username:'fixture',tls:true,caCertificate:cert});
  // The fixture ends after TLS; it never pretends to implement Oracle or supply database metrics.
  await assert.rejects(readVendorDatabaseMetrics('oracle',config,'fixture-password',1));assert.equal(handshakes,1,'trusted CA+hostname must complete the actual driver TLS handshake');
  await assert.rejects(readVendorDatabaseMetrics('oracle',{...config,caCertificate:''},'fixture-password',1));assert.equal(handshakes,1,'untrusted CA must not complete TLS');
  await assert.rejects(readVendorDatabaseMetrics('oracle',{...config,address:'127.0.0.1'},'fixture-password',1));assert.equal(handshakes,1,'wrong hostname must not complete TLS');
  const result={capturedAt:new Date().toISOString(),driver:'oracledb@6.10.0 Thin',scope:'synthetic TLS handshake only; no Oracle server protocol',trustedCAAndHostname:'PASS',untrustedCARejected:'PASS',wrongHostnameRejected:'PASS',liveOracleTCPS:'NOT_ACCEPTED',liveOracleTCPSReason:'Cached slim server image lacks Java required by orapki wallet tooling'};
  const output=resolve(__dirname,'../../../.artifacts/results/database-vendor-acceptance');mkdirSync(output,{recursive:true});writeFileSync(resolve(output,'tls-handshake-result.json'),JSON.stringify(result,null,2)+'\n');console.log(JSON.stringify(result,null,2));
 }finally{await new Promise<void>(resolve=>server.close(()=>resolve()));}
}
void main().catch(()=>{console.error('TLS_HANDSHAKE_ACCEPTANCE_FAILED');process.exitCode=1;});
