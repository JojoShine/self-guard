// Run against the dedicated disposable fixture containers only; never accepts remote endpoints.
import {readFileSync,mkdirSync,writeFileSync} from 'node:fs';
import {resolve} from 'node:path';
import {databaseRuntimeInput} from '../src/database-runtime-contract';
import {readVendorDatabaseMetrics} from '../src/database-vendor-metrics';

async function main(){
 const envFile=process.env.SG_VENDOR_ACCEPT_ENV;
 if(!envFile)throw new Error('SG_VENDOR_ACCEPT_ENV_REQUIRED');
 const secrets=Object.fromEntries(readFileSync(envFile,'utf8').trim().split('\n').map(line=>{const index=line.indexOf('=');return [line.slice(0,index),line.slice(index+1)];}));
 const results:Record<string,unknown>={capturedAt:new Date().toISOString(),scope:'isolated-loopback-fixtures',kingbase:{status:'NOT_ACCEPTED',reason:'PROPRIETARY_MEDIA_UNAVAILABLE'},vastbase:{status:'NOT_ACCEPTED',reason:'PROPRIETARY_MEDIA_UNAVAILABLE'},oracle11g:{status:'NOT_SUPPORTED',reason:'THIN_REQUIRES_12_1_OR_LATER_THICK_CLIENT_NOT_DEPLOYED'},dmTls:{status:'NOT_SUPPORTED',reason:'OFFICIAL_DRIVER_REJECT_UNAUTHORIZED_FALSE'}};
 let failed=false;
 const selected=process.env.SG_VENDOR_ACCEPT_ENGINE;
 if(selected&&selected!=='oracle'&&selected!=='dm')throw new Error('FIXTURE_ENGINE_INVALID');
 for(const engine of ['oracle','dm'] as const){
  if(selected&&selected!==engine)continue;
  const config=databaseRuntimeInput.parse({address:'127.0.0.1',port:engine==='oracle'?21521:25236,database:engine==='oracle'?'FREEPDB1':'DAMENG',username:engine==='oracle'?'system':'SYSDBA',tls:false});
  try{results[engine]=await readVendorDatabaseMetrics(engine,config,secrets[engine==='oracle'?'ORACLE_PASSWORD':'SYSDBA_PWD'],1);}
  catch(error){failed=true;results[engine]={status:'NOT_ACCEPTED',reason:error instanceof Error&&/^DATABASE_[A-Z_]+$/.test(error.message)?error.message:'DATABASE_COLLECTION_FAILED'};}
 }
 const output=resolve(__dirname,'../../../.artifacts/results/database-vendor-acceptance');mkdirSync(output,{recursive:true});
 writeFileSync(resolve(output,selected?`${selected}-result.json`:'result.json'),JSON.stringify(results,null,2)+'\n');
 console.log(JSON.stringify(results,null,2));if(failed)process.exitCode=1;
}
void main().catch(()=>{console.error('VENDOR_ACCEPTANCE_FAILED');process.exitCode=1;});
