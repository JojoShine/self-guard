import {test} from 'node:test';import assert from 'node:assert/strict';
import {sealMonitorPassword,openMonitorPassword,monitorPublicConfig,validateMonitorCA} from '../src/postgres-monitor';
import {postgresMonitorInput} from '../src/monitoring-contract';
test('monitor password is encrypted and bound to instance, endpoint, account and TLS trust',()=>{
 const saved=process.env.DATA_ENCRYPTION_KEY;process.env.DATA_ENCRYPTION_KEY='c'.repeat(64);
 try{const config=postgresMonitorInput.parse({address:'192.0.2.1',port:5432,database:'app',username:'monitor',password:'private-monitor-value',tls:true});const cipher=sealMonitorPassword('instance',config,config.password!);assert.ok(!cipher.includes('private-monitor-value'));assert.equal(openMonitorPassword('instance',config,cipher),'private-monitor-value');assert.throws(()=>openMonitorPassword('other',config,cipher));assert.throws(()=>openMonitorPassword('instance',{...config,address:'192.0.2.2'},cipher));assert.throws(()=>openMonitorPassword('instance',{...config,username:'other'},cipher));assert.ok(!JSON.stringify(monitorPublicConfig(config)).includes('private-monitor-value'));}finally{if(saved===undefined)delete process.env.DATA_ENCRYPTION_KEY;else process.env.DATA_ENCRYPTION_KEY=saved;}
});

test('monitor trust accepts only valid certificates and rejects private material',()=>{assert.doesNotThrow(()=>validateMonitorCA(''));assert.throws(()=>validateMonitorCA('-----BEGIN PRIVATE KEY-----\nfixture\n-----END PRIVATE KEY-----'));assert.throws(()=>validateMonitorCA('-----BEGIN CERTIFICATE-----\ninvalid\n-----END CERTIFICATE-----'));});

test('generic credentials are also bound to the product engine',()=>{
 const saved=process.env.DATA_ENCRYPTION_KEY;process.env.DATA_ENCRYPTION_KEY='c'.repeat(64);
 try{const config=postgresMonitorInput.parse({address:'127.0.0.1',port:3306,database:'app',username:'monitor',tls:false});const cipher=sealMonitorPassword('instance',config,'secret','mysql');assert.equal(openMonitorPassword('instance',config,cipher,'mysql'),'secret');assert.throws(()=>openMonitorPassword('instance',config,cipher,'redis'));assert.throws(()=>openMonitorPassword('instance',config,cipher));}finally{if(saved===undefined)delete process.env.DATA_ENCRYPTION_KEY;else process.env.DATA_ENCRYPTION_KEY=saved;}
});
