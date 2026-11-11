import {test} from 'node:test';import assert from 'node:assert/strict';
import {parseRedisInfo,databaseRates} from '../src/database-native-metrics';
import {databaseRuntimeInput} from '../src/database-runtime-contract';
const config=databaseRuntimeInput.parse({address:'127.0.0.1',port:6379,database:'0',username:'monitor',tls:false});
test('Redis reports only observed counters; unlimited memory has no percent',()=>{
 const metric=parseRedisInfo('redis_version:7.4.2\r\nrun_id:abc\r\nuptime_in_seconds:12\r\nconnected_clients:2\r\nmaxclients:100\r\nused_memory:1024\r\nmaxmemory:0\r\ntotal_commands_processed:20\r\nkeyspace_hits:9\r\nkeyspace_misses:1\r\ndb0:keys=3,expires=0,avg_ttl=0\r\n',config,1,2);
 assert.equal(metric.engine,'redis');assert.equal(metric.keyCount,3);assert.equal(metric.memoryPercent,undefined);assert.equal(metric.commits,undefined);assert.equal(metric.cacheHitPercent,90);
});
test('Redis rejects unknown identity and oversized replies',()=>{assert.throws(()=>parseRedisInfo('redis_version:garbage',config,1,0));assert.throws(()=>parseRedisInfo('x'.repeat(1024*1024+1),config,1,0));});
test('rates require matching engine, version, reset and monotone counters',()=>{
 const old=parseRedisInfo('redis_version:7.4.2\r\nrun_id:a\r\ntotal_commands_processed:10',config,1,0);const current={...old,capturedAt:new Date(Date.parse(old.capturedAt)+10000).toISOString(),commands:30};
 assert.equal(databaseRates(old,current).commandsPerSecond,2);assert.deepEqual(databaseRates({...old,configurationVersion:2},current),{});assert.deepEqual(databaseRates({...old,resetAt:'changed'},current),{});
});
test('rate derivation detects restart even when counters have already caught up',()=>{const old=parseRedisInfo('redis_version:7.4.2\r\nrun_id:a\r\nuptime_in_seconds:100\r\ntotal_commands_processed:10',config,1,0);assert.deepEqual(databaseRates(old,{...old,capturedAt:new Date(Date.parse(old.capturedAt)+10000).toISOString(),uptimeSeconds:105,commands:30}),{});});
test('generic configuration keeps TLS mandatory beyond literal loopback',()=>{assert.equal(databaseRuntimeInput.safeParse({...config,address:'localhost',tls:false}).success,false);assert.equal(databaseRuntimeInput.safeParse({...config,address:'192.0.2.1',tls:false}).success,false);});
test('MySQL literal IP TLS fails before authentication because driver skips IP SAN identity check',async()=>{const {readMysqlMetrics}=await import('../src/database-native-metrics');await assert.rejects(readMysqlMetrics({...config,tls:true},'never-sent',1),/MYSQL_TLS_DNS_REQUIRED/);});
test('exported native readers validate remote TLS policy before opening a socket',async()=>{const {readMysqlMetrics,readRedisMetrics}=await import('../src/database-native-metrics');for(const read of [readMysqlMetrics,readRedisMetrics])await assert.rejects(read({...config,address:'192.0.2.1',tls:false},'never-sent',1));});
