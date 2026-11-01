const {test} = require('node:test');
const assert = require('node:assert/strict');
const {collectPersistentRecords} = require('./waf-persistent-records.cjs');

test('failed loads retain actual database and node evidence without waiting for impossible totals', async () => {
  let reads = 0;
  const actual = {counts: {telemetry: 5, wafEvents: 2, telemetryTypes: {ACCESS: 3, WAF_ATTACK: 2}}, node: {stats: {totalRequests: 3}}, inspectionFailures: [{kind: 'QUEUE_TIMEOUT', count: 1}]};
  const result = await collectPersistentRecords({read: async () => { reads++; return actual; }, expectedAccess: 20, expectedAttacks: 1, processExit: 1, pause: async () => assert.fail('failed load must not wait for unsent requests')});
  assert.equal(reads, 1);
  assert.deepEqual(result, actual);
});
test('successful loads wait for exact durable types and final node counters', async () => {
  const complete = {counts: {telemetry: 21, wafEvents: 1, telemetryTypes: {ACCESS: 20, WAF_ATTACK: 1}}, node: {stats: {totalRequests: 20}}, inspectionFailures: []};
  let reads = 0, pauses = 0;
  const result = await collectPersistentRecords({read: async () => ++reads === 1 ? {...complete, node: {stats: {totalRequests: 19}}} : complete, expectedAccess: 20, expectedAttacks: 1, processExit: 0, pause: async () => { pauses++; }});
  assert.equal(reads, 2); assert.equal(pauses, 1); assert.deepEqual(result, complete);
});
test('failed loads wait for the heartbeat to include actually persisted requests without requiring impossible success counts', async () => {
  let reads=0,pauses=0;
  const complete={counts:{telemetry:21,wafEvents:2,telemetryTypes:{ACCESS:19,WAF_ATTACK:2}},node:{stats:{totalRequests:19}},inspectionFailures:[{kind:'QUEUE_CAPACITY',count:1}]};
  const result=await collectPersistentRecords({read:async()=>++reads===1?{...complete,node:{stats:{totalRequests:17}}}:complete,expectedAccess:20,expectedAttacks:1,processExit:1,pause:async()=>{pauses++}});
  assert.equal(reads,2);assert.equal(pauses,1);assert.deepEqual(result,complete);
});
test('incomplete persistence is returned for a failed assessment instead of discarding evidence', async () => {
  let reads = 0;
  const partial = {counts: {telemetry: 19, wafEvents: 0, telemetryTypes: {ACCESS: 19}}, node: {stats: {totalRequests: 20}}, inspectionFailures: []};
  const result = await collectPersistentRecords({read: async () => { reads++; return partial; }, expectedAccess: 20, expectedAttacks: 1, processExit: 0, attempts: 2, pause: async () => {}});
  assert.equal(reads, 2); assert.deepEqual(result, partial);
});
