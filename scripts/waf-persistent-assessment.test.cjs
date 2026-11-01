const {test} = require('node:test');
const assert = require('node:assert/strict');
const {assessPersistentLoad} = require('./waf-persistent-assessment.cjs');

// Synthetic data exercises the acceptance classifier, not a runtime claim.
const samples = Array.from({length: 180000}, (_, index) => ({index, attack: index % 20 === 0, status: index % 20 === 0 ? 403 : 200, baselineStatus: 200, wafMs: 10, baselineMs: 2, addedMs: 8, dispatchDelayMs: 0}));
const at = index => new Date(Date.UTC(2026, 10, 1) + index * 1000).toISOString();
const memory = Array.from({length: 1801}, (_, index) => ({at: at(index), elapsedSeconds: index, rssBytes: 100 << 20, processes: 4, pendingAccess: 24, pendingEvents: 1}));
const fixture = {
  report: {requests: 180000, durationSeconds: 1800, elapsedSeconds: 1800, errors: 0, bodyBytes: 4096, normalPercent: 95, attackPercent: 5, warmupRequests: 20, warmupAttacks: 1, expectedAttacks: 9001, engineSha256: 'a'.repeat(64), samples, memoryAndQueues: memory,
    drain: {at: at(1801), pendingAccess: 0, pendingEvents: 0, elapsedSeconds: 1}},
  counts: {telemetry: 189021, wafEvents: 9001, telemetryTypes: {ACCESS: 180020, WAF_ATTACK: 9001}},
  node: {droppedEvents: 0, stats: {totalRequests: 180020, blockedRequests: 9001, accessLogDropped: 0, upstreamErrors: 0}},
  resources: {cpus: 4, memoryKiB: 8130404, persistentDisk: 'ext2/ext3'}, processExit: 0,
};
test('only complete reference evidence can satisfy the performance gate', () => {
  const result = assessPersistentLoad(fixture);
  assert.equal(result.passed, true, JSON.stringify(result));
  assert.equal(result.measuredAddedP95Ms, 8);
});
test('short tests and shared environments cannot become full acceptance', () => {
  assert.equal(assessPersistentLoad({...fixture, report: {...fixture.report, durationSeconds: 60}}).passed, false);
  for (const resources of [undefined, {...fixture.resources, cpus: 2}, {...fixture.resources, persistentDisk: 'tmpfs'}]) {
    assert.equal(assessPersistentLoad({...fixture, resources}).passed, false);
  }
});
test('valid short diagnostics keep their actual latency and count results', () => {
  const result = assessPersistentLoad({...fixture,
    report: {...fixture.report, requests: 6000, durationSeconds: 60, elapsedSeconds: 60, expectedAttacks: 301, samples: samples.slice(0, 6000), memoryAndQueues: memory.slice(0, 61)},
    counts: {telemetry: 6321, wafEvents: 301, telemetryTypes: {ACCESS: 6020, WAF_ATTACK: 301}},
    node: {...fixture.node, stats: {...fixture.node.stats, totalRequests: 6020, blockedRequests: 301}},
  });
  assert.equal(result.passed, false);
  assert.equal(result.measuredAddedP95Ms, 8);
  assert.deepEqual(result.reasons, ['REFERENCE_WORKLOAD_INCOMPLETE', 'SUSTAINED_PARENT_AND_WORKER_MEMORY_NOT_VERIFIED', 'SUSTAINED_MEMORY_GROWTH_NOT_VERIFIED']);
});
test('recomputes classifications and latency from actual samples', () => {
  const bad = samples.slice();
  bad[1] = {...bad[1], status: 403};
  assert.equal(assessPersistentLoad({...fixture, report: {...fixture.report, samples: bad}}).passed, false);
  assert.equal(assessPersistentLoad({...fixture, report: {...fixture.report, samples: samples.slice(1)}}).passed, false);
  assert.equal(assessPersistentLoad({...fixture, report: {...fixture.report, samples: samples.map(row => ({...row, wafMs: 25, addedMs: 23}))}}).passed, false);
});
test('requires exact database types and independently drained queues', () => {
  assert.equal(assessPersistentLoad({...fixture, counts: {...fixture.counts, telemetryTypes: {ACCESS: 180020}}}).passed, false);
  for (const drain of [undefined, {...fixture.report.drain, pendingAccess: 1}, {...fixture.report.drain, pendingEvents: 1}, {...fixture.report.drain, error: 'UNREADABLE'}]) {
    assert.equal(assessPersistentLoad({...fixture, report: {...fixture.report, drain}}).passed, false);
  }
});
test('requires sustained measured memory including worker processes', () => {
  const rising = memory.map((row, index) => ({...row, rssBytes: index < 900 ? 100 << 20 : 200 << 20}));
  const missing = memory.map((row, index) => index === 900 ? {...row, error: 'RSS_UNAVAILABLE'} : row);
  for (const memoryAndQueues of [memory.slice(0, 50), rising, missing, memory.map(row => ({...row, processes: 1}))]) {
    assert.equal(assessPersistentLoad({...fixture, report: {...fixture.report, memoryAndQueues}}).passed, false);
  }
});
test('never accepts a failed process or dropped data', () => {
  assert.equal(assessPersistentLoad({...fixture, processExit: 1}).passed, false);
  assert.equal(assessPersistentLoad({...fixture, node: {...fixture.node, droppedEvents: 1}}).passed, false);
});
test('wall clock correction cannot shorten or reorder real sustained-memory observation', () => {
  const adjusted = memory.map((row, index) => ({...row, at: new Date(Date.parse(row.at) - (index > 900 ? 15000 : 0)).toISOString()}));
  assert.equal(assessPersistentLoad({...fixture, report: {...fixture.report, memoryAndQueues: adjusted}}).passed, true);
});
test('elapsed sample time must be observed rather than inferred from row number or wall timestamps', () => {
  const missing = memory.map(({elapsedSeconds, ...row}) => row);
  const jump = memory.map((row, index) => index === 900 ? {...row, elapsedSeconds: row.elapsedSeconds - 5} : row);
  for (const memoryAndQueues of [missing, jump]) assert.equal(assessPersistentLoad({...fixture, report: {...fixture.report, memoryAndQueues}}).passed, false);
});
