const percentile = (values, percent) => values.length ? values.slice().sort((a, b) => a - b)[Math.floor((values.length - 1) * percent / 100)] : null;

function assessPersistentLoad({report, counts, node, resources, processExit}) {
  const reasons = [];
  const check = (condition, reason) => { if (!condition) reasons.push(reason); };
  check(processExit === 0, 'LOAD_PROCESS_FAILED');
  check(report.durationSeconds === 1800 && report.requests === 180000 && report.bodyBytes === 4096 && report.normalPercent === 95 && report.attackPercent === 5, 'REFERENCE_WORKLOAD_INCOMPLETE');
  check(Number.isFinite(report.elapsedSeconds) && report.elapsedSeconds >= report.durationSeconds - 1 && report.requests / report.elapsedSeconds >= 99, 'SUSTAINED_RATE_NOT_REACHED');
  check(resources?.cpus === 4 && resources.memoryKiB >= 7.5 * 1024 ** 2 && resources.memoryKiB <= 8.5 * 1024 ** 2 && ['ext2/ext3', 'ext4', 'xfs', 'btrfs'].includes(resources.persistentDisk), 'REFERENCE_RESOURCES_NOT_VERIFIED');
  check(/^[a-f0-9]{64}$/.test(report.engineSha256 || ''), 'ENGINE_DIGEST_MISSING');
  const samples = Array.isArray(report.samples) ? report.samples : [];
  const valid = Number.isInteger(report.requests) && report.requests > 0 && report.requests <= 180000 && samples.length === report.requests && samples.every((row, index) => row.index === index && row.attack === (index % 20 === 0) && row.status === (row.attack ? 403 : 200) && row.baselineStatus === 200 && !row.failure && [row.wafMs, row.baselineMs, row.addedMs, row.dispatchDelayMs].every(Number.isFinite) && row.wafMs >= 0 && row.baselineMs >= 0 && Math.abs(row.addedMs - (row.wafMs - row.baselineMs)) < 0.000001);
  check(valid && report.errors === 0, 'REQUEST_RESULTS_INCOMPLETE_OR_INCORRECT');
  const measuredAddedP95Ms = valid ? percentile(samples.map(row => row.wafMs - row.baselineMs), 95) : null;
  check(measuredAddedP95Ms !== null && measuredAddedP95Ms <= 20, 'ADDED_P95_NOT_VERIFIED_WITHIN_20MS');
  const expectedAccess = report.requests + 20, expectedAttacks = Math.ceil(report.requests / 20) + 1;
  check(report.warmupRequests === 20 && report.warmupAttacks === 1 && report.expectedAttacks === expectedAttacks && counts?.telemetry === expectedAccess + expectedAttacks && counts.wafEvents === expectedAttacks && counts.telemetryTypes?.ACCESS === expectedAccess && counts.telemetryTypes?.WAF_ATTACK === expectedAttacks, 'PERSISTED_COUNTS_INCOMPLETE');
  check(node?.droppedEvents === 0 && node.stats?.accessLogDropped === 0 && node.stats?.upstreamErrors === 0 && node.stats?.totalRequests === expectedAccess && node.stats?.blockedRequests === expectedAttacks, 'NODE_COUNTERS_INCOMPLETE_OR_DROPPED');
  const drain = report.drain;
  check(drain && !drain.error && drain.pendingAccess === 0 && drain.pendingEvents === 0 && Number.isFinite(drain.elapsedSeconds) && drain.elapsedSeconds <= 30 && Number.isFinite(Date.parse(drain.at)), 'DISK_QUEUES_NOT_DRAINED');
  const memory = Array.isArray(report.memoryAndQueues) ? report.memoryAndQueues : [];
  const times = memory.map(row => row.elapsedSeconds * 1000);
  const sampled = memory.length >= 1710 && memory.every((row, index) => !row.error && Number.isFinite(Date.parse(row.at)) && Number.isFinite(times[index]) && times[index] >= 0 && row.rssBytes > 0 && row.rssBytes <= 1024 ** 3 && Number.isInteger(row.processes) && row.processes >= 1 && row.processes <= 5 && Number.isInteger(row.pendingAccess) && row.pendingAccess >= 0 && Number.isInteger(row.pendingEvents) && row.pendingEvents >= 0 && (index === 0 || times[index] >= times[index - 1] && times[index] - times[index - 1] <= 3000)) && times.at(-1) - times[0] >= 1790000 && memory.some(row => row.processes >= 2);
  check(sampled, 'SUSTAINED_PARENT_AND_WORKER_MEMORY_NOT_VERIFIED');
  let earlyMemoryP95Bytes = null, lateMemoryP95Bytes = null;
  if (sampled) {
    // Compare five-minute windows after initial warmup and at the end. Keep
    // GC/recycling variation explicit instead of requiring monotonic RSS.
    earlyMemoryP95Bytes = percentile(memory.filter((row, index) => times[index] >= times[0] + 60000 && times[index] <= times[0] + 360000).map(row => row.rssBytes), 95);
    lateMemoryP95Bytes = percentile(memory.filter((row, index) => times[index] >= times.at(-1) - 300000).map(row => row.rssBytes), 95);
  }
  check(earlyMemoryP95Bytes !== null && lateMemoryP95Bytes !== null && lateMemoryP95Bytes <= earlyMemoryP95Bytes + Math.max(32 * 1024 ** 2, earlyMemoryP95Bytes * 0.2), sampled ? 'SUSTAINED_MEMORY_GROWTH' : 'SUSTAINED_MEMORY_GROWTH_NOT_VERIFIED');
  return {passed: reasons.length === 0, memoryClock: 'MONOTONIC_ELAPSED', reasons, measuredAddedP95Ms, earlyMemoryP95Bytes, lateMemoryP95Bytes, scope: 'W11 persistent reference performance only; rule compatibility and failure-recovery gates remain independent'};
}

module.exports = {assessPersistentLoad};
