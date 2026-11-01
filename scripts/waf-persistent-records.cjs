async function collectPersistentRecords({read, expectedAccess, expectedAttacks, processExit, attempts = 60, pause = () => new Promise(resolve => setTimeout(resolve, 500))}) {
  let actual;
  for (let index = 0; index < attempts; index++) {
    actual = await read();
    const {counts, node} = actual;
    const finalFailedHeartbeat=processExit!==0&&Number.isInteger(counts.telemetryTypes.ACCESS)&&node?.stats?.totalRequests===counts.telemetryTypes.ACCESS;
    if (finalFailedHeartbeat || processExit===0&&counts.telemetry === expectedAccess + expectedAttacks && counts.wafEvents === expectedAttacks && counts.telemetryTypes.ACCESS === expectedAccess && counts.telemetryTypes.WAF_ATTACK === expectedAttacks && node?.stats?.totalRequests === expectedAccess) break;
    if (index + 1 < attempts) await pause();
  }
  return actual;
}

module.exports = {collectPersistentRecords};
