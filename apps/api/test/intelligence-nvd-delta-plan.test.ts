import {test} from 'node:test';
import assert from 'node:assert/strict';
import {mergeNvdVersionSets, planNvdIncrement, assertNvdModifiedWindow, type NvdVersionSet} from '../src/intelligence-nvd-delta-plan';

test('expired modified feed cannot stand in for the current eight-day window', () => {
  const now = new Date('2026-11-01T00:00:00Z');
  assert.doesNotThrow(() => assertNvdModifiedWindow('2026-10-31T18:00:07-04:00', now));
  assert.throws(() => assertNvdModifiedWindow('2026-10-23T18:00:07-04:00', now), /8天|过期/);
});

const sha = (letter: string) => letter.repeat(64);
const versions = (coveredThrough: string, values: [string, string, string][]): NvdVersionSet => ({coveredThrough, records: new Map(values.map(([id, time]) => [id, time])), digests: new Map(values.map(([id, , digest]) => [id, digest]))});
const root = versions('2026-10-30T00:00:00Z', [['CVE-2026-10001', '2026-10-20T00:00:00', sha('a')], ['CVE-2026-10002', '2026-10-29T00:00:00', sha('b')]]);
test('full plus modified versions keep the newest original and preserve equal-time corrections', () => {
  const changed = versions('2026-10-31T00:00:00Z', [['CVE-2026-10001', '2026-10-31T00:00:00.123456789', sha('c')], ['CVE-2026-10002', '2026-10-28T00:00:00', sha('d')], ['CVE-2001-10003', '2026-10-21T00:00:00', sha('e')]]);
  const merged = mergeNvdVersionSets(root, changed);
  assert.equal(merged.records.size, 3); assert.equal(merged.records.get('CVE-2026-10001'), '2026-10-31T00:00:00.123456789'); assert.equal(merged.digests.get('CVE-2026-10002'), sha('b')); assert.equal(merged.added, 1); assert.equal(merged.updated, 1); assert.equal(merged.ignoredOlder, 1); assert.equal(root.records.size, 2);
  const sameTime = mergeNvdVersionSets(root, versions('2026-10-31T00:00:00Z', [['CVE-2026-10001', '2026-10-20T00:00:00', sha('f')]])); assert.equal(sameTime.updated, 1); assert.equal(sameTime.digests.get('CVE-2026-10001'), sha('f'));
});
test('incremental coverage uses verified publisher time rather than local sync completion', () => {
  const changed = versions('2026-10-31T00:00:00Z', [['CVE-2026-10001', '2026-10-31T00:00:00', sha('c')]]);
  assert.equal(planNvdIncrement(root, root, changed, new Date('2026-10-31T00:00:00Z')).mode, 'DELTA');
  const old = {...root, coveredThrough: '2026-10-21T00:00:00Z'};
  const result = planNvdIncrement(old, old, changed, new Date('2026-10-31T00:00:00Z')); assert.equal(result.mode, 'REBASE'); assert.equal(result.reason, 'COVERAGE_WINDOW_WILL_EXPIRE');
});
test('a disappeared prior update requires a complete rebase and is never silently deleted', () => {
  const accepted = {...mergeNvdVersionSets(root, versions('2026-10-31T00:00:00Z', [['CVE-2026-10001', '2026-10-31T00:00:00', sha('c')]])), coveredThrough: '2026-10-31T00:00:00Z'};
  const result = planNvdIncrement(root, accepted, versions('2026-10-31T02:00:00Z', []), new Date('2026-10-31T02:00:00Z')); assert.equal(result.mode, 'REBASE'); assert.equal(result.reason, 'PREVIOUS_UPDATE_NO_LONGER_IN_MODIFIED_SOURCE');
});
test('older source generations and regressed accepted updates are rejected', () => {
  const accepted = {...mergeNvdVersionSets(root, versions('2026-10-31T00:00:00Z', [['CVE-2026-10001', '2026-10-31T00:00:00', sha('c')]])), coveredThrough: '2026-10-31T00:00:00Z'};
  const old = planNvdIncrement(root, accepted, versions('2026-10-30T00:00:00Z', []), new Date('2026-10-31T00:00:00Z')); assert.equal(old.mode, 'REJECT'); assert.equal(old.reason, 'OLDER_MODIFIED_SOURCE');
  const regressed = planNvdIncrement(root, accepted, versions('2026-10-31T02:00:00Z', [['CVE-2026-10001', '2026-10-30T00:00:00', sha('d')]]), new Date('2026-10-31T02:00:00Z')); assert.equal(regressed.mode, 'REJECT'); assert.equal(regressed.reason, 'ACCEPTED_RECORD_VERSION_WENT_BACK');
});
test('all copied version identities need an exact record fingerprint', () => {
  assert.throws(() => mergeNvdVersionSets({...root, digests: new Map()}, root), /指纹/);
});
