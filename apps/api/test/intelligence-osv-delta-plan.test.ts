import {test} from 'node:test';
import assert from 'node:assert/strict';
import {readOsvModifiedIndex} from '../src/intelligence-osv-index';
import {planOsvDelta} from '../src/intelligence-osv-delta-plan';

async function index(rows: string[]) {
  async function* bytes() { yield Buffer.from(rows.join('\n') + '\n'); }
  return readOsvModifiedIndex(bytes());
}

test('detects one-nanosecond changes, new identities and unchanged records', async () => {
  const current = await index(['2026-10-31T00:00:00.123456789Z,GO-1', '2026-10-31T00:00:00Z,GO-2', '2026-10-30T00:00:00Z,GO-3']);
  const baseline = new Map([['GO-1', '2026-10-31T00:00:00.123456788Z'], ['GO-3', '2026-10-30T00:00:00.000000000Z']]);
  const result = planOsvDelta(baseline, current);
  assert.equal(result.mode, 'DELTA');
  if (result.mode !== 'DELTA') throw Error('expected delta');
  assert.deepEqual(result.added, ['GO-2']);
  assert.deepEqual(result.updated, ['GO-1']);
  assert.equal(result.unchangedRecords, 1);
});

test('only an equivalent complete identity set can be unchanged', async () => {
  const current = await index(['2026-10-31T00:00:00Z,GO-1']);
  assert.equal(planOsvDelta(new Map([['GO-1', '2026-10-31T00:00:00.000Z']]), current).mode, 'UNCHANGED');
  const missing = planOsvDelta(new Map([['GO-1', '2026-10-31T00:00:00Z'], ['GO-2', '2026-10-30T00:00:00Z']]), current);
  assert.equal(missing.mode, 'FULL');
  if (missing.mode === 'FULL') assert.equal(missing.reason, 'INDEX_REMOVED_IDENTITIES');
});

test('original ISO offsets compare at the same nanosecond without rewriting the original value', async () => {
  const current = await index(['2026-10-31T00:00:00.000000001Z,GO-1']);
  assert.equal(planOsvDelta(new Map([['GO-1', '2026-10-31T01:00:00.000000001+01:00']]), current).mode, 'UNCHANGED');
  const newer = planOsvDelta(new Map([['GO-1', '2026-10-31T01:00:00.000000002+01:00']]), current);
  assert.equal(newer.mode, 'FULL');
  if (newer.mode === 'FULL') assert.equal(newer.reason, 'INDEX_OLDER_THAN_BASELINE');
});

test('missing baseline, uncertain original times and older index require complete refresh', async () => {
  const current = await index(['2026-10-31T00:00:00Z,GO-1']);
  assert.equal(planOsvDelta(null, current).mode, 'FULL');
  const cases = [
    {old: 'not-an-original-timestamp', reason: 'BASELINE_TIMESTAMP_UNSUPPORTED'},
    {old: '2026-10-31T00:00:00.000000001Z', reason: 'INDEX_OLDER_THAN_BASELINE'},
  ];
  for (const value of cases) {
    const result = planOsvDelta(new Map([['GO-1', value.old]]), current);
    assert.equal(result.mode, 'FULL');
    if (result.mode === 'FULL') assert.equal(result.reason, value.reason);
  }
});

test('large change batches fall back to full import without a partial delta plan', async () => {
  const current = await index(Array.from({length: 501}, (_, id) => '2026-10-31T00:00:00Z,GO-' + id));
  const result = planOsvDelta(new Map([['GO-0', '2026-10-30T00:00:00Z']]), current);
  assert.equal(result.mode, 'FULL');
  if (result.mode === 'FULL') assert.equal(result.reason, 'CHANGE_BATCH_EXCEEDS_BUDGET');
  assert.equal('updated' in result, false);
});
