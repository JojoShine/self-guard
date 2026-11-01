import {test} from 'node:test';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {intelligenceRecordFingerprint, intelligenceSnapshotFingerprint} from '../src/intelligence-fingerprint';

const record: any = {externalId: 'GO-1', modifiedAt: '2026-10-31T00:00:00.123456789Z', metadata: {b: 2, a: 1}, aliases: ['GO-1', 'CVE-2026-12345'], rawSha256: 'a'.repeat(64)};
test('record facts retain the existing canonical digest contract and original time precision', () => {
  const expected = createHash('sha256').update('{"aliases":["GO-1","CVE-2026-12345"],"externalId":"GO-1","metadata":{"a":1,"b":2},"modifiedAt":"2026-10-31T00:00:00.123456789Z"}').digest('hex');
  assert.equal(intelligenceRecordFingerprint(record), expected);
  assert.equal(intelligenceRecordFingerprint({...record, metadata: {a: 1, b: 2}, rawSha256: 'b'.repeat(64)}), expected);
  assert.notEqual(intelligenceRecordFingerprint({...record, modifiedAt: '2026-10-31T00:00:00.123456788Z'}), expected);
  assert.notEqual(intelligenceRecordFingerprint({...record, aliases: ['CVE-2026-12345', 'GO-1']}), expected);
});

test('snapshot digest uses the existing sorted fingerprint protocol without mutating input', () => {
  const hashes = ['b'.repeat(64), 'a'.repeat(64)], original = hashes.slice();
  assert.equal(intelligenceSnapshotFingerprint(hashes), createHash('sha256').update(hashes.slice().sort().join('\n')).digest('hex'));
  assert.deepEqual(hashes, original);
  for (const input of [[], ['missing'], ['a'.repeat(64), null]]) assert.throws(() => intelligenceSnapshotFingerprint(input as any));
});
