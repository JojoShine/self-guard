import {test} from 'node:test';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {readOsvModifiedIndex} from '../src/intelligence-osv-index';

async function* chunks(value: string | Buffer, size = 7) {
  const bytes = Buffer.isBuffer(value) ? value : Buffer.from(value);
  for (let offset = 0; offset < bytes.length; offset += size) yield bytes.subarray(offset, offset + size);
}

test('reads the official date,id order across byte boundaries without losing timestamp precision', async () => {
  const raw = '2026-10-31T12:00:00.123456789Z,GO-2026-0001\r\n2026-10-31T12:00:00.123456788Z,GO-2026-0002\r\n2026-10-30T12:00:00Z,GHSA-aaaa-bbbb-cccc';
  const result = await readOsvModifiedIndex(chunks(raw, 1));
  assert.equal(result.records.size, 3);
  assert.equal(result.records.get('GO-2026-0001')?.modifiedAt, '2026-10-31T12:00:00.123456789Z');
  assert.equal(result.records.get('GO-2026-0001')!.modifiedNanoseconds - result.records.get('GO-2026-0002')!.modifiedNanoseconds, 1n);
  assert.equal(result.sourceSha256, createHash('sha256').update(raw).digest('hex'));
  assert.equal(result.bytes, Buffer.byteLength(raw));
  assert.equal(result.crc32c, 'Z+sXrQ==');
  assert.equal(result.descending, true);
});

test('reads the entire index even when timestamps have equal or unexpected ordering', async () => {
  const result = await readOsvModifiedIndex(chunks('2026-10-30T00:00:00Z,1\n2026-10-31T00:00:00Z,2\n2026-10-31T00:00:00Z,3\n'));
  assert.equal(result.records.size, 3);
  assert.equal(result.descending, false);
});

test('rejects duplicate identity, malformed dates, path injection and incomplete UTF-8', async () => {
  for (const raw of [
    '2026-10-31T00:00:00Z,id\n2026-10-30T00:00:00Z,id\n',
    '2026-02-30T00:00:00Z,id\n', '2026-10-31T00:00:60Z,id\n',
    '2026-10-31T00:00:00Z,../private\n', '2026-10-31T00:00:00Z,Go/id\n',
    '2026-10-31T00:00:00Z,id,extra\n', '2026-10-31T00:00:00Z, id\n',
    '2026-10-31T00:00:00Z,id\n\n2026-10-30T00:00:00Z,other\n',
    'id,2026-10-31T00:00:00Z\n', '',
    Buffer.from([0x32, 0x30, 0xc3]),
  ]) await assert.rejects(() => readOsvModifiedIndex(chunks(raw)));
});

test('does not return a usable index after a transport failure', async () => {
  async function* broken() { yield Buffer.from('2026-10-31T00:00:00Z,id\n'); throw Error('fixture transport cut'); }
  await assert.rejects(() => readOsvModifiedIndex(broken()), /transport cut/);
});

test('rejects oversized lines before accumulating an unbounded buffer', async () => {
  await assert.rejects(() => readOsvModifiedIndex(chunks('2026-10-31T00:00:00Z,' + 'a'.repeat(4096), 19)), /行|编号/);
});
