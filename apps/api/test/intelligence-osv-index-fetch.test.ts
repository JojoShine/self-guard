import {test} from 'node:test';
import assert from 'node:assert/strict';
import {PassThrough} from 'node:stream';
import {EventEmitter} from 'node:events';
import {fetchOsvModifiedIndex} from '../src/intelligence-osv-index-fetch';
import {currentRawArchive, withRawArchive} from '../src/intelligence-artifacts';

const body = Buffer.from('2026-10-31T12:00:00.123456789Z,GO-2026-0001\r\n2026-10-31T12:00:00.123456788Z,GO-2026-0002\r\n2026-10-30T12:00:00Z,GHSA-aaaa-bbbb-cccc');
function transport(headers: Record<string, string> = {}, inspect?: (url: URL, options: any) => void): any {
  return (url: URL, options: any, callback: any) => {
    inspect?.(url, options);
    const request: any = new EventEmitter();
    request.destroy = () => request;
    request.setTimeout = () => request;
    request.end = () => queueMicrotask(() => {
      const response: any = new PassThrough();
      response.statusCode = 200;
      response.headers = {'x-goog-generation': '123456789', 'x-goog-hash': 'crc32c=Z+sXrQ==', 'x-goog-stored-content-length': String(body.length), ...headers};
      callback(response);
      response.end(body);
    });
    return request;
  };
}

test('fetches only the selected official index and verifies generation, bytes and CRC', async () => {
  const result = await fetchOsvModifiedIndex('Go', transport({}, (url, options) => {
    assert.equal(url.href, 'https://storage.googleapis.com/osv-vulnerabilities/Go/modified_id.csv');
    assert.equal(options.rejectUnauthorized, true);
    assert.equal(options.headers['accept-encoding'], 'identity');
  }));
  assert.equal(result.records.size, 3);
  assert.equal(result.generation, '123456789');
  assert.equal(result.crc32c, 'Z+sXrQ==');
  assert.deepEqual(result.original, body);
});

test('rejects missing generation, missing checksum, changed checksum and wrong stored size', async () => {
  for (const headers of [
    {'x-goog-generation': ''}, {'x-goog-hash': ''}, {'x-goog-hash': 'crc32c=AAAAAA=='},
    {'x-goog-stored-content-length': String(body.length + 1)}, {'x-goog-stored-content-length': '-1'},
  ]) await assert.rejects(() => fetchOsvModifiedIndex('Go', transport(headers)));
});

test('bounded ecosystem choices cannot be used as network input', async () => {
  for (const value of ['private', 'Go/../../private', 'Go?extra=1', 'Ubuntu:24.04', '[EMPTY]']) {
    await assert.rejects(() => fetchOsvModifiedIndex(value as any, (() => { throw Error('network must not be reached'); }) as any), /生态/);
  }
});

test('keeps index metadata separate from the immutable snapshot payload writer', async () => {
  await withRawArchive(1024 * 1024, async () => {
    const index = await fetchOsvModifiedIndex('Go', transport());
    assert.equal(currentRawArchive()?.artifact, undefined);
    const proof: any = currentRawArchive()?.manifest.osvIndex;
    assert.equal(proof.sourceSha256, index.sourceSha256);
    assert.equal(proof.records, 3);
    assert.equal(proof.crc32c, 'Z+sXrQ==');
  });
});
