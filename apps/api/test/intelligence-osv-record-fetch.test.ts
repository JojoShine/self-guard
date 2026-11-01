import {test} from 'node:test';
import assert from 'node:assert/strict';
import {PassThrough} from 'node:stream';
import {EventEmitter} from 'node:events';
import {fetchOsvOfficialRecord} from '../src/intelligence-osv-record-fetch';
import {osvBytesCRC32C} from '../src/intelligence-osv-index';
import {currentRawArchive, withRawArchive} from '../src/intelligence-artifacts';

const document = {id: 'GO-2026-0001', modified: '2026-10-31T12:00:00.123456789Z', affected: [{package: {ecosystem: 'Go', name: 'fixture.test/package'}}]};
function transport(value: unknown = document, headers: Record<string, string> = {}, inspect?: (url: URL, options: any) => void): any {
  const bytes = Buffer.from(JSON.stringify(value));
  return (url: URL, options: any, callback: any) => {
    inspect?.(url, options);
    const request: any = new EventEmitter(); request.destroy = () => request; request.setTimeout = () => request;
    request.end = () => queueMicrotask(() => {
      const response: any = new PassThrough(); response.statusCode = 200;
      response.headers = {'x-goog-generation': '123456789', 'x-goog-hash': 'crc32c=' + osvBytesCRC32C(bytes), 'x-goog-stored-content-length': String(bytes.length), ...headers};
      callback(response); response.end(bytes);
    });
    return request;
  };
}
test('official changed record is bound to exact ecosystem, ID and original nanosecond version', async () => {
  await withRawArchive(1024 * 1024, async () => {
    const result = await fetchOsvOfficialRecord('Go', document.id, document.modified, transport(document, {}, (url, options) => {
      assert.equal(url.href, 'https://storage.googleapis.com/osv-vulnerabilities/Go/GO-2026-0001.json');
      assert.equal(options.rejectUnauthorized, true); assert.equal(options.headers['accept-encoding'], 'identity');
    }));
    assert.deepEqual(result.document, document); assert.deepEqual(result.original, Buffer.from(JSON.stringify(document)));
    assert.equal(result.generation, '123456789'); assert.equal(currentRawArchive()?.artifact, undefined);
  });
});
test('record cannot race its index, change identity, leave ecosystem or lack official integrity proof', async () => {
  for (const raw of [{...document, id: 'GO-2026-0002'}, {...document, modified: '2026-10-31T12:00:00.123456788Z'}, {...document, affected: [{package: {ecosystem: 'npm', name: 'wrong'}}]}]) {
    await assert.rejects(() => fetchOsvOfficialRecord('Go', document.id, document.modified, transport(raw)));
  }
  for (const headers of [{'x-goog-generation': ''}, {'x-goog-hash': ''}, {'x-goog-hash': 'crc32c=AAAAAA=='}, {'x-goog-stored-content-length': '1'}]) {
    await assert.rejects(() => fetchOsvOfficialRecord('Go', document.id, document.modified, transport(document, headers)));
  }
});
test('withdrawn entries can be verified without creating an invented affected scope', async () => {
  const raw = {...document, affected: [], withdrawn: '2026-10-31T12:00:00Z'};
  assert.deepEqual((await fetchOsvOfficialRecord('Go', raw.id, raw.modified, transport(raw))).document, raw);
});
test('invalid ecosystem or identity is rejected before network access', async () => {
  for (const [ecosystem, id] of [['Go/../private', document.id], ['Go', '../secret'], ['Go', 'id?extra=1'], ['Ubuntu:24.04', document.id]]) {
    await assert.rejects(() => fetchOsvOfficialRecord(ecosystem as any, id, document.modified, (() => assert.fail('network reached')) as any));
  }
});
test('official vendor identifiers retain their encoded punctuation without opening arbitrary URLs', async () => {
  const raw = {...document, id: 'RLSA-2026:100+build', affected: [{package: {ecosystem: 'Rocky Linux:9', name: 'kernel'}}]};
  const result = await fetchOsvOfficialRecord('Rocky Linux', raw.id, raw.modified, transport(raw));
  assert.equal(result.sourceUrl, 'https://storage.googleapis.com/osv-vulnerabilities/Rocky%20Linux/RLSA-2026%3A100%2Bbuild.json');
});
