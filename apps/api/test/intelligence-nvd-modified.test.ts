import {test} from 'node:test';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {gzipSync} from 'node:zlib';
import {EventEmitter} from 'node:events';
import {PassThrough} from 'node:stream';
import {mkdtemp, rm} from 'node:fs/promises';
import {join} from 'node:path';
import {tmpdir} from 'node:os';
import {fetchNvdModifiedFeed, nvdFeedDocument, nvdTimeNanoseconds} from '../src/intelligence-nvd-feed';
import {stageNvdAnnualSnapshot} from '../src/intelligence-nvd-stage';
import {withRawArchive, currentRawArchive} from '../src/intelligence-artifacts';

const cve = (id: string) => ({cve: {id, lastModified: '2026-10-31T20:00:00.123', descriptions: [{lang: 'en', value: 'Actual owned source fixture'}]}});
const document = {format: 'NVD_CVE', version: '2.0', timestamp: '2026-10-31T20:00:08.043', startIndex: 0, resultsPerPage: 2, totalResults: 2, vulnerabilities: [cve('CVE-2001-10001'), cve('CVE-2026-10001')]};
function transport(value: unknown = document, badSha = false, inspect?: (url: URL, options: any) => void): any {
  const bytes = Buffer.from(JSON.stringify(value)), zipped = gzipSync(bytes), sha256 = createHash('sha256').update(bytes).digest('hex'), meta = Buffer.from('lastModifiedDate:2026-10-31T16:00:08-04:00\nsize:' + bytes.length + '\ngzSize:' + zipped.length + '\nsha256:' + (badSha ? 'f'.repeat(64) : sha256) + '\n');
  return (url: URL, options: any, callback: any) => {
    inspect?.(url, options); const request: any = new EventEmitter(); request.destroy = () => request; request.setTimeout = () => request;
    request.end = () => queueMicrotask(() => { const response: any = new PassThrough(); response.statusCode = 200; response.headers = {}; callback(response); response.end(url.pathname.endsWith('.meta') ? meta : zipped); });
    return request;
  };
}
test('fixed official modified source verifies its full body and preserves exact generation metadata', async () => {
  const root = await mkdtemp(join(tmpdir(), 'selfguard-nvd-modified-')), urls: string[] = [];
  try { await withRawArchive(1024 * 1024, async () => {
    const fetched = await fetchNvdModifiedFeed(transport(document, false, (url, options) => { urls.push(url.href); assert.equal(options.rejectUnauthorized, true); }));
    assert.equal(fetched.document.scope, 'MODIFIED'); const records = []; for await (const row of fetched.document.entries) records.push(row);
    fetched.document.validate(); assert.equal(records.length, 2); assert.ok(currentRawArchive()?.artifact); assert.equal(fetched.sourceSha256, createHash('sha256').update(JSON.stringify(document)).digest('hex'));
    assert.deepEqual(currentRawArchive()?.manifest.nvdFeed, {scope: 'MODIFIED', generatedAt: document.timestamp, records: 2});
    assert.deepEqual(urls, ['https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-modified.meta', 'https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-modified.json.gz']);
  }, {root}); } finally { await rm(root, {recursive: true, force: true}); }
});
test('modified source cannot pass with mismatched official hash, duplicate IDs or incomplete metadata', async () => {
  for (const [raw, badSha] of [[document, true], [{...document, vulnerabilities: [cve('CVE-2026-10001'), cve('CVE-2026-10001')]}, false], [{...document, totalResults: 3}, false]] as const) {
    await assert.rejects(async () => { const fetched = await fetchNvdModifiedFeed(transport(raw, badSha)); try { for await (const _ of fetched.document.entries) {} fetched.document.validate(); } finally { fetched.document.abort(); } });
  }
});
test('NVD timezone-free timestamps are UTC and retain submillisecond precision', () => {
  assert.equal(nvdTimeNanoseconds('2026-10-31T20:00:00.123456789'), nvdTimeNanoseconds('2026-10-31T16:00:00.123456789-04:00'));
  for (const time of ['2026-02-31T00:00:00', 'Oct 31 2026', '2026-10-31T00:00:00.1234567890']) assert.throws(() => nvdTimeNanoseconds(time));
});
test('annual staging rejects a modified stream and verifies CVE year membership including pre-2002', async () => {
  const staged: any[] = [], db: any = {$transaction: async (work: any) => work({vulnerabilityFeed: {updateMany: async () => ({count: 1})}, vulnerabilityRecord: {createMany: async (input: any) => staged.push(...input.data)}, vulnerabilitySnapshot: {update: async () => {}}})};
  function source(ids: string[], scope = 'ANNUAL') { return {sourceSha256: 'a'.repeat(64), document: {kind: 'NVD_FEED_STREAM', scope, meta: {lastModifiedDate: '2026-10-31T20:00:00Z'}, entries: (async function*() { for (const id of ids) yield cve(id); })(), validate() {}, abort() {}}}; }
  await assert.rejects(() => stageNvdAnnualSnapshot(db, {id: 'feed', config: {year: 2026}}, 'snapshot', 'lease', source(['CVE-2025-10001'])), /年份|年度/); assert.equal(staged.length, 0);
  await assert.rejects(() => stageNvdAnnualSnapshot(db, {id: 'feed', config: {year: 2026}}, 'snapshot', 'lease', source(['CVE-2026-10001'], 'MODIFIED')), /年度/);
  const valid = await stageNvdAnnualSnapshot(db, {id: 'feed', config: {year: 2002}}, 'snapshot', 'lease', source(['CVE-1999-10001', 'CVE-2002-10001'])); assert.equal(valid.recordCount, 2);
});
