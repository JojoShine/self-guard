import {test} from 'node:test';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {gzipSync} from 'node:zlib';
import {mkdtemp, rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {withRawArchive, currentRawArchive, captureRawChunks, recordSourceManifest} from '../src/intelligence-artifacts';
import {nvdFeedDocument, parseNvdMeta} from '../src/intelligence-nvd-feed';
import {downloadNvdModifiedPart} from '../src/intelligence-nvd-part';
import {readNvdOriginalVersions} from '../src/intelligence-nvd-original';

const feed = {id: 'owned-feed', provider: 'NVD', config: {mode: 'YEAR', year: 2002, syncMode: 'AUTO'}};
function source(scope: 'ANNUAL' | 'MODIFIED' = 'MODIFIED') {
  return async () => {
    const raw = {format: 'NVD_CVE', version: '2.0', timestamp: '2026-10-31T22:00:00', startIndex: 0, resultsPerPage: 2, totalResults: 2, vulnerabilities: [{cve: {id: 'CVE-2001-10001', lastModified: '2026-10-31T22:00:00.123456789'}}, {cve: {id: 'CVE-2026-10001', lastModified: '2026-10-30T22:00:00'}}]}, bytes = Buffer.from(JSON.stringify(raw)), sha256 = createHash('sha256').update(bytes).digest('hex'), original = 'lastModifiedDate:2026-10-31T22:00:00Z\nsize:' + bytes.length + '\ngzSize:' + gzipSync(bytes).length + '\nsha256:' + sha256 + '\n', meta = parseNvdMeta(original);
    recordSourceManifest('nvdMeta', {...meta, original, sha256OfMeta: createHash('sha256').update(original).digest('hex')});
    const stream = {chunks: undefined as any, sourceSha256: '', decodedBytes: 0, abort() {}};
    async function* chunks() { for (let offset = 0; offset < bytes.length; offset += 23) { const part = bytes.subarray(offset, offset + 23); stream.decodedBytes += part.length; yield part; } stream.sourceSha256 = sha256; }
    stream.chunks = captureRawChunks(chunks()); return nvdFeedDocument(meta, stream, scope);
  };
}
test('a downloaded modified part keeps all original bytes and separate publisher proof under the task budget', async () => {
  const root = await mkdtemp(join(tmpdir(), 'selfguard-nvd-part-'));
  try { await withRawArchive(1024 * 1024, async () => {
    const part = await downloadNvdModifiedPart(feed, source());
    assert.equal(part.versions.records.size, 1); assert.equal(part.versions.records.get('CVE-2001-10001'), '2026-10-31T22:00:00.123456789'); assert.equal(part.versions.totalRecords, 2); assert.equal(part.versions.coveredThrough, '2026-10-31T22:00:00Z');
    assert.ok(part.snapshot.artifactSha256); assert.equal(currentRawArchive()?.artifact, undefined); assert.equal(currentRawArchive()?.manifest.nvdMeta, undefined);
    const reread = await readNvdOriginalVersions(part.snapshot, 2002, 'MODIFIED'); assert.deepEqual(reread.records, part.versions.records); assert.deepEqual(reread.digests, part.versions.digests);
  }, {root}); } finally { await rm(root, {recursive: true, force: true}); }
});
test('a modified part cannot be replaced by an annual body or a different provider', async () => {
  const root = await mkdtemp(join(tmpdir(), 'selfguard-wrong-nvd-part-'));
  try { await withRawArchive(1024 * 1024, async () => {
    await assert.rejects(() => downloadNvdModifiedPart(feed, source('ANNUAL')), /修改源/);
    await assert.rejects(() => downloadNvdModifiedPart({...feed, provider: 'OSV'}, source()), /NVD/);
  }, {root}); } finally { await rm(root, {recursive: true, force: true}); }
});
