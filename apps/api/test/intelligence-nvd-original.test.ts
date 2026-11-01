import {test} from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp, rm, readFile, writeFile} from 'node:fs/promises';
import {join} from 'node:path';
import {tmpdir} from 'node:os';
import {createHash} from 'node:crypto';
import {gzipSync} from 'node:zlib';
import {withRawArchive, captureRawBuffer, currentRawArchive, artifactPath, recordSourceManifest} from '../src/intelligence-artifacts';
import {readNvdOriginalVersions, nvdCoveredThrough} from '../src/intelligence-nvd-original';

const sha = (bytes: Buffer) => createHash('sha256').update(bytes).digest('hex');
async function fixture(work: (snapshot: any, file: string) => Promise<void>) {
  const root = await mkdtemp(join(tmpdir(), 'selfguard-nvd-original-'));
  try { await withRawArchive(1024 * 1024, async () => {
    const raw = {format: 'NVD_CVE', version: '2.0', timestamp: '2026-10-31T20:00:08.043', startIndex: 0, resultsPerPage: 2, totalResults: 2, vulnerabilities: [{cve: {id: 'CVE-2026-10001', lastModified: '2026-10-31T20:00:00.123456789'}}, {cve: {id: 'CVE-2001-10001', lastModified: '2026-10-30T20:00:00'}}]}, bytes = Buffer.from(JSON.stringify(raw)), zipped = gzipSync(bytes), original = 'lastModifiedDate:2026-10-31T16:00:08-04:00\nsize:' + bytes.length + '\ngzSize:' + zipped.length + '\nsha256:' + sha(bytes) + '\n';
    await captureRawBuffer(bytes); const artifact = currentRawArchive()!.artifact!;
    const snapshot = {sourceUrl: 'https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-modified.json.gz', sourceSha256: sha(bytes), artifactSha256: artifact.sha256, artifact, recordCount: 999, sourceManifest: {nvdMeta: {original, sha256OfMeta: sha(Buffer.from(original))}, nvdFeed: {scope: 'MODIFIED', generatedAt: raw.timestamp, records: 2}}};
    recordSourceManifest('nvdFeed', {scope: 'CURRENT_DOWNLOAD'});
    await work(snapshot, artifactPath(root, artifact.sha256));
  }, {root}); } finally { await rm(root, {recursive: true, force: true}); }
}
test('verified NVD originals retain exact source times and filter selected CVE years without changing live download metadata', async () => {
  await fixture(async snapshot => {
    const current = currentRawArchive()!.manifest.nvdFeed;
    const result = await readNvdOriginalVersions(snapshot, 2026, 'MODIFIED');
    assert.equal(result.records.size, 1); assert.equal(result.records.get('CVE-2026-10001'), '2026-10-31T20:00:00.123456789'); assert.equal(result.coveredThrough, '2026-10-31T16:00:08-04:00'); assert.equal(result.totalRecords, 2);
    assert.deepEqual(currentRawArchive()!.manifest.nvdFeed, current);
    const older = await readNvdOriginalVersions(snapshot, 2002, 'MODIFIED'); assert.equal(older.records.size, 1); assert.ok(older.records.has('CVE-2001-10001'));
  });
});
test('NVD original version reads reject missing publisher proof, source changes and damaged retained files', async () => {
  await fixture(async (snapshot, file) => {
    for (const changed of [{sourceSha256: 'f'.repeat(64)}, {sourceUrl: 'https://unrelated.test/file'}, {sourceManifest: {...snapshot.sourceManifest, nvdMeta: {original: snapshot.sourceManifest.nvdMeta.original, sha256OfMeta: 'f'.repeat(64)}}}]) await assert.rejects(() => readNvdOriginalVersions({...snapshot, ...changed}, 2026, 'MODIFIED'));
    await assert.rejects(() => readNvdOriginalVersions(snapshot, 2026, 'ANNUAL'));
    const bytes = await readFile(file); bytes[bytes.length - 5] ^= 1; await writeFile(file, bytes);
    await assert.rejects(() => readNvdOriginalVersions(snapshot, 2026, 'MODIFIED'));
  });
});
test('window anchor uses the official META timezone rather than guessing the timezone-free body generation time', () => {
  assert.equal(nvdCoveredThrough({lastModifiedDate: '2026-10-31T18:00:07-04:00'}, '2026-10-31T18:00:03.4269196'), '2026-10-31T18:00:07-04:00');
  assert.throws(() => nvdCoveredThrough({lastModifiedDate: '2026-10-31T18:00:07'}, '2026-10-31T18:00:03'), /时区/);
});
