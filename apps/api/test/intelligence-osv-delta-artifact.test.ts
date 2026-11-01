import {test} from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp, readFile, rm, writeFile} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {createHash} from 'node:crypto';
import {gzipSync, gunzipSync} from 'node:zlib';
import {withRawArchive, currentRawArchive, artifactPath} from '../src/intelligence-artifacts';
import {readOsvModifiedIndex} from '../src/intelligence-osv-index';
import {captureOsvDeltaPackage, readOsvDeltaIndex} from '../src/intelligence-osv-delta-artifact';

const sha = (bytes: Buffer) => createHash('sha256').update(bytes).digest('hex');
const rootId = '00000000-0000-4000-8000-000000000001', rootSha = 'a'.repeat(64);
async function index() {
  const original = Buffer.from('2026-10-31T00:00:00.123456789Z,GO-2026-0001\n');
  return {...await readOsvModifiedIndex((async function*() { yield original; })()), original, generation: '12345', sourceUrl: 'https://storage.googleapis.com/osv-vulnerabilities/Go/modified_id.csv'};
}
test('delta receipt keeps exact index bytes and identifies its complete root package', async () => {
  const root = await mkdtemp(join(tmpdir(), 'selfguard-delta-originals-'));
  try {
    await withRawArchive(1024 * 1024, async () => {
      const fixed = await index(), payload = await captureOsvDeltaPackage({ecosystem: 'Go', release: null, baseSnapshotId: rootId, baseArtifactSha256: rootSha, baseContentSha256: 'b'.repeat(64), index: fixed, records: []});
      const artifact = currentRawArchive()!.artifact!, file = artifactPath(root, artifact.sha256);
      const decoded = JSON.parse(gunzipSync(await readFile(file)).toString());
      assert.equal(decoded.format, 'selfguard-osv-delta-v1'); assert.deepEqual(Buffer.from(decoded.index.originalBase64, 'base64'), fixed.original);
      const result = await readOsvDeltaIndex(file, {...artifact, sourceSha256: payload.sourceSha256}, {ecosystem: 'Go', release: null, baseSnapshotId: rootId, baseArtifactSha256: rootSha, baseContentSha256: 'b'.repeat(64)});
      assert.equal(result.records.get('GO-2026-0001')?.modifiedAt, '2026-10-31T00:00:00.123456789Z');
      await assert.rejects(() => readOsvDeltaIndex(file, {...artifact, sourceSha256: 'f'.repeat(64)}, {ecosystem: 'Go', release: null, baseSnapshotId: rootId, baseArtifactSha256: rootSha, baseContentSha256: 'b'.repeat(64)}), /摘要/);
      for (const changes of [{ecosystem: 'npm'}, {baseSnapshotId: '00000000-0000-4000-8000-000000000002'}, {baseArtifactSha256: 'c'.repeat(64)}, {release: '24.04'}]) {
        await assert.rejects(() => readOsvDeltaIndex(file, {...artifact, sourceSha256: payload.sourceSha256}, {ecosystem: 'Go', release: null, baseSnapshotId: rootId, baseArtifactSha256: rootSha, baseContentSha256: 'b'.repeat(64), ...changes} as any), /基线|范围/);
      }
      // An internally corrupted index is rejected even with recomputed envelope checksums.
      decoded.index.originalBase64 = Buffer.from('2026-10-30T00:00:00Z,OTHER\n').toString('base64');
      const changed = Buffer.from(JSON.stringify(decoded)), compressed = gzipSync(changed), corrupt = join(root, 'corrupt.blob'); await writeFile(corrupt, compressed);
      await assert.rejects(() => readOsvDeltaIndex(corrupt, {sha256: sha(compressed), size: compressed.length, sourceSha256: sha(changed)}, {ecosystem: 'Go', release: null, baseSnapshotId: rootId, baseArtifactSha256: rootSha, baseContentSha256: 'b'.repeat(64)}), /索引/);
      decoded.index.originalBase64 = Buffer.alloc(16 * 1024 * 1024, 65).toString('base64');
      const large = Buffer.from(JSON.stringify(decoded)), largeZip = gzipSync(large), largeFile = join(root, 'large.blob'); await writeFile(largeFile, largeZip);
      await assert.rejects(() => readOsvDeltaIndex(largeFile, {sha256: sha(largeZip), size: largeZip.length, sourceSha256: sha(large)}, {ecosystem: 'Go', release: null, baseSnapshotId: rootId, baseArtifactSha256: rootSha, baseContentSha256: 'b'.repeat(64)}), /行长度/);
    }, {root});
  } finally { await rm(root, {recursive: true, force: true}); }
});
