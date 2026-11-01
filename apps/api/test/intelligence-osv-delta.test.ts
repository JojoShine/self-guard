import {test} from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp, rm} from 'node:fs/promises';
import {join} from 'node:path';
import {tmpdir} from 'node:os';
import {createHash} from 'node:crypto';
import {tryFetchOsvDelta, verifyOsvFullRefresh} from '../src/intelligence-osv-delta';
import {readOsvModifiedIndex, osvBytesCRC32C} from '../src/intelligence-osv-index';
import {withRawArchive, currentRawArchive, intelligenceNormalizerVersion, captureRawChunks, recordSourceManifest} from '../src/intelligence-artifacts';

const baseId = '00000000-0000-4000-8000-000000000001', sourceSha256 = 'a'.repeat(64), contentSha256 = 'b'.repeat(64), config = {mode: 'ECOSYSTEM', ecosystem: 'Go', syncMode: 'AUTO'};
const base = {id: baseId, feedId: 'feed', status: 'COMPLETE', normalizerVersion: intelligenceNormalizerVersion, config, completedAt: new Date(), contentSha256, sourceSha256, artifactSha256: sourceSha256, artifact: {encoding: 'ZIP', size: 100}, recordCount: 1, sourceManifest: {zip: {officialCRC32CVerified: true, crc32c: 'AAAAAA=='}}};
const feed = {id: 'feed', config};
async function index(lines: string) {
  const original = Buffer.from(lines);
  return {...await readOsvModifiedIndex((async function*() { yield original; })()), original, sourceUrl: 'https://storage.googleapis.com/osv-vulnerabilities/Go/modified_id.csv', generation: '123456'};
}
async function withFixture(work: (db: any, dependencies: any) => Promise<void>) {
  const root = await mkdtemp(join(tmpdir(), 'selfguard-delta-'));
  const db: any = {vulnerabilityRecord: {count: async (query: any) => query.where.normalizedSha256 === null ? 0 : 1}, vulnerabilitySnapshot: {findFirst: async () => base}};
  const dependencies: any = {
    readVersions: async () => ({records: new Map([['GO-2026-0001', '2026-10-30T00:00:00Z']])}),
    fetchIndex: async () => index('2026-10-31T00:00:00.123456789Z,GO-2026-0002\n2026-10-31T00:00:00Z,GO-2026-0001\n'),
    fetchRecord: async (_eco: string, id: string, modified: string) => {
      const document = {id, modified, affected: [{package: {ecosystem: 'Go', name: 'fixture.test/example'}, ranges: [{type: 'SEMVER', events: [{introduced: '0'}, {fixed: '2.0.0'}]}]}]}, original = Buffer.from(JSON.stringify(document));
      return {document, original, sourceSha256: createHash('sha256').update(original).digest('hex'), crc32c: osvBytesCRC32C(original), generation: '123457', sourceUrl: 'https://storage.googleapis.com/osv-vulnerabilities/Go/' + id + '.json'};
    },
  };
  try { await withRawArchive(16 * 1024 * 1024, () => work(db, dependencies), {root}); }
  finally { await rm(root, {recursive: true, force: true}); }
}
test('missing, incompatible, expired or incomplete full baselines clearly choose a full refresh', async () => {
  await withFixture(async (db, dependencies) => {
    dependencies.fetchIndex = async () => assert.fail('index not needed before a valid baseline');
    for (const current of [null, {...base, normalizerVersion: 'old'}, {...base, config: {...config, ecosystem: 'npm'}}, {...base, completedAt: new Date(Date.now() - 8 * 86400000)}]) {
      assert.equal(await tryFetchOsvDelta(db, feed, current, dependencies), null);
      assert.equal((currentRawArchive()?.manifest.sync as any)?.mode, 'FULL');
    }
    db.vulnerabilityRecord.count = async (query: any) => query.where.normalizedSha256 === null ? 1 : 1;
    assert.equal(await tryFetchOsvDelta(db, feed, base, dependencies), null);
  });
});
test('downloads exact added and updated IDs then retains a single cumulative original package', async () => {
  await withFixture(async (db, dependencies) => {
    const downloaded: string[] = [], fetch = dependencies.fetchRecord;
    dependencies.fetchRecord = async (...args: any[]) => { downloaded.push(args[1]); return fetch(...args); };
    const result = await tryFetchOsvDelta(db, feed, base, dependencies);
    assert.equal(result?.document.kind, 'OSV_DELTA'); assert.equal(result?.document.receiptOnly, false);
    assert.deepEqual(downloaded, ['GO-2026-0002', 'GO-2026-0001']);
    assert.equal(result?.document.records.length, 2); assert.ok(currentRawArchive()?.artifact);
    const sync: any = currentRawArchive()?.manifest.sync;
    assert.equal(sync.mode, 'DELTA'); assert.equal(sync.baseSnapshotId, baseId); assert.equal(sync.added, 1); assert.equal(sync.updated, 1);
  });
});
test('unchanged complete index produces only a receipt and does not download records', async () => {
  await withFixture(async (db, dependencies) => {
    dependencies.fetchIndex = async () => index('2026-10-30T00:00:00Z,GO-2026-0001\n');
    dependencies.fetchRecord = async () => assert.fail('unchanged records must not be fetched');
    const result = await tryFetchOsvDelta(db, feed, base, dependencies);
    assert.equal(result?.document.receiptOnly, true); assert.equal((currentRawArchive()?.manifest.sync as any)?.mode, 'UNCHANGED'); assert.ok(currentRawArchive()?.artifact);
  });
});
test('older index versions are rejected while removed IDs request an explicit complete refresh', async () => {
  await withFixture(async (db, dependencies) => {
    dependencies.fetchIndex = async () => index('2026-10-29T00:00:00Z,GO-2026-0001\n');
    await assert.rejects(() => tryFetchOsvDelta(db, feed, base, dependencies), /旧|回退/);
    dependencies.fetchIndex = async () => index('2026-10-31T00:00:00Z,GO-2026-0002\n');
    assert.equal(await tryFetchOsvDelta(db, feed, base, dependencies), null); assert.equal(currentRawArchive()?.artifact, undefined);
    assert.equal((currentRawArchive()?.manifest.sync as any)?.reason, 'INDEX_REMOVED_IDENTITIES');
  });
});
test('later increments compare the accepted raw index while always referencing the same complete root', async () => {
  await withFixture(async (db, dependencies) => {
    const first = (await tryFetchOsvDelta(db, feed, base, dependencies))!, scope = currentRawArchive()!;
    const current = {...base, id: '00000000-0000-4000-8000-000000000002', artifact: {...scope.artifact}, artifactSha256: scope.artifact!.sha256, sourceSha256: first.sourceSha256, recordCount: 2, sourceManifest: JSON.parse(JSON.stringify(scope.manifest))};
    db.vulnerabilityRecord.count = async (query: any) => query.where.normalizedSha256 === null ? 0 : query.where.snapshotId === baseId ? 1 : 2;
    await withRawArchive(16 * 1024 * 1024, async () => {
      const repeated = (await tryFetchOsvDelta(db, feed, current, dependencies))!;
      assert.equal(repeated.document.receiptOnly, true); assert.equal(repeated.document.current.id, current.id); assert.equal((currentRawArchive()?.manifest.sync as any).baseSnapshotId, baseId);
    }, {root: scope.root});
    await withRawArchive(16 * 1024 * 1024, async () => {
      dependencies.fetchIndex = async () => index('2026-10-31T00:00:00.123456789Z,GO-2026-0002\n2026-10-30T00:00:00Z,GO-2026-0001\n');
      await assert.rejects(() => tryFetchOsvDelta(db, feed, current, dependencies), /旧|回退/);
    }, {root: scope.root});
  });
});
test('complete refresh checks every shared timestamp even beyond the incremental change budget', async () => {
  await withFixture(async (db, dependencies) => {
    const old = new Map(Array.from({length: 601}, (_, i) => ['GO-' + i, '2026-10-30T00:00:00Z']));
    const next = new Map([...old].map(([id]) => [id, id === 'GO-600' ? '2026-10-29T00:00:00Z' : '2026-10-31T00:00:00Z']));
    dependencies.readVersions = async (_file: string, sha: string) => ({records: sha === sourceSha256 ? old : next});
    for await (const _ of captureRawChunks((async function*() { yield Buffer.from('owned original fixture'); })(), 'ZIP')) {}
    recordSourceManifest('zip', {officialCRC32CVerified: true, crc32c: 'AAAAAA=='});
    await assert.rejects(() => verifyOsvFullRefresh(db, feed, base, dependencies), /旧/);
  });
});
test('withdrawn Ubuntu source entries stay counted even when outside the selected standard release', async () => {
  await withFixture(async (db, dependencies) => {
    const config = {mode: 'ECOSYSTEM', ecosystem: 'Ubuntu', release: '24.04', syncMode: 'AUTO'}, id = 'UBUNTU-CVE-2026-10001', modified = '2026-10-31T00:00:00Z';
    dependencies.readVersions = async () => ({records: new Map([[id, '2026-10-30T00:00:00Z']])});
    dependencies.fetchIndex = async () => ({...await index(modified + ',' + id + '\n'), sourceUrl: 'https://storage.googleapis.com/osv-vulnerabilities/Ubuntu/modified_id.csv'});
    dependencies.fetchRecord = async () => {
      const document = {id, modified, withdrawn: modified, affected: [{package: {ecosystem: 'Ubuntu:22.04:LTS', name: 'example'}}]}, original = Buffer.from(JSON.stringify(document));
      return {document, original, sourceSha256: createHash('sha256').update(original).digest('hex'), crc32c: osvBytesCRC32C(original), generation: '123457', sourceUrl: 'https://storage.googleapis.com/osv-vulnerabilities/Ubuntu/' + id + '.json'};
    };
    const result = (await tryFetchOsvDelta(db, {...feed, config}, {...base, config}, dependencies))!;
    assert.equal(result.document.records[0].record, null); assert.equal((currentRawArchive()?.manifest.sync as any).withdrawn, 1); assert.equal((currentRawArchive()?.manifest.sync as any).scopeExcluded, 1);
  });
});
