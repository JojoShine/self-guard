import 'reflect-metadata';
import {test} from 'node:test';
import assert from 'node:assert/strict';
import {randomBytes, createHash} from 'node:crypto';
import {spawnSync} from 'node:child_process';
import {mkdtemp, rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {gzipSync} from 'node:zlib';
import {Db} from '../src/db';
import {syncVulnerabilityFeed, VulnerabilityFeedsController} from '../src/intelligence';
import {prepareNvdMerge} from '../src/intelligence-nvd-sync';
import {nvdFeedDocument, parseNvdMeta} from '../src/intelligence-nvd-feed';
import {captureRawChunks, currentRawArchive, recordSourceManifest} from '../src/intelligence-artifacts';
import {snapshotSourceProof} from '../src/intelligence-snapshot-proof';

const digest = (value: Buffer | string) => createHash('sha256').update(value).digest('hex');
const cve = (id: string, day: number, status = 'Analyzed') => ({cve: {id, lastModified: '2026-10-' + day + 'T12:00:00.123456789', vulnStatus: status, descriptions: [{lang: 'en', value: 'Controlled original for publication acceptance'}]}});
function official(records: any[], day: number, scope: 'ANNUAL' | 'MODIFIED') {
  const raw = Buffer.from(JSON.stringify({format: 'NVD_CVE', version: '2.0', startIndex: 0, resultsPerPage: records.length, totalResults: records.length, timestamp: '2026-10-' + day + 'T18:00:00', vulnerabilities: records}));
  const original = 'lastModifiedDate:2026-10-' + day + 'T18:00:07-04:00\nsize:' + raw.length + '\ngzSize:' + gzipSync(raw).length + '\nsha256:' + digest(raw) + '\n', meta = parseNvdMeta(original);
  return {meta, original, fetched() {
    recordSourceManifest('nvdMeta', {...meta, original, sha256OfMeta: digest(original)});
    const stream: any = {sourceSha256: '', decodedBytes: 0, abort() {}};
    async function* bytes() { yield raw; stream.sourceSha256 = digest(raw); stream.decodedBytes = raw.length; }
    stream.chunks = captureRawChunks(bytes()); return nvdFeedDocument(meta, stream, scope);
  }};
}
test('NVD source publishes bounded annual plus modified originals atomically, receipts preserve the active snapshot and failed refreshes preserve risks', {skip: !process.env.DATABASE_URL}, async () => {
  const root = await mkdtemp(join(tmpdir(), 'selfguard-nvd-sync-')), schema = 'nvd_sync_' + randomBytes(12).toString('hex'), admin = new Db(), url = new URL(process.env.DATABASE_URL!); url.searchParams.set('schema', schema); let db: Db | undefined;
  const previousRoot = process.env.INTELLIGENCE_ARTIFACT_DIR; process.env.INTELLIGENCE_ARTIFACT_DIR = root;
  try {
    await admin.$executeRawUnsafe('CREATE SCHEMA "' + schema + '"');
    const setup = spawnSync(process.execPath, ['node_modules/prisma/build/index.js', 'migrate', 'deploy'], {env: {...process.env, DATABASE_URL: url.href}, encoding: 'utf8'}); assert.equal(setup.status, 0, setup.stderr); db = new Db({datasourceUrl: url.href});
    const controller = new VulnerabilityFeedsController(db), req = {user: {role: 'ADMIN', email: 'owned-nvd-sync@fixture.test', scope: 'GLOBAL'}};
    const feed = await controller.create(req, {name: 'Controlled official NVD synchronization', provider: 'NVD', config: {mode: 'YEAR', year: 2026, syncMode: 'AUTO'}});
    const annual = official([cve('CVE-2026-10001', 20), cve('CVE-2026-10002', 20)], 21, 'ANNUAL');
    let modified = official([cve('CVE-2026-10001', 30), cve('CVE-2026-10003', 30), cve('CVE-2001-10001', 30)], 30, 'MODIFIED'), annualReads = 0, modifiedReads = 0;
    const prepare = (client: any, source: any, current: any, snapshotId: string, leaseId: string) => prepareNvdMerge(client, source, current, snapshotId, leaseId, {fetchAnnual: async () => { annualReads++; return annual.fetched(); }, fetchModified: async () => { modifiedReads++; return modified.fetched(); }, fetchMeta: async () => { recordSourceManifest('nvdMeta', {...modified.meta, original: modified.original, sha256OfMeta: digest(modified.original)}); return modified.meta; }});
    const sync = () => syncVulnerabilityFeed(db!, feed.id, req.user.email, undefined, {prepareNvdMerge: prepare});
    const first = await sync(); assert.equal(first.snapshot.status, 'COMPLETE'); assert.equal(first.snapshot.recordCount, 3); assert.equal(first.snapshot.sourceManifest.sync.strategy, 'NVD_FULL_WITH_MODIFIED');
    const annualId = first.snapshot.sourceManifest.sync.annualSnapshotId, component = await db.vulnerabilitySnapshot.findUniqueOrThrow({where: {id: annualId}, include: {artifact: true}});
    assert.equal(component.status, 'COMPLETE'); assert.ok(component.artifact); assert.equal(component.recordCount, 2); assert.notEqual(component.artifactSha256, first.snapshot.artifactSha256);
    const firstSnapshot = await db.vulnerabilitySnapshot.findUniqueOrThrow({where: {id: first.snapshot.id}, include: {artifact: true}});
    assert.deepEqual((await snapshotSourceProof(db, firstSnapshot)).sourceParts?.map(part => part.role), ['ANNUAL_SOURCE', 'BASELINE_UPDATES']);
    const risk = await db.finding.create({data: {dedupKey: 'nvd-sync-owned-risk', externalId: 'CVE-2026-10001', title: 'Retained verified risk', kind: 'RISK', severity: 'HIGH', source: 'fixture', evidence: 'Existing component version evidence', status: 'OPEN'}});
    const second = await sync(); assert.equal(second.snapshot.status, 'UNCHANGED'); assert.equal(second.feed.currentSnapshotId, first.snapshot.id); assert.equal(annualReads, 1); assert.equal(modifiedReads, 1); assert.equal(await db.vulnerabilityRecord.count({where: {snapshotId: second.snapshot.id}}), 0);
    modified = official([cve('CVE-2026-10001', 31, 'Rejected'), cve('CVE-2026-10003', 30), cve('CVE-2026-10004', 31)], 31, 'MODIFIED');
    const third = await sync(); assert.equal(third.snapshot.status, 'COMPLETE'); assert.equal(third.snapshot.recordCount, 4); assert.equal(third.snapshot.sourceManifest.sync.strategy, 'NVD_MODIFIED'); assert.equal(third.snapshot.sourceManifest.sync.baseSnapshotId, first.snapshot.id); assert.equal(annualReads, 1); assert.equal(modifiedReads, 2);
    const thirdSnapshot = await db.vulnerabilitySnapshot.findUniqueOrThrow({where: {id: third.snapshot.id}, include: {artifact: true}});
    assert.deepEqual((await snapshotSourceProof(db, thirdSnapshot)).sourceParts?.map(part => part.role), ['ANNUAL_SOURCE', 'BASELINE_UPDATES', 'VERIFIED_DELTA']);
    await assert.rejects(() => snapshotSourceProof(db, {...thirdSnapshot, sourceManifest: {sync: {...(thirdSnapshot.sourceManifest as any).sync, baseContentSha256: 'f'.repeat(64)}}}), /基线/);
    assert.ok((await db.vulnerabilityRecord.findUniqueOrThrow({where: {snapshotId_externalId: {snapshotId: third.snapshot.id, externalId: 'CVE-2026-10001'}}})).withdrawnAt);
    assert.deepEqual(await db.finding.findUniqueOrThrow({where: {id: risk.id}}), risk);
    modified = official([cve('CVE-2026-10001', 29)], 29, 'MODIFIED');
    const failed = await sync(); assert.equal(failed.snapshot.status, 'FAILED'); assert.equal(failed.feed.currentSnapshotId, third.snapshot.id); assert.match(failed.snapshot.error!, /回退|更旧/);
    assert.equal(await db.vulnerabilitySnapshot.count({where: {feedId: feed.id, status: 'STAGING'}}), 0);
    assert.equal(await db.vulnerabilityRecord.count({where: {snapshotId: first.snapshot.id}}), 3);
    const legacy = await controller.create(req, {name: 'Legacy annual source', provider: 'NVD', config: {mode: 'YEAR', year: 2002}});
    const old = await db.vulnerabilitySnapshot.create({data: {feedId: legacy.id, config: legacy.config as any, sourceUrl: 'https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-2002.json.gz', status: 'COMPLETE', license: 'fixture'}});
    await db.vulnerabilityFeed.update({where: {id: legacy.id}, data: {currentSnapshotId: old.id}});
    const saved = await controller.patch(req, legacy.id, {config: {mode: 'YEAR', year: 2002, syncMode: 'FULL'}}); assert.equal(saved.currentSnapshotId, old.id);
    const interrupted = await controller.create(req, {name: 'Interrupted composed source', provider: 'NVD', config: {mode: 'YEAR', year: 2025, syncMode: 'AUTO'}});
    const stopped = await syncVulnerabilityFeed(db, interrupted.id, req.user.email, undefined, {prepareNvdMerge: async (...args) => {
      const annual2025 = official([cve('CVE-2025-10001', 20)], 21, 'ANNUAL'), modified2025 = official([cve('CVE-2025-10001', 31)], 31, 'MODIFIED');
      const fetched = await prepareNvdMerge(...args, {fetchAnnual: async () => annual2025.fetched(), fetchModified: async () => modified2025.fetched(), fetchMeta: async () => modified2025.meta});
      await db!.vulnerabilityFeed.update({where: {id: interrupted.id}, data: {enabled: false}}); return fetched;
    }});
    assert.equal(stopped.snapshot.status, 'FAILED'); assert.equal(stopped.feed.currentSnapshotId, null);
    const pieces = await db.vulnerabilitySnapshot.findMany({where: {feedId: interrupted.id}}); assert.equal(pieces.length, 2); assert.ok(pieces.every(piece => piece.status === 'FAILED'));
  } finally {
    if (previousRoot === undefined) delete process.env.INTELLIGENCE_ARTIFACT_DIR; else process.env.INTELLIGENCE_ARTIFACT_DIR = previousRoot;
    await db?.$disconnect(); await admin.$executeRawUnsafe('DROP SCHEMA "' + schema + '" CASCADE'); await admin.$disconnect(); await rm(root, {recursive: true, force: true});
  }
});
