import 'reflect-metadata';
import {test} from 'node:test';
import assert from 'node:assert/strict';
import {randomBytes, randomUUID} from 'node:crypto';
import {spawnSync} from 'node:child_process';
import {mkdtemp, rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {Db} from '../src/db';
import {stageOsvDeltaSnapshot} from '../src/intelligence-osv-delta-stage';
import {normalizeOsvScopedRecord} from '../src/intelligence-osv-scoped';
import {intelligenceRecordFingerprint, intelligenceSnapshotFingerprint} from '../src/intelligence-fingerprint';
import {intelligenceNormalizerVersion, withRawArchive, currentRawArchive, captureRawBuffer, recordSourceManifest} from '../src/intelligence-artifacts';
import {syncVulnerabilityFeed, VulnerabilityFeedsController} from '../src/intelligence';
import {createHash} from 'node:crypto';

const raw = (id: string, modified = '2026-10-30T00:00:00Z', extra = {}) => ({id, modified, affected: [{package: {ecosystem: 'Go', name: 'fixture.test/example'}, ranges: [{type: 'SEMVER', events: [{introduced: '0'}, {fixed: '2.0.0'}]}]}], ...extra});
function data(record: any, snapshotId: string) {
  return {...record, snapshotId, normalizedSha256: intelligenceRecordFingerprint(record), modifiedAt: record.modifiedAt ? new Date(record.modifiedAt) : null, withdrawnAt: record.withdrawnAt ? new Date(record.withdrawnAt) : null};
}
test('real database delta stages a complete immutable snapshot and fences failed ownership', {skip: !process.env.DATABASE_URL}, async () => {
  const root = await mkdtemp(join(tmpdir(), 'selfguard-delta-publish-')), previousRoot = process.env.INTELLIGENCE_ARTIFACT_DIR;
  process.env.INTELLIGENCE_ARTIFACT_DIR = root;
  const admin = new Db(), schema = 'osv_delta_stage_' + randomBytes(12).toString('hex'), url = new URL(process.env.DATABASE_URL!); url.searchParams.set('schema', schema); let db: Db | undefined;
  try {
    await admin.$executeRawUnsafe('CREATE SCHEMA "' + schema + '"');
    const migrated = spawnSync(process.execPath, ['node_modules/prisma/build/index.js', 'migrate', 'deploy'], {env: {...process.env, DATABASE_URL: url.href}, encoding: 'utf8'}); assert.equal(migrated.status, 0, migrated.stderr);
    db = new Db({datasourceUrl: url.href});
    const config = {mode: 'ECOSYSTEM', ecosystem: 'Go', syncMode: 'AUTO'}, leaseId = randomUUID(), feed = await db.vulnerabilityFeed.create({data: {name: 'owned delta fixture', provider: 'OSV', config, configHash: 'owned', enabled: true, status: 'SYNCING', leaseId, leaseUntil: new Date(Date.now() + 300000)}});
    const records = ['GO-1', 'GO-2', 'GO-3'].map(id => normalizeOsvScopedRecord(raw(id), 'Go')!), contentSha256 = intelligenceSnapshotFingerprint(records.map(intelligenceRecordFingerprint));
    const base = await db.vulnerabilitySnapshot.create({data: {feedId: feed.id, config, sourceUrl: 'https://storage.googleapis.com/osv-vulnerabilities/Go/all.zip', license: 'fixture', status: 'COMPLETE', normalizerVersion: intelligenceNormalizerVersion, contentSha256, recordCount: records.length, completedAt: new Date()}});
    const risk = await db.finding.create({data: {dedupKey: 'owned-existing-risk', externalId: 'GO-2', title: 'Previously verified owned risk', kind: 'RISK', severity: 'HIGH', source: 'owned acceptance', evidence: 'Retained actual fixture evidence', status: 'OPEN'}});
    await db.vulnerabilityRecord.createMany({data: records.map(record => data(record, base.id))}); await db.vulnerabilityFeed.update({where: {id: feed.id}, data: {currentSnapshotId: base.id}});
    const changed = normalizeOsvScopedRecord(raw('GO-1', '2026-10-31T00:00:00.123456789Z', {details: 'Updated genuine fixture fact'}), 'Go')!, withdrawn = normalizeOsvScopedRecord(raw('GO-2', '2026-10-31T00:00:00Z', {withdrawn: '2026-10-31T00:00:00Z'}), 'Go')!, added = normalizeOsvScopedRecord(raw('GO-4', '2026-10-31T00:00:00Z', {affected: [{ranges: []}]}), 'Go')!;
    const document: any = {kind: 'OSV_DELTA', ecosystem: 'Go', base, current: base, receiptOnly: false, version: 'owned index', records: [{id: 'GO-1', record: changed}, {id: 'GO-2', record: withdrawn}, {id: 'GO-4', record: added}]};
    const staging = () => db!.vulnerabilitySnapshot.create({data: {feedId: feed.id, config, sourceUrl: 'https://storage.googleapis.com/osv-vulnerabilities/Go/modified_id.csv', license: 'fixture', normalizerVersion: intelligenceNormalizerVersion}});
    const snapshot = await staging();
    await withRawArchive(1024, async () => {
      const result = await stageOsvDeltaSnapshot(db!, feed, snapshot.id, leaseId, document);
      assert.equal(result.recordCount, 4); assert.equal(result.contentSha256, intelligenceSnapshotFingerprint([changed, withdrawn, added, records[2]].map(intelligenceRecordFingerprint)));
      assert.deepEqual(currentRawArchive()?.manifest.normalization, {activeUnscopedAffected: 1, coveredEcosystems: ['Go']});
    });
    assert.equal((await db.vulnerabilityFeed.findUniqueOrThrow({where: {id: feed.id}})).currentSnapshotId, base.id);
    assert.deepEqual((await db.vulnerabilityRecord.findMany({where: {snapshotId: base.id}, orderBy: {externalId: 'asc'}})).map(row => row.normalizedSha256), records.map(intelligenceRecordFingerprint));
    const staged = await db.vulnerabilityRecord.findMany({where: {snapshotId: snapshot.id}, orderBy: {externalId: 'asc'}}); assert.equal(staged.length, 4); assert.ok(staged[1].withdrawnAt); assert.equal((staged[0].metadata as any).osvOriginalVersion.modified, '2026-10-31T00:00:00.123456789Z'); assert.equal(new Set(staged.map(row => row.id)).size, 4);
    const receipt = await staging();
    const unchanged = await stageOsvDeltaSnapshot(db, feed, receipt.id, leaseId, {...document, receiptOnly: true, records: []}); assert.equal(unchanged.contentSha256, base.contentSha256); assert.equal(await db.vulnerabilityRecord.count({where: {snapshotId: receipt.id}}), 0);
    const disabled = await staging(); await db.vulnerabilityFeed.update({where: {id: feed.id}, data: {enabled: false}});
    await assert.rejects(() => stageOsvDeltaSnapshot(db!, feed, disabled.id, leaseId, document), /来源|租约/); assert.equal(await db.vulnerabilityRecord.count({where: {snapshotId: disabled.id}}), 0);
    await db.vulnerabilityFeed.update({where: {id: feed.id}, data: {enabled: true, leaseUntil: new Date(Date.now() - 1000)}});
    const expired = await staging(); await assert.rejects(() => stageOsvDeltaSnapshot(db!, feed, expired.id, leaseId, document), /来源|租约/); assert.equal(await db.vulnerabilityRecord.count({where: {snapshotId: expired.id}}), 0);
    await db.vulnerabilityFeed.update({where: {id: feed.id}, data: {leaseUntil: new Date(Date.now() + 300000)}});
    await db.vulnerabilityRecord.updateMany({where: {snapshotId: base.id, externalId: 'GO-3'}, data: {normalizedSha256: null}});
    const incomplete = await staging(); await assert.rejects(() => stageOsvDeltaSnapshot(db!, feed, incomplete.id, leaseId, document), /指纹/); assert.equal(await db.vulnerabilityRecord.count({where: {snapshotId: incomplete.id}}), 0);
    await db.vulnerabilityRecord.updateMany({where: {snapshotId: base.id, externalId: 'GO-3'}, data: {normalizedSha256: intelligenceRecordFingerprint(records[2])}});
    await db.vulnerabilityFeed.update({where: {id: feed.id}, data: {status: 'IDLE', leaseId: null, leaseUntil: null}});
    const fetched = (value: any, expire = false) => async () => {
      const bytes = Buffer.from(JSON.stringify({ownedPublicationFixture: true, receipt: value.receiptOnly})); await captureRawBuffer(bytes);
      recordSourceManifest('sync', {mode: value.receiptOnly ? 'UNCHANGED' : 'DELTA', baseSnapshotId: base.id});
      if (expire) await db!.vulnerabilityFeed.update({where: {id: feed.id}, data: {leaseUntil: new Date(0)}});
      return {document: value, sourceSha256: createHash('sha256').update(bytes).digest('hex'), sourceUrl: 'https://storage.googleapis.com/osv-vulnerabilities/Go/modified_id.csv'};
    };
    const published = await syncVulnerabilityFeed(db, feed.id, 'owned fixture', fetched(document));
    assert.equal(published.snapshot.status, 'COMPLETE', published.snapshot.error || ''); assert.equal(published.feed.currentSnapshotId, published.snapshot.id); assert.equal(published.snapshot.recordCount, 4); assert.ok(published.snapshot.artifactSha256); assert.match(published.snapshot.sourceUrl, /modified_id/);
    const receiptDocument = {...document, current: published.snapshot, receiptOnly: true, records: []};
    const checked = await syncVulnerabilityFeed(db, feed.id, 'owned fixture', fetched(receiptDocument)); assert.equal(checked.snapshot.status, 'UNCHANGED', checked.snapshot.error || ''); assert.equal(checked.feed.currentSnapshotId, published.snapshot.id); assert.equal(await db.vulnerabilityRecord.count({where: {snapshotId: checked.snapshot.id}}), 0);
    const failed = await syncVulnerabilityFeed(db, feed.id, 'owned fixture', fetched({...document, current: published.snapshot}, true)); assert.equal(failed.snapshot.status, 'FAILED'); assert.equal(failed.feed.currentSnapshotId, published.snapshot.id); assert.equal(await db.vulnerabilityRecord.count({where: {snapshotId: published.snapshot.id}}), 4);
    assert.deepEqual(await db.finding.findUniqueOrThrow({where: {id: risk.id}}), risk);
    const pageLease = randomUUID(), pageFeed = await db.vulnerabilityFeed.create({data: {name: 'owned multi-page delta fixture', provider: 'OSV', config, configHash: 'page-owned', enabled: true, status: 'SYNCING', leaseId: pageLease, leaseUntil: new Date(Date.now() + 300000)}});
    const pageRecords = Array.from({length: 1001}, (_, i) => ({...records[0], externalId: 'GO-PAGE-' + i, aliases: ['GO-PAGE-' + i]})), pageHash = intelligenceSnapshotFingerprint(pageRecords.map(intelligenceRecordFingerprint));
    const pageBase = await db.vulnerabilitySnapshot.create({data: {feedId: pageFeed.id, config, sourceUrl: base.sourceUrl, license: 'fixture', status: 'COMPLETE', normalizerVersion: intelligenceNormalizerVersion, contentSha256: pageHash, recordCount: pageRecords.length, completedAt: new Date()}});
    await db.vulnerabilityRecord.createMany({data: pageRecords.map(record => data(record, pageBase.id))}); await db.vulnerabilityFeed.update({where: {id: pageFeed.id}, data: {currentSnapshotId: pageBase.id}});
    const pageSnapshot = await db.vulnerabilitySnapshot.create({data: {feedId: pageFeed.id, config, sourceUrl: base.sourceUrl, license: 'fixture', normalizerVersion: intelligenceNormalizerVersion}});
    const pageResult = await stageOsvDeltaSnapshot(db, pageFeed, pageSnapshot.id, pageLease, {...document, base: pageBase, current: pageBase, records: []}); assert.equal(pageResult.recordCount, 1001); assert.equal(pageResult.contentSha256, pageHash); assert.equal(await db.vulnerabilityRecord.count({where: {snapshotId: pageBase.id}}), 1001);
    const controller = new VulnerabilityFeedsController(db), req = {user: {role: 'ADMIN', email: 'legacy-mode@fixture.test'}}, legacy = await controller.create(req, {name: 'Legacy full source', provider: 'OSV', config: {mode: 'ECOSYSTEM', ecosystem: 'Go'}}), legacySnapshot = await db.vulnerabilitySnapshot.create({data: {feedId: legacy.id, config: legacy.config as any, sourceUrl: base.sourceUrl, license: 'fixture', status: 'COMPLETE'}});
    await db.vulnerabilityFeed.update({where: {id: legacy.id}, data: {currentSnapshotId: legacySnapshot.id}});
    const savedLegacy = await controller.patch(req, legacy.id, {name: 'Renamed legacy full source', config: {mode: 'ECOSYSTEM', ecosystem: 'Go', syncMode: 'FULL'}}); assert.equal(savedLegacy.currentSnapshotId, legacySnapshot.id); assert.equal((savedLegacy.config as any).syncMode, undefined);
  } finally { if (previousRoot === undefined) delete process.env.INTELLIGENCE_ARTIFACT_DIR; else process.env.INTELLIGENCE_ARTIFACT_DIR = previousRoot; await db?.$disconnect(); await admin.$executeRawUnsafe('DROP SCHEMA "' + schema + '" CASCADE'); await admin.$disconnect(); await rm(root, {recursive: true, force: true}); }
});
