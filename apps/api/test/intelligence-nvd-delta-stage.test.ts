import 'reflect-metadata';
import {test} from 'node:test';
import assert from 'node:assert/strict';
import {randomBytes, randomUUID, createHash} from 'node:crypto';
import {spawnSync} from 'node:child_process';
import {mkdtemp, rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {gzipSync} from 'node:zlib';
import {Db} from '../src/db';
import {stageNvdDeltaSnapshot} from '../src/intelligence-nvd-delta-stage';
import {normalizeIntelligence} from '../src/intelligence-normalize';
import {intelligenceRecordFingerprint, intelligenceSnapshotFingerprint} from '../src/intelligence-fingerprint';
import {intelligenceNormalizerVersion, withRawArchive, currentRawArchive, captureRawBuffer} from '../src/intelligence-artifacts';

const cve = (id: string, lastModified: string, vulnStatus = 'Analyzed') => ({cve: {id, lastModified, vulnStatus, descriptions: [{lang: 'en', value: 'Owned NVD source fact'}]}});
const normalized = (raw: any) => normalizeIntelligence('NVD', {startIndex: 0, totalResults: 1, timestamp: '2026-10-31T22:00:00Z', vulnerabilities: [raw]}).records[0];
const row = (record: any, snapshotId: string) => ({...record, snapshotId, normalizedSha256: intelligenceRecordFingerprint(record), modifiedAt: new Date(record.modifiedAt), withdrawnAt: record.withdrawnAt ? new Date(record.withdrawnAt) : null});
test('real NVD merge retains newer full facts, rejection history and existing risks without publishing staging rows', {skip: !process.env.DATABASE_URL}, async () => {
  const root = await mkdtemp(join(tmpdir(), 'selfguard-nvd-merge-')), schema = 'nvd_delta_stage_' + randomBytes(12).toString('hex'), admin = new Db(), url = new URL(process.env.DATABASE_URL!); url.searchParams.set('schema', schema); let db: Db | undefined;
  try {
    await admin.$executeRawUnsafe('CREATE SCHEMA "' + schema + '"'); const setup = spawnSync(process.execPath, ['node_modules/prisma/build/index.js', 'migrate', 'deploy'], {env: {...process.env, DATABASE_URL: url.href}, encoding: 'utf8'}); assert.equal(setup.status, 0, setup.stderr); db = new Db({datasourceUrl: url.href});
    const config = {mode: 'YEAR', year: 2026, syncMode: 'AUTO'}, leaseId = randomUUID(), feed = await db.vulnerabilityFeed.create({data: {name: 'Owned NVD merged source', provider: 'NVD', config, configHash: 'owned', enabled: true, status: 'SYNCING', leaseId, leaseUntil: new Date(Date.now() + 300000)}});
    const rawBase = [cve('CVE-2026-10001', '2026-10-29T00:00:00'), cve('CVE-2026-10002', '2026-10-30T00:00:00'), cve('CVE-2026-10004', '2026-10-30T00:00:00')], records = rawBase.map(normalized), contentSha256 = intelligenceSnapshotFingerprint(records.map(intelligenceRecordFingerprint));
    const base = await db.vulnerabilitySnapshot.create({data: {feedId: feed.id, config, sourceUrl: 'https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-2026.json.gz', license: 'fixture', status: 'COMPLETE', normalizerVersion: intelligenceNormalizerVersion, contentSha256, recordCount: records.length, completedAt: new Date()}}); await db.vulnerabilityRecord.createMany({data: records.map(record => row(record, base.id))}); await db.vulnerabilityFeed.update({where: {id: feed.id}, data: {currentSnapshotId: base.id}});
    const risk = await db.finding.create({data: {dedupKey: 'owned-nvd-existing-risk', externalId: 'CVE-2026-10001', title: 'Previously verified component risk', kind: 'RISK', severity: 'HIGH', source: 'owned fixture', evidence: 'Existing component version evidence', status: 'OPEN'}});
    const updated = cve('CVE-2026-10001', '2026-10-31T00:00:00.123', 'Rejected'), added = cve('CVE-2026-10003', '2026-10-31T00:00:00'), original = {format: 'NVD_CVE', version: '2.0', timestamp: '2026-10-31T22:00:00', startIndex: 0, resultsPerPage: 5, totalResults: 5, vulnerabilities: [updated, added, cve('CVE-2026-10002', '2026-10-28T00:00:00'), rawBase[2], cve('CVE-2001-10001', '2026-10-31T00:00:00')]}, bytes = Buffer.from(JSON.stringify(original)), sourceSha256 = createHash('sha256').update(bytes).digest('hex'), meta = 'lastModifiedDate:2026-10-31T22:00:00Z\nsize:' + bytes.length + '\ngzSize:' + gzipSync(bytes).length + '\nsha256:' + sourceSha256 + '\n';
    await withRawArchive(1024 * 1024, async () => {
      await captureRawBuffer(bytes); const artifact = currentRawArchive()!.artifact!, modified = {sourceUrl: 'https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-modified.json.gz', sourceSha256, artifactSha256: artifact.sha256, artifact, sourceManifest: {nvdMeta: {original: meta, sha256OfMeta: createHash('sha256').update(meta).digest('hex')}, nvdFeed: {scope: 'MODIFIED', generatedAt: original.timestamp, records: 5}}};
      const baseVersions = {records: new Map(rawBase.map(raw => [raw.cve.id, raw.cve.lastModified])), digests: new Map(records.map(record => [record.externalId, record.rawSha256])), coveredThrough: '2026-10-30T00:00:00Z'}, document: any = {kind: 'NVD_MERGE', base, current: base, modified, baseVersions, receiptOnly: false, version: 'NVD/2026@modified-owned'};
      const staging = () => db!.vulnerabilitySnapshot.create({data: {feedId: feed.id, config, sourceUrl: modified.sourceUrl, license: 'fixture', normalizerVersion: intelligenceNormalizerVersion}}), snapshot = await staging(), result = await stageNvdDeltaSnapshot(db!, feed, snapshot.id, leaseId, document);
      assert.equal(result.recordCount, 4); assert.equal(result.contentSha256, intelligenceSnapshotFingerprint([normalized(updated), normalized(added), records[1], records[2]].map(intelligenceRecordFingerprint)));
      assert.deepEqual(currentRawArchive()?.manifest.nvdMerge, {year: 2026, sourceRecords: 5, selectedYearRecords: 4, added: 1, updated: 1, ignoredOlder: 1, unchanged: 1, withdrawn: 1});
      assert.equal((await db!.vulnerabilityFeed.findUniqueOrThrow({where: {id: feed.id}})).currentSnapshotId, base.id); assert.deepEqual(await db!.finding.findUniqueOrThrow({where: {id: risk.id}}), risk);
      const staged = await db!.vulnerabilityRecord.findMany({where: {snapshotId: snapshot.id}}); assert.ok(staged.find(row => row.externalId === 'CVE-2026-10001')!.withdrawnAt); assert.ok(staged.every(row => row.purpose === 'CANDIDATE')); assert.equal(await db!.vulnerabilityRecord.count({where: {snapshotId: base.id}}), 3);
      const receipt = await staging(), unchanged = await stageNvdDeltaSnapshot(db!, feed, receipt.id, leaseId, {...document, receiptOnly: true}); assert.equal(unchanged.contentSha256, base.contentSha256); assert.equal(await db!.vulnerabilityRecord.count({where: {snapshotId: receipt.id}}), 0);
      const disabled = await staging(); await db!.vulnerabilityFeed.update({where: {id: feed.id}, data: {enabled: false}}); await assert.rejects(() => stageNvdDeltaSnapshot(db!, feed, disabled.id, leaseId, document), /来源|租约/); assert.equal(await db!.vulnerabilityRecord.count({where: {snapshotId: disabled.id}}), 0);
    }, {root});
  } finally { await db?.$disconnect(); await admin.$executeRawUnsafe('DROP SCHEMA "' + schema + '" CASCADE'); await admin.$disconnect(); await rm(root, {recursive: true, force: true}); }
});
