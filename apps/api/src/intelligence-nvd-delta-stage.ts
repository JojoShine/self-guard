import {ConflictException} from '@nestjs/common';
import {isDeepStrictEqual} from 'node:util';
import type {Db} from './db';
import {copySnapshotRecords, snapshotFingerprint} from './intelligence-snapshot-stage';
import {intelligenceNormalizerVersion, recordSourceManifest} from './intelligence-artifacts';
import {intelligenceRecordFingerprint} from './intelligence-fingerprint';
import {normalizeIntelligence} from './intelligence-normalize';
import {nvdCveInYear, openNvdOriginal} from './intelligence-nvd-original';
import {nvdTimeNanoseconds} from './intelligence-nvd-feed';
import type {NvdVersionSet} from './intelligence-nvd-delta-plan';

export type NvdMergeDocument = {kind: 'NVD_MERGE'; base: any; current: any | null; modified: any; baseVersions: NvdVersionSet; receiptOnly: boolean; version: string; promoteAnnualId?: string};
export async function stageNvdDeltaSnapshot(db: Db, feed: any, snapshotId: string, leaseId: string, document: NvdMergeDocument) {
  const base = document.base, ownAnnual = base.status === 'STAGING' && base.sourceManifest?.sync?.role === 'ANNUAL_COMPONENT' && base.sourceManifest.sync.parentSnapshotId === snapshotId;
  if (base.feedId !== feed.id || !isDeepStrictEqual(base.config, feed.config) || base.normalizerVersion !== intelligenceNormalizerVersion || base.status !== 'COMPLETE' && !ownAnnual) throw Error('NVD合并基线未完整确认或与本次来源范围不符');
  async function held(tx: any) {
    const result = await tx.vulnerabilityFeed.updateMany({where: {id: feed.id, leaseId, enabled: true, configHash: feed.configHash, currentSnapshotId: document.current?.id || null, leaseUntil: {gt: new Date()}}, data: {leaseUntil: new Date(Date.now() + 300000)}});
    if (!result.count) throw new ConflictException('NVD来源停用、范围更改、快照变化或租约过期');
  }
  await db.$transaction(held);
  const baseline = await snapshotFingerprint(db, base.id, base.recordCount);
  if (baseline.contentSha256 !== base.contentSha256 || document.baseVersions.records.size !== baseline.recordCount) throw Error('NVD完整合并基线指纹或版本数量不一致');
  if (document.receiptOnly) {
    if (!document.current || document.current.status !== 'COMPLETE') throw Error('NVD更新收据缺少当前完整快照');
    const current = await snapshotFingerprint(db, document.current.id, document.current.recordCount);
    if (current.contentSha256 !== document.current.contentSha256) throw Error('NVD当前完整快照指纹不一致');
    return {...current, version: document.version, coverage: 'NVD官方修改源元数据与已接受版本一致，保留检查收据并继续使用当前完整快照。' + (document.current.coverage || '')};
  }
  await copySnapshotRecords(db, base.id, snapshotId, baseline.recordCount, held);
  const original = await openNvdOriginal(document.modified, feed.config.year, 'MODIFIED');
  let sourceRecords = 0, selectedYearRecords = 0, added = 0, updated = 0, ignoredOlder = 0, unchanged = 0, withdrawn = 0;
  try {
    for await (const raw of original.document.entries) {
      const cve = (raw as any).cve;
      if (typeof cve.lastModified !== 'string') throw Error('NVD修改源缺少原始修改时间');
      const modified = nvdTimeNanoseconds(cve.lastModified); sourceRecords++;
      if (!nvdCveInYear(cve.id, feed.config.year)) continue;
      selectedYearRecords++;
      const previous = document.baseVersions.records.get(cve.id);
      if (previous !== undefined && modified < nvdTimeNanoseconds(previous)) { ignoredOlder++; continue; }
      const record = normalizeIntelligence('NVD', {startIndex: 0, totalResults: 1, timestamp: original.document.meta.lastModifiedDate, vulnerabilities: [raw]}).records[0];
      if (document.baseVersions.digests.get(cve.id) === record.rawSha256) { unchanged++; continue; }
      const row: any = {...record, snapshotId, normalizedSha256: intelligenceRecordFingerprint(record), modifiedAt: record.modifiedAt ? new Date(record.modifiedAt) : null, withdrawnAt: record.withdrawnAt ? new Date(record.withdrawnAt) : null};
      await db.$transaction(async tx => { await held(tx); await tx.vulnerabilityRecord.upsert({where: {snapshotId_externalId: {snapshotId, externalId: cve.id}}, create: row, update: row}); }, {timeout: 30000});
      if (previous === undefined) added++; else updated++;
      if (record.withdrawnAt) withdrawn++;
    }
    original.document.validate();
    const result = await snapshotFingerprint(db, snapshotId);
    recordSourceManifest('nvdMerge', {year: feed.config.year, sourceRecords, selectedYearRecords, added, updated, ignoredOlder, unchanged, withdrawn});
    await db.$transaction(async tx => { await held(tx); await tx.vulnerabilitySnapshot.update({where: {id: snapshotId}, data: {recordCount: result.recordCount}}); });
    return {...result, version: document.version, coverage: 'NVD所选' + feed.config.year + '编号年度的完整合并快照；基线与已校验官方修改源共同组成来源依据，保留各份原件和数据版本。新增' + added + '条、修改' + updated + '条、保留较新基线' + ignoredOlder + '条；产品候选与评分用于辅助真实组件证据，不独立确认资产漏洞，拒绝或撤回不会自动关闭已有资产风险。'};
  } finally { original.document.abort(); }
}
