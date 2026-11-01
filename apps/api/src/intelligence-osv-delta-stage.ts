import {snapshotFingerprint,copySnapshotRecords} from './intelligence-snapshot-stage';
import {ConflictException} from '@nestjs/common';
import type {Db} from './db';
import {intelligenceRecordFingerprint} from './intelligence-fingerprint';
import {recordSourceManifest} from './intelligence-artifacts';
import {osvEcosystemContains} from './intelligence-osv-scoped';
import type {OsvDeltaDocument} from './intelligence-osv-delta';


export async function stageOsvDeltaSnapshot(db: Db, feed: any, snapshotId: string, leaseId: string, document: OsvDeltaDocument) {
  if (document.ecosystem !== feed.config.ecosystem || document.base.feedId !== feed.id || document.current.feedId !== feed.id) throw Error('增量通告与来源或生态不一致');
  async function held(tx: any) {
    const result = await tx.vulnerabilityFeed.updateMany({where: {id: feed.id, leaseId, enabled: true, configHash: feed.configHash, currentSnapshotId: document.current.id, leaseUntil: {gt: new Date()}}, data: {leaseUntil: new Date(Date.now() + 300000)}});
    if (!result.count) throw new ConflictException('来源停用、更改、当前快照变化或租约过期');
  }
  await db.$transaction(held);
  const baseline = await snapshotFingerprint(db, document.base.id, document.base.recordCount);
  if (baseline.contentSha256 !== document.base.contentSha256) throw Error('完整基线记录指纹不一致');
  if (document.receiptOnly) {
    const current = document.current.id === document.base.id ? baseline : await snapshotFingerprint(db, document.current.id, document.current.recordCount);
    if (current.contentSha256 !== document.current.contentSha256) throw Error('当前完整快照记录指纹不一致');
    return {...current, version: document.version, coverage: '完整官方更新索引核对通过，无新增修改；继续使用已发布的完整有效快照。' + (document.current.coverage || '')};
  }
  await copySnapshotRecords(db, document.base.id, snapshotId, baseline.recordCount, held);
  const seen = new Set<string>();
  for (const {id, record} of document.records) {
    if (seen.has(id) || seen.size >= 500 || record && record.externalId !== id) throw Error('增量通告重复、超限或身份不一致');
    seen.add(id);
    if (record && Buffer.byteLength(JSON.stringify(record)) > 4 * 1024 * 1024) throw Error('增量归一化通告超过单条预算');
    await db.$transaction(async tx => {
      await held(tx);
      if (!record) { await tx.vulnerabilityRecord.deleteMany({where: {snapshotId, externalId: id}}); return; }
      const row: any = {...record, snapshotId, normalizedSha256: intelligenceRecordFingerprint(record), modifiedAt: record.modifiedAt ? new Date(record.modifiedAt) : null, withdrawnAt: record.withdrawnAt ? new Date(record.withdrawnAt) : null};
      await tx.vulnerabilityRecord.upsert({where: {snapshotId_externalId: {snapshotId, externalId: id}}, create: row, update: row});
    }, {timeout: 30000});
  }
  const result = await snapshotFingerprint(db, snapshotId);
  const groups = await db.$queryRaw<{kind: string | null; ecosystem: string | null; count: number}[]>`
    SELECT a->>'kind' AS kind, a->>'ecosystem' AS ecosystem, count(*)::int AS count
    FROM "VulnerabilityRecord" r CROSS JOIN LATERAL jsonb_array_elements(r.affected) a
    WHERE r."snapshotId"=${snapshotId} AND r."withdrawnAt" IS NULL AND r.metadata->>'vendorAdvisory' IS DISTINCT FROM 'true'
    GROUP BY a->>'kind', a->>'ecosystem'`;
  const activeUnscopedAffected = groups.filter(row => row.kind === 'OSV_UNSCOPED').reduce((sum, row) => sum + row.count, 0), coveredEcosystems = [...new Set(groups.filter(row => row.ecosystem && osvEcosystemContains(document.ecosystem, row.ecosystem)).map(row => row.ecosystem!))].sort();
  recordSourceManifest('normalization', {activeUnscopedAffected, coveredEcosystems});
  await db.$transaction(async tx => { await held(tx); await tx.vulnerabilitySnapshot.update({where: {id: snapshotId}, data: {recordCount: result.recordCount}}); });
  return {...result, version: document.version, coverage: '以OSV官方完整原包为基线，核验官方更新索引和逐条通告后生成的完整合并快照，共' + result.recordCount + '条；原件包由平台封装并保留原文字节与基线引用。' + (activeUnscopedAffected ? '含' + activeUnscopedAffected + '项未提供软件身份的活动范围，不能证明此生态已完整检查。' : '') + '撤回和范围变化不自动关闭资产风险。'};
}
