import {isDeepStrictEqual} from 'node:util';
import {ConflictException} from '@nestjs/common';
import {currentRawArchive, withNestedRawArchive, registerIntelligenceArtifact, intelligenceNormalizerVersion, recordSourceManifest, captureRawBuffer} from './intelligence-artifacts';
import {fetchNvdAnnualFeed, fetchNvdModifiedFeed, fetchNvdModifiedMeta, nvdTimeNanoseconds} from './intelligence-nvd-feed';
import {stageNvdAnnualSnapshot} from './intelligence-nvd-stage';
import {downloadNvdModifiedPart} from './intelligence-nvd-part';
import {readNvdOriginalVersions, nvdCoveredThrough} from './intelligence-nvd-original';
import {mergeNvdVersionSets, planNvdIncrement, assertNvdModifiedWindow, type NvdVersionSet} from './intelligence-nvd-delta-plan';
import type {NvdMergeDocument} from './intelligence-nvd-delta-stage';
import type {Db} from './db';

const modifiedUrl = 'https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-modified.json.gz';
type Dependencies = {fetchAnnual: typeof fetchNvdAnnualFeed; fetchModified: typeof fetchNvdModifiedFeed; fetchMeta: typeof fetchNvdModifiedMeta};
const defaults: Dependencies = {fetchAnnual: fetchNvdAnnualFeed, fetchModified: fetchNvdModifiedFeed, fetchMeta: fetchNvdModifiedMeta};
const digest = (value: unknown) => typeof value === 'string' && /^[a-f0-9]{64}$/.test(value);
function compatible(snapshot: any, feed: any) {
  return snapshot?.feedId === feed.id && snapshot.status === 'COMPLETE' && snapshot.normalizerVersion === intelligenceNormalizerVersion && isDeepStrictEqual(snapshot.config, feed.config) && snapshot.artifact?.encoding === 'GZIP_JSON' && digest(snapshot.sourceSha256) && digest(snapshot.artifactSha256) && digest(snapshot.contentSha256);
}
export async function holdNvdLease(tx: any, feed: any, leaseId: string, current: any) {
  const held = await tx.vulnerabilityFeed.updateMany({where: {id: feed.id, leaseId, enabled: true, configHash: feed.configHash, currentSnapshotId: current?.id || null, leaseUntil: {gt: new Date()}}, data: {leaseUntil: new Date(Date.now() + 300000)}});
  if (!held.count) throw new ConflictException('NVD来源停用、范围更改、快照变化或租约过期');
}
function binding(snapshot: any) { return {snapshotId: snapshot.id, artifactSha256: snapshot.artifactSha256, contentSha256: snapshot.contentSha256}; }
async function roots(db: Db, feed: any, current: any) {
  if (!compatible(current, feed)) return null;
  const sync = current.sourceManifest?.sync;
  const root = sync?.strategy === 'NVD_FULL_WITH_MODIFIED' ? current : sync?.strategy === 'NVD_MODIFIED' ? await db.vulnerabilitySnapshot.findFirst({where: {id: sync.baseSnapshotId, feedId: feed.id, status: 'COMPLETE'}, include: {artifact: true}}) : null;
  if (!compatible(root, feed)) return null;
  if (root.id !== current.id && (root.artifactSha256 !== sync.baseArtifactSha256 || root.contentSha256 !== sync.baseContentSha256)) throw Error('NVD完整基线摘要与当前来源记录不一致');
  const rootSync = root.sourceManifest?.sync;
  if (rootSync?.strategy !== 'NVD_FULL_WITH_MODIFIED') throw Error('NVD完整基线缺少年度与修改源组成');
  const annual = await db.vulnerabilitySnapshot.findFirst({where: {id: rootSync.annualSnapshotId, feedId: feed.id, status: 'COMPLETE'}, include: {artifact: true}});
  if (!annual || !compatible(annual, feed) || annual.artifactSha256 !== rootSync.annualArtifactSha256 || annual.contentSha256 !== rootSync.annualContentSha256 || (annual.sourceManifest as any)?.sync?.parentSnapshotId !== root.id) throw Error('NVD完整基线的年度原件已缺失或摘要不符');
  return {root, annual};
}
async function versionsOf(root: any, annual: any, year: number) {
  const annualVersions = await readNvdOriginalVersions(annual, year, 'ANNUAL'), changes = await readNvdOriginalVersions(root, year, 'MODIFIED');
  return mergeNvdVersionSets(annualVersions, changes);
}
function rejectRegression(accepted: NvdVersionSet | undefined, next: NvdVersionSet) {
  if (!accepted) return;
  if (nvdTimeNanoseconds(next.coveredThrough) < nvdTimeNanoseconds(accepted.coveredThrough)) throw Error('NVD修改源比已接受版本更旧，拒绝回退');
  for (const [id, previous] of accepted.records) {
    const modified = next.records.get(id);
    if (modified === undefined || nvdTimeNanoseconds(modified) < nvdTimeNanoseconds(previous)) throw Error('NVD完整刷新缺少已接受通告或版本回退，保留有效快照');
  }
}
export async function prepareNvdMerge(db: Db, feed: any, current: any, snapshotId: string, leaseId: string, dependencies: Dependencies = defaults) {
  const parent = currentRawArchive(); if (!parent || parent.writer || feed.provider !== 'NVD' || feed.config?.mode !== 'YEAR') throw Error('NVD完整合并必须在独立受管来源任务中执行');
  await db.$transaction(tx => holdNvdLease(tx, feed, leaseId, current));
  const previous = await roots(db, feed, current);
  let rootVersions: NvdVersionSet | undefined, accepted: NvdVersionSet | undefined;
  if (previous) {
    rootVersions = await versionsOf(previous.root, previous.annual, feed.config.year);
    accepted = current.id === previous.root.id ? rootVersions : mergeNvdVersionSets(rootVersions, await readNvdOriginalVersions(current, feed.config.year, 'MODIFIED'));
    const meta = await dependencies.fetchMeta();
    assertNvdModifiedWindow(meta.lastModifiedDate);
    const rootAge = BigInt(Date.now()) * 1000000n - nvdTimeNanoseconds(rootVersions.coveredThrough);
    if (rootAge <= 7n * 86400n * 1000000000n && meta.sha256 === current.sourceSha256 && nvdTimeNanoseconds(nvdCoveredThrough(meta, current.sourceManifest.nvdFeed.generatedAt)) === nvdTimeNanoseconds(accepted.coveredThrough)) {
      const metaProof = parent.manifest.nvdMeta;
      if (!metaProof) throw Error('NVD检查收据缺少本次官方元数据');
      const bytes = Buffer.from(JSON.stringify({format: 'selfguard-nvd-receipt-v1', year: feed.config.year, current: binding(current), base: binding(previous.root), annual: binding(previous.annual), meta: metaProof}));
      await captureRawBuffer(bytes); const artifact = parent.artifact!;
      recordSourceManifest('sync', {mode: 'UNCHANGED', strategy: 'NVD_META_RECEIPT', packageFormat: 'selfguard-nvd-receipt-v1', comparedSnapshotId: current.id, baseSnapshotId: previous.root.id, baseArtifactSha256: previous.root.artifactSha256, baseContentSha256: previous.root.contentSha256, annualSnapshotId: previous.annual.id, coveredThrough: accepted.coveredThrough});
      const document: NvdMergeDocument = {kind: 'NVD_MERGE', base: previous.root, current, modified: current, baseVersions: rootVersions, receiptOnly: true, version: current.version};
      return {document, sourceSha256: artifact.payloadSha256, sourceUrl: modifiedUrl.replace('.json.gz', '.meta')};
    }
    if (nvdTimeNanoseconds(meta.lastModifiedDate) < nvdTimeNanoseconds(accepted.coveredThrough)) throw Error('NVD修改源比已接受版本更旧，拒绝回退');
  }
  const part = await downloadNvdModifiedPart(feed, dependencies.fetchModified);
  assertNvdModifiedWindow(part.versions.coveredThrough);
  if (accepted && nvdTimeNanoseconds(part.versions.coveredThrough) < nvdTimeNanoseconds(accepted.coveredThrough)) throw Error('NVD修改源比已接受版本更旧，拒绝回退');
  const plan = previous ? planNvdIncrement(rootVersions!, accepted!, part.versions) : null;
  if (plan?.mode === 'REJECT') throw Error('NVD修改源通告版本回退，保留有效快照：' + plan.reason);
  let base = previous?.root, baseVersions = rootVersions, annual: any = previous?.annual, promoteAnnualId: string | undefined;
  const rebase = !previous || plan?.mode === 'REBASE';
  if (rebase) {
    const url = new URL('https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-' + feed.config.year + '.json.gz');
    annual = await db.$transaction(async tx => {
      await holdNvdLease(tx, feed, leaseId, current);
      return tx.vulnerabilitySnapshot.create({data: {feedId: feed.id, config: feed.config, sourceUrl: url.href, license: 'NVD公开数据；不代表NVD认证或背书', normalizerVersion: intelligenceNormalizerVersion, sourceManifest: {sync: {role: 'ANNUAL_COMPONENT', parentSnapshotId: snapshotId}}}});
    });
    annual = await withNestedRawArchive(Math.min(128 * 1024 * 1024, Math.floor(parent.reservedBytes / 2)), async () => {
      const fetched = await dependencies.fetchAnnual(url), staged = await stageNvdAnnualSnapshot(db, feed, annual.id, leaseId, fetched);
      recordSourceManifest('sync', {role: 'ANNUAL_COMPONENT', parentSnapshotId: snapshotId});
      return db.$transaction(async tx => {
        await holdNvdLease(tx, feed, leaseId, current); const artifact = await registerIntelligenceArtifact(tx, fetched.sourceSha256);
        if (!artifact) throw Error('NVD年度基线缺少完整原件');
        return tx.vulnerabilitySnapshot.update({where: {id: annual.id}, data: {...staged, sourceSha256: fetched.sourceSha256, artifactSha256: artifact.sha256, sourceManifest: currentRawArchive()!.manifest as any}, include: {artifact: true}});
      });
    });
    base = annual; baseVersions = await readNvdOriginalVersions(annual, feed.config.year, 'ANNUAL'); promoteAnnualId = annual.id;
    rejectRegression(accepted, mergeNvdVersionSets(baseVersions!, part.versions));
  }
  parent.artifact = part.snapshot.artifact;
  for (const [key, value] of Object.entries(part.snapshot.sourceManifest)) recordSourceManifest(key, value);
  recordSourceManifest('sync', {mode: rebase ? 'FULL' : 'DELTA', strategy: rebase ? 'NVD_FULL_WITH_MODIFIED' : 'NVD_MODIFIED', reason: plan?.reason || 'NO_COMPATIBLE_COMPLETE_BASELINE', ...(!rebase ? {baseSnapshotId: base.id, baseArtifactSha256: base.artifactSha256, baseContentSha256: base.contentSha256} : {}), annualSnapshotId: annual.id, annualArtifactSha256: annual.artifactSha256, annualContentSha256: annual.contentSha256, coveredThrough: part.versions.coveredThrough, sourceRecords: part.versions.totalRecords, selectedYearRecords: part.versions.records.size});
  const document: NvdMergeDocument = {kind: 'NVD_MERGE', base, current, modified: part.snapshot, baseVersions: baseVersions!, receiptOnly: false, version: 'NVD/' + feed.config.year + '@modified-' + part.versions.coveredThrough, ...(promoteAnnualId ? {promoteAnnualId} : {})};
  return {document, sourceSha256: part.snapshot.sourceSha256, sourceUrl: modifiedUrl};
}
export async function publishNvdAnnualComponent(tx: any, feedId: string, snapshotId: string, document: any) {
  if (document?.kind !== 'NVD_MERGE' || !document.promoteAnnualId) return;
  const component = await tx.vulnerabilitySnapshot.findFirst({where: {id: document.promoteAnnualId, feedId, status: 'STAGING'}});
  if (!component || component.sourceManifest?.sync?.role !== 'ANNUAL_COMPONENT' || component.sourceManifest.sync.parentSnapshotId !== snapshotId || !digest(component.contentSha256) || !digest(component.artifactSha256)) throw Error('NVD年度组成快照未完整确认，拒绝发布');
  await tx.vulnerabilitySnapshot.update({where: {id: component.id}, data: {status: 'COMPLETE', completedAt: new Date()}});
}
export async function failNvdAnnualComponents(tx: any, feedId: string, parentSnapshotId: string, reason: string) {
  await tx.vulnerabilitySnapshot.updateMany({where: {feedId, status: 'STAGING', sourceManifest: {path: ['sync', 'parentSnapshotId'], equals: parentSnapshotId}}, data: {status: 'FAILED', completedAt: new Date(), error: reason}});
}
