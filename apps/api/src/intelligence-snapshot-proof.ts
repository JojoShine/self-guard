import {ConflictException} from '@nestjs/common';
import {isDeepStrictEqual} from 'node:util';
import type {SourceEvidence, SourcePart} from './intelligence-match';

const digest = (value: unknown): value is string => typeof value === 'string' && /^[a-f0-9]{64}$/.test(value);
function sourcePart(role: SourcePart['role'], snapshot: any): SourcePart {
  if (!digest(snapshot.sourceSha256) || !digest(snapshot.artifactSha256) || !digest(snapshot.contentSha256) || typeof snapshot.sourceUrl !== 'string') throw new ConflictException('组合来源缺少完整原件与内容摘要');
  return {role, snapshotId: snapshot.id, sourceSha256: snapshot.sourceSha256, artifactSha256: snapshot.artifactSha256, contentSha256: snapshot.contentSha256, sourceUrl: snapshot.sourceUrl};
}
export async function snapshotSourceProof(db: any, snapshot: any): Promise<Partial<SourceEvidence>> {
  const proof: Partial<SourceEvidence> = {
    ...(digest(snapshot.contentSha256) ? {contentSha256: snapshot.contentSha256} : {}),
    ...(digest(snapshot.artifactSha256) ? {artifactSha256: snapshot.artifactSha256} : {}),
    ...(typeof snapshot.normalizerVersion === 'string' ? {normalizerVersion: snapshot.normalizerVersion} : {}),
  };
  const sync = snapshot.sourceManifest?.sync;
  if (['NVD_FULL_WITH_MODIFIED', 'NVD_MODIFIED'].includes(sync?.strategy)) {
    const root = sync.strategy === 'NVD_FULL_WITH_MODIFIED' ? snapshot : await db.vulnerabilitySnapshot.findFirst({where: {id: sync.baseSnapshotId, feedId: snapshot.feedId, status: 'COMPLETE'}, include: {artifact: true}});
    const sameScope = (part: any) => part && part.feedId === snapshot.feedId && part.status === 'COMPLETE' && part.normalizerVersion === snapshot.normalizerVersion && isDeepStrictEqual(part.config, snapshot.config) && part.artifact?.encoding === 'GZIP_JSON';
    if (!sameScope(root) || root.sourceManifest?.sync?.strategy !== 'NVD_FULL_WITH_MODIFIED' || root.id !== snapshot.id && (root.artifactSha256 !== sync.baseArtifactSha256 || root.contentSha256 !== sync.baseContentSha256)) throw new ConflictException('NVD组合来源的完整基线缺失或摘要、范围不一致');
    const original = root.sourceManifest.sync, annual = await db.vulnerabilitySnapshot.findFirst({where: {id: original.annualSnapshotId, feedId: snapshot.feedId, status: 'COMPLETE'}, include: {artifact: true}});
    if (!sameScope(annual) || annual.artifactSha256 !== original.annualArtifactSha256 || annual.contentSha256 !== original.annualContentSha256 || annual.sourceManifest?.sync?.role !== 'ANNUAL_COMPONENT' || annual.sourceManifest.sync.parentSnapshotId !== root.id || sync.annualSnapshotId !== annual.id || sync.annualArtifactSha256 !== annual.artifactSha256 || sync.annualContentSha256 !== annual.contentSha256) throw new ConflictException('NVD组合来源的年度原件缺失或摘要、范围不一致');
    return {...proof, sourceParts: [sourcePart('ANNUAL_SOURCE', annual), sourcePart('BASELINE_UPDATES', root), ...(root.id !== snapshot.id ? [sourcePart('VERIFIED_DELTA', snapshot)] : [])]};
  }
  if (sync?.packageFormat !== 'selfguard-osv-delta-v1') return proof;
  if (sync.mode !== 'DELTA' || !/^[a-f0-9-]{36}$/.test(sync.baseSnapshotId || '')) throw new ConflictException('增量来源未记录有效完整基线');
  const base = await db.vulnerabilitySnapshot.findFirst({where: {id: sync.baseSnapshotId, feedId: snapshot.feedId, status: 'COMPLETE'}, include: {artifact: true}});
  if (!base || base.id !== sync.baseSnapshotId || base.feedId !== snapshot.feedId || base.status !== 'COMPLETE' || base.artifact?.encoding !== 'ZIP' || base.artifactSha256 !== sync.baseArtifactSha256 || base.contentSha256 !== sync.baseContentSha256 || base.normalizerVersion !== snapshot.normalizerVersion || !isDeepStrictEqual(base.config, snapshot.config)) throw new ConflictException('增量来源的完整基线已缺失或与固定范围、摘要不一致');
  return {...proof, sourceParts: [sourcePart('COMPLETE_BASE', base), sourcePart('VERIFIED_DELTA', snapshot)]};
}
