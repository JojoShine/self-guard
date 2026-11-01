import {isDeepStrictEqual} from 'node:util';
import {artifactPath, currentRawArchive, intelligenceArtifactRoot, intelligenceNormalizerVersion, recordSourceManifest} from './intelligence-artifacts';
import {type OsvEcosystem} from './intelligence-osv-archive';
import {fetchOsvModifiedIndex} from './intelligence-osv-index-fetch';
import {fetchOsvOfficialRecord} from './intelligence-osv-record-fetch';
import {readOsvOriginalVersions} from './intelligence-osv-original-versions';
import {planOsvDelta} from './intelligence-osv-delta-plan';
import {captureOsvDeltaPackage, readOsvDeltaIndex} from './intelligence-osv-delta-artifact';
import {normalizeOsvScopedRecord} from './intelligence-osv-scoped';
import type {IntelligenceRecord} from './intelligence-normalize';
import {osvModifiedNanoseconds} from './intelligence-osv-index';

type Dependencies = {fetchIndex: typeof fetchOsvModifiedIndex; fetchRecord: typeof fetchOsvOfficialRecord; readVersions: typeof readOsvOriginalVersions};
export type OsvDeltaDocument = {kind: 'OSV_DELTA'; ecosystem: OsvEcosystem; base: any; current: any; records: {id: string; record: IntelligenceRecord | null}[]; receiptOnly: boolean; version: string};
const defaults: Dependencies = {fetchIndex: fetchOsvModifiedIndex, fetchRecord: fetchOsvOfficialRecord, readVersions: readOsvOriginalVersions};
function compatible(snapshot: any, feed: any) {
  return snapshot?.feedId === feed.id && snapshot.status === 'COMPLETE' && snapshot.normalizerVersion === intelligenceNormalizerVersion && isDeepStrictEqual(snapshot.config, feed.config) && /^[a-f0-9]{64}$/.test(snapshot.artifactSha256 || '') && /^[a-f0-9]{64}$/.test(snapshot.contentSha256 || '');
}
function binding(base: any, feed: any) {
  return {ecosystem: feed.config.ecosystem as OsvEcosystem, release: feed.config.release || null, baseSnapshotId: base.id, baseArtifactSha256: base.artifactSha256 as string, baseContentSha256: base.contentSha256 as string};
}
async function completeRoot(db: any, feed: any, current: any) {
  if (!compatible(current, feed)) return null;
  if (current.artifact?.encoding === 'ZIP') return current;
  const sync = current.sourceManifest?.sync;
  if (sync?.mode !== 'DELTA' || !/^[a-f0-9-]{36}$/.test(sync.baseSnapshotId || '')) return null;
  const base = await db.vulnerabilitySnapshot.findFirst({where: {id: sync.baseSnapshotId, feedId: feed.id, status: 'COMPLETE'}, include: {artifact: true}});
  return compatible(base, feed) && base.artifact?.encoding === 'ZIP' && base.artifactSha256 === sync.baseArtifactSha256 && base.contentSha256 === sync.baseContentSha256 ? base : null;
}
async function rootVersions(base: any, ecosystem: OsvEcosystem, dependencies: Dependencies) {
  const zip = base.sourceManifest?.zip;
  if (!zip?.officialCRC32CVerified || !/^[A-Za-z0-9+/]{6}==$/.test(zip.crc32c || '') || base.sourceSha256 !== base.artifactSha256) throw Error('完整基线原包缺少官方校验证明');
  return (await dependencies.readVersions(artifactPath(currentRawArchive()?.root || intelligenceArtifactRoot(), base.artifactSha256), base.sourceSha256, zip.crc32c, ecosystem === 'Ubuntu')).records;
}
async function acceptedVersions(current: any, base: any, feed: any, versions: Map<string, string>) {
  if (current.id === base.id) return versions;
  if (current.artifact?.encoding !== 'GZIP_JSON') throw Error('当前增量快照缺少可核验原件包');
  const index = await readOsvDeltaIndex(artifactPath(currentRawArchive()?.root || intelligenceArtifactRoot(), current.artifactSha256), {sha256: current.artifactSha256, size: current.artifact.size, sourceSha256: current.sourceSha256}, binding(base, feed));
  return new Map([...index.records].map(([id, row]) => [id, row.modifiedAt]));
}

export async function tryFetchOsvDelta(db: any, feed: any, current: any, dependencies: Dependencies = defaults) {
  const full = (reason: string) => { recordSourceManifest('sync', {mode: 'FULL', reason}); return null; };
  const base = await completeRoot(db, feed, current);
  if (!base) return full('NO_COMPATIBLE_COMPLETE_BASELINE');
  if (!base.completedAt || !Number.isFinite(new Date(base.completedAt).getTime()) || Date.now() - new Date(base.completedAt).getTime() > 7 * 86400000) return full('BASELINE_OLDER_THAN_SEVEN_DAYS');
  for (const snapshot of base.id === current.id ? [base] : [base, current]) {
    if (await db.vulnerabilityRecord.count({where: {snapshotId: snapshot.id}}) !== snapshot.recordCount || await db.vulnerabilityRecord.count({where: {snapshotId: snapshot.id, normalizedSha256: null}})) return full('BASELINE_RECORD_FINGERPRINTS_INCOMPLETE');
  }
  const versions = await rootVersions(base, feed.config.ecosystem, dependencies), accepted = await acceptedVersions(current, base, feed, versions), index = await dependencies.fetchIndex(feed.config.ecosystem);
  if (current.id !== base.id && BigInt(index.generation) < BigInt(current.sourceManifest?.osvIndex?.generation || '0')) throw Error('官方索引对象版本比当前已接受版本更旧，拒绝回退');
  const currentPlan = planOsvDelta(accepted, index);
  if (currentPlan.mode === 'FULL' && currentPlan.reason === 'INDEX_OLDER_THAN_BASELINE') throw Error('官方索引通告时间比当前已接受版本更旧，拒绝回退');
  if (currentPlan.mode === 'FULL') return full(currentPlan.reason);
  const plan = planOsvDelta(versions, index);
  if (plan.mode === 'FULL') return full(plan.reason);
  const receiptOnly = currentPlan.mode === 'UNCHANGED', originals: Awaited<ReturnType<typeof fetchOsvOfficialRecord>>[] = [], records: OsvDeltaDocument['records'] = [];
  let totalBytes = 0, withdrawn = 0, scopeExcluded = 0;
  if (!receiptOnly && plan.mode === 'DELTA') for (const id of [...plan.added, ...plan.updated]) {
    if (currentRawArchive()?.cancelled) throw currentRawArchive()!.cancelled;
    const row = index.records.get(id)!, fetched = await dependencies.fetchRecord(feed.config.ecosystem, id, row.modifiedAt);
    totalBytes += fetched.original.length;
    if (totalBytes > 16 * 1024 * 1024) return full('CHANGE_BYTES_EXCEED_16MIB');
    const record = normalizeOsvScopedRecord(fetched.document, feed.config.ecosystem, feed.config.release);
    if (fetched.document.withdrawn) withdrawn++;
    if (!record) scopeExcluded++;
    originals.push(fetched); records.push({id, record});
  }
  const fixed = binding(base, feed), captured = await captureOsvDeltaPackage({...fixed, index, records: originals, receiptOnly});
  recordSourceManifest('sync', {mode: receiptOnly ? 'UNCHANGED' : 'DELTA', ...fixed, baselineAt: new Date(base.completedAt).toISOString(), comparedSnapshotId: current.id, indexRecords: index.records.size, added: !receiptOnly && plan.mode === 'DELTA' ? plan.added.length : 0, updated: !receiptOnly && plan.mode === 'DELTA' ? plan.updated.length : 0, downloadedRecords: originals.length, withdrawn, scopeExcluded, originalBytes: totalBytes, packageFormat: 'selfguard-osv-delta-v1'});
  return {...captured, sourceUrl: index.sourceUrl, document: {kind: 'OSV_DELTA' as const, ecosystem: feed.config.ecosystem, base, current, records, receiptOnly, version: 'OSV/' + feed.config.ecosystem + '@index-' + index.generation} as OsvDeltaDocument};
}

// A full rebase must not silently roll back original versions already accepted
// through an incremental snapshot. Missing IDs remain an explicit full-scope change.
export async function verifyOsvFullRefresh(db: any, feed: any, current: any, dependencies: Dependencies = defaults) {
  const scope = currentRawArchive(), zip: any = scope?.manifest.zip, artifact = scope?.artifact;
  if (!artifact || artifact.encoding !== 'ZIP' || !zip?.officialCRC32CVerified) throw Error('完整刷新未取得官方原包证明');
  const next = (await dependencies.readVersions(artifactPath(scope!.root, artifact.sha256), artifact.payloadSha256, zip.crc32c, feed.config.ecosystem === 'Ubuntu')).records;
  const base = await completeRoot(db, feed, current);
  if (!base) return;
  const accepted = await acceptedVersions(current, base, feed, await rootVersions(base, feed.config.ecosystem, dependencies));
  for (const [id, modified] of accepted) if (next.has(id) && osvModifiedNanoseconds(next.get(id)!) < osvModifiedNanoseconds(modified)) throw Error('完整原包比当前已接受通告版本更旧，保留有效快照');
}
