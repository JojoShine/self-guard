import {nvdTimeNanoseconds} from './intelligence-nvd-feed';

export type NvdVersionSet = {records: ReadonlyMap<string, string>; digests: ReadonlyMap<string, string>; coveredThrough: string};
export function assertNvdModifiedWindow(coveredThrough: string, now = new Date()) {
  if (!Number.isFinite(now.getTime()) || BigInt(now.getTime()) * 1000000n - nvdTimeNanoseconds(coveredThrough) > 8n * 86400n * 1000000000n) throw Error('NVD修改源已超过8天覆盖窗口，保留原有效快照');
}
function validate(set: NvdVersionSet) {
  nvdTimeNanoseconds(set.coveredThrough);
  if (set.records.size > 1000000 || set.records.size !== set.digests.size) throw Error('NVD原件版本数量或通告指纹不完整');
  for (const [id, modified] of set.records) {
    if (!/^CVE-\d{4}-\d{4,}$/.test(id) || !/^[a-f0-9]{64}$/.test(set.digests.get(id) || '')) throw Error('NVD原件缺少完整通告身份或指纹');
    nvdTimeNanoseconds(modified);
  }
}
export function mergeNvdVersionSets(base: NvdVersionSet, changes: NvdVersionSet) {
  validate(base); validate(changes);
  const records = new Map(base.records), digests = new Map(base.digests); let added = 0, updated = 0, ignoredOlder = 0;
  for (const [id, modified] of changes.records) {
    const previous = base.records.get(id);
    if (previous !== undefined && nvdTimeNanoseconds(modified) < nvdTimeNanoseconds(previous)) { ignoredOlder++; continue; }
    if (previous === undefined) added++;
    else if (base.digests.get(id) !== changes.digests.get(id)) updated++;
    records.set(id, modified); digests.set(id, changes.digests.get(id)!);
  }
  return {records, digests, coveredThrough: changes.coveredThrough, added, updated, ignoredOlder};
}
export function planNvdIncrement(root: NvdVersionSet, accepted: NvdVersionSet, modified: NvdVersionSet, now = new Date()) {
  validate(root); validate(accepted); validate(modified);
  if (!Number.isFinite(now.getTime())) throw Error('NVD窗口检查时间无效');
  if (nvdTimeNanoseconds(modified.coveredThrough) < nvdTimeNanoseconds(accepted.coveredThrough)) return {mode: 'REJECT' as const, reason: 'OLDER_MODIFIED_SOURCE'};
  const rootEnd = nvdTimeNanoseconds(root.coveredThrough), maximumAge = 7n * 86400n * 1000000000n;
  if (nvdTimeNanoseconds(modified.coveredThrough) - rootEnd > maximumAge || BigInt(now.getTime()) * 1000000n - rootEnd > maximumAge) return {mode: 'REBASE' as const, reason: 'COVERAGE_WINDOW_WILL_EXPIRE'};
  for (const [id, previous] of accepted.records) {
    const original = root.records.get(id), wasUpdated = original === undefined || nvdTimeNanoseconds(previous) !== nvdTimeNanoseconds(original) || accepted.digests.get(id) !== root.digests.get(id);
    if (!wasUpdated) continue;
    const next = modified.records.get(id);
    if (next === undefined) return {mode: 'REBASE' as const, reason: 'PREVIOUS_UPDATE_NO_LONGER_IN_MODIFIED_SOURCE'};
    if (nvdTimeNanoseconds(next) < nvdTimeNanoseconds(previous)) return {mode: 'REJECT' as const, reason: 'ACCEPTED_RECORD_VERSION_WENT_BACK'};
  }
  return {mode: 'DELTA' as const, reason: 'VERIFIED_MODIFIED_WINDOW', ...mergeNvdVersionSets(root, modified)};
}
