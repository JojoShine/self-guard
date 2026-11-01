import {osvModifiedNanoseconds, type OsvModifiedEntry} from './intelligence-osv-index';

// This compares verified original timestamps, never database Date columns.
// Scope, normalizer and immutable baseline binding remain the sync caller's job.
export function planOsvDelta(baseline: ReadonlyMap<string, string> | null, index: {records: ReadonlyMap<string, OsvModifiedEntry>}) {
  const counts = {baselineRecords: baseline?.size || 0, indexRecords: index.records.size};
  const full = (reason: 'NO_BASELINE' | 'INDEX_REMOVED_IDENTITIES' | 'BASELINE_TIMESTAMP_UNSUPPORTED' | 'INDEX_OLDER_THAN_BASELINE' | 'CHANGE_BATCH_EXCEEDS_BUDGET') => ({...counts, mode: 'FULL' as const, reason});
  if (!baseline?.size) return full('NO_BASELINE');
  // A missing index entry can be an ecosystem move or a withdrawn record. It
  // cannot silently turn into a deletion in a partially reconstructed snapshot.
  for (const id of baseline.keys()) if (!index.records.has(id)) return full('INDEX_REMOVED_IDENTITIES');
  const added: string[] = [], updated: string[] = [];
  let unchangedRecords = 0;
  for (const [id, row] of index.records) {
    const original = baseline.get(id);
    if (original === undefined) added.push(id);
    else {
      let previous: bigint;
      try { previous = osvModifiedNanoseconds(original); }
      catch { return full('BASELINE_TIMESTAMP_UNSUPPORTED'); }
      if (row.modifiedNanoseconds < previous) return full('INDEX_OLDER_THAN_BASELINE');
      if (row.modifiedNanoseconds > previous) updated.push(id);
      else unchangedRecords++;
    }
    if (added.length + updated.length > 500) return full('CHANGE_BATCH_EXCEEDS_BUDGET');
  }
  if (!added.length && !updated.length) return {...counts, mode: 'UNCHANGED' as const, unchangedRecords};
  return {...counts, mode: 'DELTA' as const, added: added.sort(), updated: updated.sort(), unchangedRecords};
}
