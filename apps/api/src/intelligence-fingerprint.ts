import {createHash} from 'node:crypto';
import type {IntelligenceRecord} from './intelligence-normalize';

function canonical(value: any): string {
  if (Array.isArray(value)) return '[' + value.map(canonical).join(',') + ']';
  if (value && typeof value === 'object') return '{' + Object.keys(value).sort().map(key => JSON.stringify(key) + ':' + canonical(value[key])).join(',') + '}';
  return JSON.stringify(value);
}

export function intelligenceRecordFingerprint(record: IntelligenceRecord) {
  const {rawSha256, ...facts} = record;
  return createHash('sha256').update(canonical(facts)).digest('hex');
}

export function intelligenceSnapshotFingerprint(hashes: readonly (string | null)[]) {
  if (!hashes.length || hashes.some(hash => typeof hash !== 'string' || !/^[a-f0-9]{64}$/.test(hash))) throw Error('情报快照缺少完整记录指纹');
  return createHash('sha256').update([...hashes].sort().join('\n')).digest('hex');
}
