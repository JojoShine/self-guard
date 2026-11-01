import {normalizeIntelligence} from './intelligence-normalize';
import type {OsvEcosystem} from './intelligence-osv-archive';

export function osvEcosystemContains(ecosystem: OsvEcosystem, value: string) {
  return value === ecosystem || ['Rocky Linux', 'Ubuntu'].includes(ecosystem) && value.startsWith(ecosystem + ':');
}

export function normalizeOsvScopedRecord(raw: unknown, ecosystem: OsvEcosystem, release?: string) {
  if (ecosystem === 'Ubuntu' && !['22.04', '24.04'].includes(release || '')) throw Error('Ubuntu需要明确并固定受支持的发行范围');
  let record;
  try { record = normalizeIntelligence('OSV', raw, ecosystem === 'Ubuntu' ? 'UBUNTU_ARCHIVE' : undefined).records[0]; }
  catch (error) {
    const id = typeof (raw as any)?.id === 'string' ? (raw as any).id.slice(0, 200) : '未提供编号';
    throw Error('OSV通告 ' + id + ' 无法归一化：' + (error instanceof Error ? error.message : '无效来源内容'));
  }
  if (record.affected.length && !record.affected.some(row => typeof row.ecosystem === 'string' && osvEcosystemContains(ecosystem, row.ecosystem) || row.kind === 'OSV_UNSCOPED')) throw Error('OSV归档通告不属于所选生态');
  record.metadata = {...record.metadata, osvOriginalVersion: {modified: (raw as any).modified, withdrawn: (raw as any).withdrawn ?? null}};
  if (ecosystem === 'Ubuntu') {
    const original = record.affected.length;
    record.affected = record.affected.filter(row => row.ecosystem === 'Ubuntu:' + release || row.kind === 'OSV_UNSCOPED');
    if (!record.affected.length) return null;
    record.packages = [...new Set(record.affected.filter(row => typeof row.package === 'string').map(row => row.ecosystem + ':' + row.package))];
    record.purpose = record.metadata.vendorAdvisory ? 'METADATA' : record.packages.length ? 'PACKAGE' : 'CANDIDATE';
    record.metadata = {...record.metadata, archiveScope: {release, excludedAffected: original - record.affected.length}};
  }
  return record;
}
