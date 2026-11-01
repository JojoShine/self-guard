import {test} from 'node:test';
import assert from 'node:assert/strict';
import {normalizeOsvScopedRecord} from '../src/intelligence-osv-scoped';

const affected = (ecosystem: string) => ({package: {ecosystem, name: 'example'}, ranges: [{type: 'ECOSYSTEM', events: [{introduced: '0'}, {fixed: '2.0-1'}]}]});
const base = {id: 'UBUNTU-CVE-2026-12345', modified: '2026-10-31T12:00:00.123456789Z'};
test('full and changed Ubuntu records use exactly the same selected standard release', () => {
  const record = normalizeOsvScopedRecord({...base, affected: [affected('Ubuntu:24.04:LTS'), affected('Ubuntu:Pro:24.04:LTS'), affected('Ubuntu:22.04:LTS')]}, 'Ubuntu', '24.04')!;
  assert.equal(record.modifiedAt, '2026-10-31T12:00:00.123Z'); assert.deepEqual(record.metadata.osvOriginalVersion, {modified: base.modified, withdrawn: null}); assert.deepEqual(record.packages, ['Ubuntu:24.04:example']);
  assert.equal(record.affected.length, 1); assert.equal(record.metadata.archiveScope.excludedAffected, 2);
  assert.equal(normalizeOsvScopedRecord({...base, affected: [affected('Ubuntu:22.04:LTS')]}, 'Ubuntu', '24.04'), null);
  assert.throws(() => normalizeOsvScopedRecord({...base, affected: []}, 'Ubuntu'), /发行范围/);
});
test('wrong ecosystems are rejected while unscoped and withdrawn facts stay explicit', () => {
  assert.throws(() => normalizeOsvScopedRecord({...base, affected: [affected('npm')]}, 'Go'), /不属于/);
  const unknown = normalizeOsvScopedRecord({...base, affected: [{ranges: []}]}, 'Go')!;
  assert.equal(unknown.affected[0].kind, 'OSV_UNSCOPED');
  const withdrawn = normalizeOsvScopedRecord({...base, affected: [], withdrawn: base.modified}, 'Go')!;
  assert.equal(withdrawn.withdrawnAt, '2026-10-31T12:00:00.123Z'); assert.deepEqual(withdrawn.metadata.osvOriginalVersion, {modified: base.modified, withdrawn: base.modified}); assert.equal(withdrawn.affected.length, 0);
});
