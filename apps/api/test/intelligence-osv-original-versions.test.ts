import {test} from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync, writeFileSync, rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {readOsvOriginalVersions} from '../src/intelligence-osv-original-versions';

const sha = 'a'.repeat(64), crc = 'pcYXxg==';
async function fixture(rows: unknown[], work: (file: string) => Promise<void>) {
  const directory = mkdtempSync(join(tmpdir(), 'osv-original-versions-')), file = join(directory, 'reader.cjs'), previous = process.env.INTELLIGENCE_ARCHIVE_READER;
  process.env.INTELLIGENCE_ARCHIVE_READER = process.execPath;
  writeFileSync(file, `if(!['--versions','--versions-ubuntu'].includes(process.argv[3]))process.exit(3);process.stdout.write(${JSON.stringify(rows.map(row => JSON.stringify(row)).join('\n') + '\n')});`);
  try { await work(file); }
  finally { if (previous === undefined) delete process.env.INTELLIGENCE_ARCHIVE_READER; else process.env.INTELLIGENCE_ARCHIVE_READER = previous; rmSync(directory, {recursive: true, force: true}); }
}
const version = {kind: 'version', id: 'GO-1', modified: '2026-10-31T00:00:00.123456789Z'};
const complete = {kind: 'complete', entries: 1, emittedEntries: 1, decodedBytes: 1234, sha256: sha, crc32c: crc};

test('baseline reader preserves the verified original timestamp rather than a database Date', async () => {
  await fixture([version, complete], async file => {
    const result = await readOsvOriginalVersions(file, sha, crc, false);
    assert.equal(result.records.get('GO-1'), '2026-10-31T00:00:00.123456789Z');
    assert.equal(result.entries, 1);
  });
});

test('baseline cannot complete with missing, mismatched or trailing proof', async () => {
  for (const rows of [
    [version], [version, {...complete, sha256: 'b'.repeat(64)}],
    [version, {...complete, crc32c: 'AAAAAA=='}], [version, {...complete, emittedEntries: 2}],
    [version, {...complete, entries: 2}], [version, version, {...complete, entries: 2, emittedEntries: 2}],
    [version, complete, version], [{...version, modified: 'not-a-date'}, complete],
  ]) await fixture(rows, async file => { await assert.rejects(() => readOsvOriginalVersions(file, sha, crc, false), /基线版本流|OSV更新索引|未取得完整/); });
});

test('Ubuntu baseline versions use the whole original archive profile', async () => {
  await fixture([{...version, id: 'UBUNTU-CVE-2026-1234'}, complete], async file => {
    assert.equal((await readOsvOriginalVersions(file, sha, crc, true)).records.size, 1);
  });
});
