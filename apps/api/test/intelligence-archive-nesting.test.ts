import {test} from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp, rm} from 'node:fs/promises';
import {join} from 'node:path';
import {tmpdir} from 'node:os';
import {withRawArchive, withNestedRawArchive, currentRawArchive, captureRawBuffer, onSourceAbort, cancelRawSource} from '../src/intelligence-artifacts';

test('multiple verified originals keep independent writers under one reserved task', async () => {
  const root = await mkdtemp(join(tmpdir(), 'selfguard-original-parts-'));
  try { await withRawArchive(2048, async () => {
    const originals = [];
    for (const value of [1, 2]) originals.push(await withNestedRawArchive(1024, async () => { await captureRawBuffer(Buffer.from(JSON.stringify({sourcePart: value}))); return currentRawArchive()!.artifact!; }));
    assert.notEqual(originals[0].sha256, originals[1].sha256); assert.equal(currentRawArchive()?.artifact, undefined); assert.equal(currentRawArchive()?.root, root);
    await captureRawBuffer(Buffer.from(JSON.stringify({verifiedParts: originals.map(row => row.sha256)}))); assert.ok(currentRawArchive()?.artifact);
    await assert.rejects(() => withNestedRawArchive(2049, async () => {}), /预算/);
  }, {root}); } finally { await rm(root, {recursive: true, force: true}); }
});
test('lease cancellation reaches an active nested source and cannot start another part', async () => {
  const root = await mkdtemp(join(tmpdir(), 'selfguard-cancel-parts-'));
  try { await withRawArchive(2048, async () => {
    let entered!: () => void; const started = new Promise<void>(resolve => { entered = resolve; });
    const nested = withNestedRawArchive(1024, async () => {
      let detach = () => {};
      try { return await new Promise((_resolve, reject) => { detach = onSourceAbort(reject); entered(); }); }
      finally { detach(); }
    });
    await started; cancelRawSource(Error('来源已停用'));
    await assert.rejects(nested, /已停用/);
    let called = false; await assert.rejects(() => withNestedRawArchive(1024, async () => { called = true; }), /已停用/); assert.equal(called, false);
  }, {root}); } finally { await rm(root, {recursive: true, force: true}); }
});
