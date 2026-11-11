const {test} = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const {spawnSync} = require('node:child_process');
const {calculateCapacity} = require('./observability-capacity.cjs');

const input = {
  dailyAccessCount: 1_000_000, recordBytesPerAccess: 1000,
  requestBytesPerAccess: 0, responseBytesPerAccess: 20_000,
  retentionDays: 7, dailyPinnedPacketBytes: 0, evidenceCopies: 1,
  dailyIndexBytes: 0, indexRetentionDays: 90, indexCopies: 1, bufferBytes: 0,
};

test('retains complete responses rather than charging only audit log rows', () => {
  assert.deepEqual(calculateCapacity(input), {
    dailyBusinessBytes: 21_000_000_000, retainedBusinessBytes: 147_000_000_000,
    retainedPinnedPacketBytes: 0, evidenceBytesWithCopies: 147_000_000_000,
    indexBytesWithCopies: 0, bufferBytes: 0, totalBytes: 147_000_000_000,
  });
  assert.equal(calculateCapacity({...input, responseBytesPerAccess: 0}).totalBytes, 7_000_000_000);
  assert.equal(calculateCapacity({...input, responseBytesPerAccess: 1_000_000}).totalBytes, 7_007_000_000_000);
});

test('counts pinned packets, independent index retention, copies and local buffer exactly once', () => {
  assert.deepEqual(calculateCapacity({
    ...input, dailyAccessCount: 10, recordBytesPerAccess: 2,
    requestBytesPerAccess: 3, responseBytesPerAccess: 5,
    dailyPinnedPacketBytes: 50, evidenceCopies: 2,
    dailyIndexBytes: 20, indexRetentionDays: 90, indexCopies: 3, bufferBytes: 17,
  }), {
    dailyBusinessBytes: 100, retainedBusinessBytes: 700, retainedPinnedPacketBytes: 350,
    evidenceBytesWithCopies: 2100, indexBytesWithCopies: 5400, bufferBytes: 17, totalBytes: 7517,
  });
});

test('accepts explicit zero traffic without inventing evidence or copies', () => {
  assert.equal(calculateCapacity({...input, dailyAccessCount: 0}).totalBytes, 0);
});

test('rejects missing and unknown fields instead of silently estimating with defaults', () => {
  const {responseBytesPerAccess, ...missing} = input;
  for (const invalid of [missing, {...input, password: 'synthetic-secret'}, null, [], 'input']) {
    assert.throws(() => calculateCapacity(invalid));
  }
});

test('rejects invalid numbers in every capacity dimension', () => {
  for (const field of Object.keys(input)) {
    for (const value of [-1, 0.1, NaN, Infinity, -Infinity, Number.MAX_SAFE_INTEGER + 1, '7', null, true]) {
      assert.throws(() => calculateCapacity({...input, [field]: value}), field);
    }
  }
  for (const field of ['retentionDays', 'evidenceCopies', 'indexRetentionDays', 'indexCopies']) {
    assert.throws(() => calculateCapacity({...input, [field]: 0}), field);
  }
});

test('rejects overflow even when each supplied number is safe', () => {
  for (const invalid of [
    {...input, dailyAccessCount: Number.MAX_SAFE_INTEGER},
    {...input, requestBytesPerAccess: Number.MAX_SAFE_INTEGER},
    {...input, dailyPinnedPacketBytes: Number.MAX_SAFE_INTEGER},
    {...input, evidenceCopies: Number.MAX_SAFE_INTEGER},
    {...input, dailyIndexBytes: Number.MAX_SAFE_INTEGER},
    {...input, bufferBytes: Number.MAX_SAFE_INTEGER},
  ]) assert.throws(() => calculateCapacity(invalid), /safe integer/i);
});

test('keeps the exact safe-integer boundary without rounding', () => {
  assert.equal(calculateCapacity({...input, dailyAccessCount: 0, bufferBytes: Number.MAX_SAFE_INTEGER}).totalBytes, Number.MAX_SAFE_INTEGER);
});

test('CLI prints only a valid calculation and rejects input errors without exposing contents', t => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sg-capacity-'));
  t.after(() => fs.rmSync(dir, {recursive: true, force: true}));
  const source = path.join(dir, 'input.json');
  const script = path.join(__dirname, 'observability-capacity.cjs');
  const run = args => spawnSync(process.execPath, [script, ...args], {encoding: 'utf8'});
  fs.writeFileSync(source, JSON.stringify(input));
  const good = run([source]);
  assert.equal(good.status, 0, good.stderr);
  assert.equal(JSON.parse(good.stdout).totalBytes, 147_000_000_000);
  fs.writeFileSync(source, '{"synthetic-secret":');
  for (const bad of [run([source]), run([source + '.missing']), run([]), run([source, 'unexpected'])]) {
    assert.notEqual(bad.status, 0);
    assert.equal(bad.stdout, '');
    assert.ok(bad.stderr.trim());
    assert.doesNotMatch(bad.stderr, /synthetic-secret/);
  }
  fs.writeFileSync(source, JSON.stringify({...input, password: 'synthetic-secret'}));
  assert.doesNotMatch(run([source]).stderr, /synthetic-secret/);
});

test('CLI rejects non-regular input without waiting for a FIFO writer', {skip: process.platform === 'win32'}, t => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sg-capacity-fifo-'));
  t.after(() => fs.rmSync(dir, {recursive: true, force: true}));
  const source = path.join(dir, 'input.pipe');
  const created = spawnSync('mkfifo', [source], {encoding: 'utf8'});
  assert.equal(created.status, 0, created.stderr);
  const result = spawnSync(process.execPath, [path.join(__dirname, 'observability-capacity.cjs'), source], {encoding: 'utf8', timeout: 1500});
  assert.equal(result.error, undefined, 'non-regular input must not hang the CLI');
  assert.notEqual(result.status, 0);
  assert.equal(result.stdout, '');
});
