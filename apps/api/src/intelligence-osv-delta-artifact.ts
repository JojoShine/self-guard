import {createHash} from 'node:crypto';
import {createReadStream} from 'node:fs';
import {lstat} from 'node:fs/promises';
import {createGunzip} from 'node:zlib';
import {captureRawBuffer, onSourceAbort} from './intelligence-artifacts';
import {readOsvModifiedIndex, osvBytesCRC32C} from './intelligence-osv-index';
import {osvEcosystems, type OsvEcosystem} from './intelligence-osv-archive';
import type {fetchOsvModifiedIndex} from './intelligence-osv-index-fetch';
import type {fetchOsvOfficialRecord} from './intelligence-osv-record-fetch';

type Binding = {ecosystem: OsvEcosystem; release: string | null; baseSnapshotId: string; baseArtifactSha256: string; baseContentSha256: string};
type Index = Awaited<ReturnType<typeof fetchOsvModifiedIndex>>;
const sha = (bytes: Buffer) => createHash('sha256').update(bytes).digest('hex');
const limit = 120 * 1024 * 1024;
function validateBinding(value: Binding) {
  if (!osvEcosystems.includes(value.ecosystem) || !/^[a-f0-9-]{36}$/.test(value.baseSnapshotId) || !/^[a-f0-9]{64}$/.test(value.baseArtifactSha256) || !/^[a-f0-9]{64}$/.test(value.baseContentSha256) || (value.ecosystem === 'Ubuntu' ? !['22.04', '24.04'].includes(value.release || '') : value.release !== null)) throw Error('增量原件包基线或范围无效');
}
function original(value: unknown, maximum: number) {
  if (typeof value !== 'string' || value.length > Math.ceil(maximum / 3) * 4 || value.length % 4 !== 0 || /[^A-Za-z0-9+/=]/.test(value)) throw Error('增量原文字节编码或大小无效');
  const bytes = Buffer.from(value, 'base64');
  if (!bytes.length || bytes.length > maximum || bytes.toString('base64') !== value) throw Error('增量原文字节不完整');
  return bytes;
}
export async function captureOsvDeltaPackage(input: Binding & {index: Index; records: Awaited<ReturnType<typeof fetchOsvOfficialRecord>>[]; receiptOnly?: boolean}) {
  validateBinding(input);
  if (input.records.length > 500 || input.records.reduce((sum, row) => sum + row.original.length, 0) > 16 * 1024 * 1024) throw Error('增量通告原文超过500条或16MiB预算');
  const {index, records, receiptOnly, ...binding} = input;
  const bytes = Buffer.from(JSON.stringify({format: 'selfguard-osv-delta-v1', mode: receiptOnly ? 'CHECK' : 'DELTA', ...binding,
    index: {originalBase64: index.original.toString('base64'), sourceSha256: index.sourceSha256, crc32c: index.crc32c, generation: index.generation, sourceUrl: index.sourceUrl, records: index.records.size},
    records: records.map(row => ({id: row.document.id, modified: row.document.modified, originalBase64: row.original.toString('base64'), sourceSha256: row.sourceSha256, crc32c: row.crc32c, generation: row.generation, sourceUrl: row.sourceUrl})),
  }));
  if (bytes.length > limit) throw Error('增量原件包超过120MiB预算');
  await captureRawBuffer(bytes);
  return {sourceSha256: sha(bytes)};
}

export async function readOsvDeltaIndex(file: string, artifact: {sha256: string; size: number; sourceSha256: string}, binding: Binding) {
  validateBinding(binding);
  if (!/^[a-f0-9]{64}$/.test(artifact.sha256) || !/^[a-f0-9]{64}$/.test(artifact.sourceSha256)) throw Error('增量原件包摘要缺失');
  const info = await lstat(file);
  if (!info.isFile() || info.isSymbolicLink() || info.size !== artifact.size || info.size > limit) throw Error('增量原件包文件或大小无效');
  const input = createReadStream(file), compressedHash = createHash('sha256'), decodedHash = createHash('sha256'), unzip = createGunzip();
  const detach = onSourceAbort(error => { input.destroy(error); unzip.destroy(error); });
  input.on('data', part => compressedHash.update(part)); input.on('error', error => unzip.destroy(error)); input.pipe(unzip);
  const parts: Buffer[] = []; let size = 0;
  try {
    for await (const chunk of unzip) {
      size += chunk.length;
      if (size > limit) throw Error('增量原件包解压超过预算');
      const bytes = Buffer.from(chunk); parts.push(bytes); decodedHash.update(bytes);
    }
    if (compressedHash.digest('hex') !== artifact.sha256 || decodedHash.digest('hex') !== artifact.sourceSha256) throw Error('增量原件包摘要不一致');
    const decoded = JSON.parse(new TextDecoder('utf-8', {fatal: true}).decode(Buffer.concat(parts)));
    if (decoded?.format !== 'selfguard-osv-delta-v1' || decoded.mode !== 'DELTA' || Object.entries(binding).some(([key, value]) => decoded[key] !== value) || !Array.isArray(decoded.records) || decoded.records.length > 500) throw Error('增量原件包基线或范围不一致');
    const bytes = original(decoded.index?.originalBase64, 64 * 1024 * 1024);
    const index = await readOsvModifiedIndex((async function*() { yield bytes; })());
    if (index.sourceSha256 !== decoded.index.sourceSha256 || index.crc32c !== decoded.index.crc32c || index.records.size !== decoded.index.records || !/^[1-9][0-9]{0,29}$/.test(decoded.index.generation) || decoded.index.sourceUrl !== 'https://storage.googleapis.com/osv-vulnerabilities/' + encodeURIComponent(binding.ecosystem) + '/modified_id.csv') throw Error('增量包内原始索引校验失败');
    return {...index, generation: decoded.index.generation as string};
  } finally { detach(); input.destroy(); unzip.destroy(); }
}
