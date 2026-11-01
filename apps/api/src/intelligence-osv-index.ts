import {createHash} from 'node:crypto';

export type OsvModifiedEntry = {id: string; modifiedAt: string; modifiedNanoseconds: bigint};

const crcTable = Uint32Array.from({length: 256}, (_, index) => {
  let value = index;
  for (let bit = 0; bit < 8; bit++) value = (value >>> 1) ^ (value & 1 ? 0x82f63b78 : 0);
  return value >>> 0;
});

export function osvBytesCRC32C(bytes: Uint8Array) {
  let crc = 0xffffffff;
  for (const byte of bytes) crc = crcTable[(crc ^ byte) & 255] ^ (crc >>> 8);
  const output = Buffer.alloc(4); output.writeUInt32BE((crc ^ 0xffffffff) >>> 0);
  return output.toString('base64');
}

export function osvModifiedNanoseconds(value: string): bigint {
  const match = /^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.(\d{1,9}))?(Z|[+-]\d{2}:\d{2})$/.exec(value);
  if (!match) throw Error('OSV更新索引修改时间格式无效');
  const calendar = Date.parse(match[1] + 'Z'), milliseconds = Date.parse(match[1] + match[3]);
  if (!Number.isFinite(calendar) || !Number.isFinite(milliseconds) || new Date(calendar).toISOString().slice(0, 19) !== match[1]) throw Error('OSV更新索引修改日期无效');
  return BigInt(milliseconds) * 1000000n + BigInt((match[2] || '').padEnd(9, '0'));
}

// Read the complete official per-ecosystem date,id index. Do not stop at a
// watermark: an interrupted index must never look like removed advisories.
export async function readOsvModifiedIndex(chunks: AsyncIterable<Uint8Array>) {
  const records = new Map<string, OsvModifiedEntry>(), hash = createHash('sha256');
  const decoder = new TextDecoder('utf-8', {fatal: true});
  let pending = '', bytes = 0, crc = 0xffffffff, descending = true, previous: bigint | undefined;
  function line(value: string) {
    if (value.endsWith('\r')) value = value.slice(0, -1);
    if (!value || value.length > 1024) throw Error('OSV更新索引存在空行或行长度超限');
    const parts = value.split(',');
    if (parts.length !== 2 || !/^[A-Za-z0-9][A-Za-z0-9._:+-]{0,199}$/.test(parts[1])) throw Error('OSV更新索引编号或列格式无效');
    const [modifiedAt, id] = parts, modifiedNanoseconds = osvModifiedNanoseconds(modifiedAt);
    if (records.has(id)) throw Error('OSV更新索引包含重复编号');
    if (records.size >= 1000000) throw Error('OSV更新索引超过一百万条限制');
    if (previous !== undefined && modifiedNanoseconds > previous) descending = false;
    previous = modifiedNanoseconds;
    records.set(id, {id, modifiedAt, modifiedNanoseconds});
  }
  for await (const chunk of chunks) {
    bytes += chunk.length;
    if (bytes > 64 * 1024 * 1024) throw Error('OSV更新索引超过64MiB限制');
    hash.update(chunk);
    for (const byte of chunk) crc = crcTable[(crc ^ byte) & 255] ^ (crc >>> 8);
    pending += decoder.decode(chunk, {stream: true});
    let end: number;
    while ((end = pending.indexOf('\n')) >= 0) {
      line(pending.slice(0, end));
      pending = pending.slice(end + 1);
    }
    if (pending.length > 1024) throw Error('OSV更新索引行长度超限');
  }
  pending += decoder.decode();
  if (pending) line(pending);
  if (!records.size) throw Error('OSV更新索引为空，不能作为有效范围');
  const checksum = Buffer.alloc(4);
  checksum.writeUInt32BE((crc ^ 0xffffffff) >>> 0);
  return {records, sourceSha256: hash.digest('hex'), crc32c: checksum.toString('base64'), bytes, descending};
}
