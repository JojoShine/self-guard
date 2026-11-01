import type {request} from 'node:https';
import {openOfficialStream} from './intelligence-stream-fetch';
import {osvEcosystems, type OsvEcosystem} from './intelligence-osv-archive';
import {osvBytesCRC32C, osvModifiedNanoseconds} from './intelligence-osv-index';

export async function fetchOsvOfficialRecord(ecosystem: OsvEcosystem, id: string, modified: string, transport?: typeof request) {
  if (!osvEcosystems.includes(ecosystem) || !/^[A-Za-z0-9][A-Za-z0-9._:+-]{0,199}$/.test(id)) throw Error('OSV单条通告生态或编号无效');
  const expected = osvModifiedNanoseconds(modified), url = new URL('https://storage.googleapis.com/osv-vulnerabilities/' + encodeURIComponent(ecosystem) + '/' + encodeURIComponent(id) + '.json');
  const stream = await openOfficialStream(url, 'OSV_RECORD', transport), parts: Buffer[] = [];
  try {
    for await (const chunk of stream.chunks) parts.push(Buffer.from(chunk));
    const original = Buffer.concat(parts);
    if (!stream.generation || stream.generation === '0' || original.length !== stream.storedBytes || osvBytesCRC32C(original) !== stream.crc32c) throw Error('OSV单条通告对象版本、大小或CRC32C不一致');
    const document = JSON.parse(new TextDecoder('utf-8', {fatal: true}).decode(original));
    if (!document || Array.isArray(document) || document.id !== id || typeof document.modified !== 'string' || osvModifiedNanoseconds(document.modified) !== expected) throw Error('OSV单条通告身份或修改时间与完整索引不一致，保留旧快照');
    if (!Array.isArray(document.affected)) throw Error('OSV单条通告缺少明确的影响范围结构');
    const belongs = (value: string) => value === ecosystem || ['Ubuntu', 'Rocky Linux'].includes(ecosystem) && value.startsWith(ecosystem + ':');
    if (document.affected.length && !document.affected.some((row: any) => typeof row?.package?.ecosystem !== 'string' || belongs(row.package.ecosystem))) throw Error('OSV单条通告不属于所选生态');
    return {document, original, sourceUrl: url.href, sourceSha256: stream.sourceSha256, generation: stream.generation, crc32c: stream.crc32c!};
  } finally { stream.abort(); }
}
