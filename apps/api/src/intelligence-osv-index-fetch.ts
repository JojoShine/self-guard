import type {request} from 'node:https';
import {openOfficialStream} from './intelligence-stream-fetch';
import {osvEcosystems, type OsvEcosystem} from './intelligence-osv-archive';
import {readOsvModifiedIndex} from './intelligence-osv-index';
import {recordSourceManifest} from './intelligence-artifacts';

export async function fetchOsvModifiedIndex(ecosystem: OsvEcosystem, transport?: typeof request) {
  if (!osvEcosystems.includes(ecosystem)) throw Error('OSV更新索引生态不在支持范围');
  const url = new URL('https://storage.googleapis.com/osv-vulnerabilities/' + encodeURIComponent(ecosystem) + '/modified_id.csv');
  const stream = await openOfficialStream(url, 'OSV_INDEX', transport), original: Buffer[] = [];
  try {
    async function* retain() {
      for await (const chunk of stream.chunks) {
        original.push(Buffer.from(chunk));
        yield chunk;
      }
    }
    const result = await readOsvModifiedIndex(retain());
    if (!stream.generation || stream.generation === '0' || result.bytes !== stream.storedBytes || result.crc32c !== stream.crc32c || result.sourceSha256 !== stream.sourceSha256) throw Error('OSV更新索引对象版本、大小或CRC32C不一致');
    recordSourceManifest('osvIndex', {ecosystem, sourceUrl: url.href, generation: stream.generation, sourceSha256: result.sourceSha256, crc32c: result.crc32c, bytes: result.bytes, records: result.records.size, descending: result.descending, readerVersion: 'selfguard-osv-index-v1'});
    return {...result, generation: stream.generation, sourceUrl: url.href, original: Buffer.concat(original)};
  } finally { stream.abort(); }
}
