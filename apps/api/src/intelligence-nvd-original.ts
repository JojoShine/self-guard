import {createReadStream} from 'node:fs';
import {lstat} from 'node:fs/promises';
import {createHash} from 'node:crypto';
import {createGunzip} from 'node:zlib';
import {artifactPath, currentRawArchive, intelligenceArtifactRoot, onSourceAbort} from './intelligence-artifacts';
import {nvdFeedDocument, nvdTimeNanoseconds, parseNvdMeta, type NvdFeedStream} from './intelligence-nvd-feed';
import type {OfficialByteStream} from './intelligence-stream-fetch';

export function nvdCveInYear(id: string, year: number) {
  const match = /^CVE-(\d{4})-\d{4,}$/.exec(id);
  if (!match || !Number.isInteger(year) || year < 2002 || year > new Date().getUTCFullYear()) throw Error('NVD年度或CVE编号无效');
  return year === 2002 ? Number(match[1]) <= 2002 : Number(match[1]) === year;
}
export async function openNvdOriginal(snapshot: any, year: number, scope: NvdFeedStream['scope']) {
  const proof = snapshot.sourceManifest?.nvdMeta, header = snapshot.sourceManifest?.nvdFeed;
  if (typeof proof?.original !== 'string' || Buffer.byteLength(proof.original) > 32768 || createHash('sha256').update(proof.original).digest('hex') !== proof.sha256OfMeta) throw Error('NVD原件缺少有效官方元数据原文');
  const meta = parseNvdMeta(proof.original), expectedUrl = 'https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-' + (scope === 'ANNUAL' ? year : 'modified') + '.json.gz';
  if (snapshot.sourceUrl !== expectedUrl || snapshot.sourceSha256 !== meta.sha256 || header?.scope !== scope || snapshot.artifact?.encoding !== 'GZIP_JSON' || !/^[a-f0-9]{64}$/.test(snapshot.artifactSha256 || '')) throw Error('NVD原件与来源范围或摘要不一致');
  const file = artifactPath(currentRawArchive()?.root || intelligenceArtifactRoot(), snapshot.artifactSha256), info = await lstat(file);
  if (!info.isFile() || info.isSymbolicLink() || info.size !== snapshot.artifact.size || info.size > 256 * 1024 * 1024) throw Error('NVD原件文件或大小无效');
  const input = createReadStream(file), decoded = createGunzip(), storedHash = createHash('sha256'), sourceHash = createHash('sha256');
  input.on('data', part => storedHash.update(part)); input.on('error', error => decoded.destroy(error)); input.pipe(decoded);
  const detach = onSourceAbort(error => { input.destroy(error); decoded.destroy(error); });
  const stream: OfficialByteStream = {chunks: undefined as any, sourceSha256: '', decodedBytes: 0, abort() { input.destroy(); decoded.destroy(); }};
  async function* chunks() {
    for await (const part of decoded) {
      stream.decodedBytes += part.length;
      if (stream.decodedBytes > meta.size) throw Error('NVD原件解压大小超过官方元数据');
      sourceHash.update(part); yield part;
    }
    if (storedHash.digest('hex') !== snapshot.artifactSha256) throw Error('NVD留存原件文件摘要不一致');
    stream.sourceSha256 = sourceHash.digest('hex');
  }
  stream.chunks = chunks();
  const fetched = nvdFeedDocument(meta, stream, scope, false), validate = fetched.document.validate, abort = fetched.document.abort;
  fetched.document.validate = () => {
    validate();
    if (header.generatedAt !== fetched.document.generatedAt || header.records !== fetched.document.recordsRead) throw Error('NVD原件记录数量或生成时间不一致');
  };
  fetched.document.abort = () => { detach(); abort(); };
  return fetched;
}
export function nvdCoveredThrough(meta: {lastModifiedDate: string}, generatedAt: string) {
  nvdTimeNanoseconds(generatedAt);
  if (!/(?:Z|[+-]\d{2}:\d{2})$/.test(meta.lastModifiedDate)) throw Error('NVD官方元数据修改时间缺少时区');
  nvdTimeNanoseconds(meta.lastModifiedDate);
  // The body generation timestamp has no timezone; only META provides a publisher-qualified feed version.
  return meta.lastModifiedDate;
}
export async function readNvdOriginalVersions(snapshot: any, year: number, scope: NvdFeedStream['scope']) {
  const fetched = await openNvdOriginal(snapshot, year, scope), records = new Map<string, string>(), digests = new Map<string, string>(); let totalRecords = 0;
  try {
    for await (const raw of fetched.document.entries) {
      const cve = (raw as any).cve;
      if (typeof cve.lastModified !== 'string') throw Error('NVD原件缺少原始修改时间');
      nvdTimeNanoseconds(cve.lastModified); totalRecords++;
      const belongs = nvdCveInYear(cve.id, year);
      if (scope === 'ANNUAL' && !belongs) throw Error('NVD年度原件包含其他编号年份');
      if (belongs) { records.set(cve.id, cve.lastModified); digests.set(cve.id, createHash('sha256').update(JSON.stringify(cve)).digest('hex')); }
    }
    fetched.document.validate();
    if (scope === 'ANNUAL' && snapshot.recordCount !== records.size) throw Error('NVD原件记录数量不一致');
    return {records, digests, totalRecords, coveredThrough: nvdCoveredThrough(fetched.document.meta, fetched.document.generatedAt!)};
  } finally { fetched.document.abort(); }
}
