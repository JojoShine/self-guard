import {createHash} from 'node:crypto';
import {currentRawArchive, intelligenceNormalizerVersion, withNestedRawArchive} from './intelligence-artifacts';
import {fetchNvdModifiedFeed, isNvdFeedStream, nvdTimeNanoseconds, parseNvdMeta} from './intelligence-nvd-feed';
import {nvdCoveredThrough, nvdCveInYear} from './intelligence-nvd-original';

export async function downloadNvdModifiedPart(feed: any, fetcher: typeof fetchNvdModifiedFeed = fetchNvdModifiedFeed) {
  if (feed.provider !== 'NVD' || feed.config?.mode !== 'YEAR') throw Error('NVD修改源需要固定所选编号年度');
  nvdCveInYear('CVE-' + feed.config.year + '-0000', feed.config.year);
  const parent = currentRawArchive();
  if (!parent) throw Error('NVD修改源必须在受管原件任务内下载');
  const budget = Math.min(128 * 1024 * 1024, Math.floor(parent.reservedBytes / 2));
  return withNestedRawArchive(budget, async () => {
    const fetched = await fetcher(), document = fetched.document;
    if (!isNvdFeedStream(document) || document.scope !== 'MODIFIED') { if (isNvdFeedStream(document)) document.abort(); throw Error('仅能将官方修改源作为本段原件'); }
    const records = new Map<string, string>(), digests = new Map<string, string>(); let totalRecords = 0;
    try {
      for await (const raw of document.entries) {
        const cve = (raw as any).cve;
        if (typeof cve.lastModified !== 'string') throw Error('NVD修改源缺少精确修改时间');
        nvdTimeNanoseconds(cve.lastModified); totalRecords++;
        if (nvdCveInYear(cve.id, feed.config.year)) { records.set(cve.id, cve.lastModified); digests.set(cve.id, createHash('sha256').update(JSON.stringify(cve)).digest('hex')); }
      }
      document.validate();
      const scope = currentRawArchive()!, artifact = scope.artifact, proof: any = scope.manifest.nvdMeta;
      if (!artifact || artifact.encoding !== 'GZIP_JSON' || artifact.payloadSha256 !== fetched.sourceSha256 || typeof proof?.original !== 'string' || createHash('sha256').update(proof.original).digest('hex') !== proof.sha256OfMeta || parseNvdMeta(proof.original).sha256 !== fetched.sourceSha256) throw Error('NVD修改源未取得独立原件和官方元数据证明');
      const sourceUrl = 'https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-modified.json.gz';
      return {versions: {records, digests, totalRecords, coveredThrough: nvdCoveredThrough(document.meta, document.generatedAt!)}, snapshot: {feedId: feed.id, config: feed.config, sourceUrl, sourceSha256: fetched.sourceSha256, artifactSha256: artifact.sha256, artifact: {...artifact}, normalizerVersion: intelligenceNormalizerVersion, sourceManifest: {...scope.manifest}, recordCount: records.size}};
    } finally { document.abort(); }
  });
}
