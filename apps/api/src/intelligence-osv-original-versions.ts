import {spawn} from 'node:child_process';
import {isAbsolute} from 'node:path';
import {frames} from './intelligence-osv-archive';
import {onSourceAbort} from './intelligence-artifacts';
import {osvModifiedNanoseconds} from './intelligence-osv-index';

export async function readOsvOriginalVersions(file: string, sha256: string, crc32c: string, ubuntu: boolean) {
  if (!isAbsolute(file) || !/^[a-f0-9]{64}$/.test(sha256) || !/^[A-Za-z0-9+/]{6}==$/.test(crc32c)) throw Error('基线原包缺少固定摘要或CRC32C');
  const child = spawn(process.env.INTELLIGENCE_ARCHIVE_READER || '/opt/selfguard/intelligence-unzip', [file, sha256, ubuntu ? '--versions-ubuntu' : '--versions'], {stdio: ['ignore', 'pipe', 'pipe'], env: {PATH: '/usr/local/bin:/usr/bin:/bin', GOMAXPROCS: '1', GOMEMLIMIT: '512MiB'}, windowsHide: true});
  let startupError = false, diagnostic = '', marker: any;
  child.once('error', () => { startupError = true; });
  child.stderr!.on('data', part => { if (diagnostic.length < 8192) diagnostic += part.toString().slice(0, 8192 - diagnostic.length); });
  const closed = new Promise<number | null>(resolve => child.once('close', resolve));
  const timer = setTimeout(() => child.kill('SIGKILL'), 1800000);
  timer.unref();
  const detach = onSourceAbort(() => child.kill('SIGKILL')), records = new Map<string, string>();
  try {
    for await (const row of frames(child.stdout!)) {
      if (!row || typeof row !== 'object' || Array.isArray(row) || marker) throw Error('基线版本流记录或结束顺序无效');
      if (row.kind === 'complete') { marker = row; continue; }
      if (row.kind !== 'version' || typeof row.id !== 'string' || !/^[A-Za-z0-9][A-Za-z0-9._:+-]{0,199}$/.test(row.id) || typeof row.modified !== 'string' || records.has(row.id) || records.size >= 1000000) throw Error('基线版本流身份、类型或数量无效');
      osvModifiedNanoseconds(row.modified);
      records.set(row.id, row.modified);
    }
    if (await closed !== 0 || startupError) throw Error('基线原包校验或读取失败' + (diagnostic ? '：' + diagnostic.trim().slice(0, 300) : ''));
    if (!marker || !records.size || marker.entries !== records.size || marker.emittedEntries !== records.size || !Number.isSafeInteger(marker.decodedBytes) || marker.decodedBytes < 1 || marker.decodedBytes > (ubuntu ? 12 : 4) * 1024 ** 3 || marker.sha256 !== sha256 || marker.crc32c !== crc32c) throw Error('基线原包未取得完整数量、摘要与CRC32C证明');
    return {records, entries: marker.entries as number, decodedBytes: marker.decodedBytes as number, sha256, crc32c};
  } finally {
    clearTimeout(timer);
    detach();
    if (child.exitCode === null) { child.kill('SIGKILL'); await closed; }
  }
}
