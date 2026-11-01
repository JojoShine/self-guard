import {it,expect} from 'vitest';
import {snapshotDownloads,snapshotUpdateLines} from './intelligence-presentation';
it('NVD evidence downloads retain gzip originals and bounded baseline references',()=>{
 const row={id:'delta',status:'COMPLETE',artifactSha256:'a',artifact:{encoding:'GZIP_JSON'},sourceManifest:{sync:{mode:'DELTA',strategy:'NVD_MODIFIED',baseSnapshotId:'root',annualSnapshotId:'annual'},nvdMerge:{added:1,updated:2,withdrawn:1,sourceRecords:100,selectedYearRecords:20}}};
 expect(snapshotDownloads(row)).toEqual([{id:'delta',encoding:'GZIP_JSON',label:'下载修改源原件'},{id:'root',encoding:'GZIP_JSON',label:'下载基线更新原件'},{id:'annual',encoding:'GZIP_JSON',label:'下载年度原包'}]);
 expect(snapshotUpdateLines(row)).toContain('修改源 100 条，属于本年度 20 条');
});
it('an unchanged receipt is distinguished from effective originals and failed snapshots offer no download',()=>{
 const row={id:'receipt',status:'UNCHANGED',artifactSha256:'a',sourceManifest:{sync:{mode:'UNCHANGED',strategy:'NVD_META_RECEIPT',baseSnapshotId:'root',comparedSnapshotId:'current',annualSnapshotId:'annual'}}};
 expect(snapshotDownloads(row).map(item=>item.label)).toEqual(['下载更新收据','下载基线更新原件','下载当前有效修改源','下载年度原包']);
 expect(snapshotDownloads({...row,status:'FAILED'})).toEqual([]);
});
it('OSV delta keeps the original ZIP base and explains a forced full refresh',()=>{
 expect(snapshotDownloads({id:'delta',status:'COMPLETE',artifactSha256:'a',sourceManifest:{sync:{mode:'DELTA',packageFormat:'selfguard-osv-delta-v1',baseSnapshotId:'base'}}})[1]).toEqual({id:'base',encoding:'ZIP',label:'下载基线原包'});
 expect(snapshotUpdateLines({sourceManifest:{sync:{mode:'FULL',reason:'BASELINE_OLDER_THAN_SEVEN_DAYS'}}})).toContain('完整基线已满7天');
});
