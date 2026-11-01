export function snapshotDownloads(row:any):{id:string;encoding:string;label:string}[]{
 if(!row.artifactSha256||!['COMPLETE','UNCHANGED'].includes(row.status))return [];
 const sync=row.sourceManifest?.sync||{},nvd=String(sync.strategy||'').startsWith('NVD_');
 const items=[{id:row.id,encoding:row.artifact?.encoding||'GZIP_JSON',label:sync.mode==='UNCHANGED'?'下载更新收据':nvd?'下载修改源原件':sync.packageFormat?'下载增量原件包':'下载原始数据'}];
 if(sync.baseSnapshotId)items.push({id:sync.baseSnapshotId,encoding:nvd?'GZIP_JSON':'ZIP',label:nvd?'下载基线更新原件':'下载基线原包'});
 if(nvd&&sync.comparedSnapshotId&&sync.comparedSnapshotId!==sync.baseSnapshotId)items.push({id:sync.comparedSnapshotId,encoding:'GZIP_JSON',label:'下载当前有效修改源'});
 if(nvd&&sync.annualSnapshotId)items.push({id:sync.annualSnapshotId,encoding:'GZIP_JSON',label:'下载年度原包'});
 return items;
}
export function snapshotUpdateLines(row:any):string[]{
 const sync=row.sourceManifest?.sync||{},merge=row.sourceManifest?.nvdMerge;
 const result=[({FULL:sync.strategy==='NVD_FULL_WITH_MODIFIED'?'年度与修改源完整合并':'完整刷新',DELTA:'增量合并',UNCHANGED:'来源内容未变化'} as Record<string,string>)[sync.mode]||'历史方式未记录'];
 if(merge)result.push(`所选年度：新增 ${merge.added} · 修改 ${merge.updated} · 撤回 ${merge.withdrawn}`,`修改源 ${merge.sourceRecords} 条，属于本年度 ${merge.selectedYearRecords} 条`);
 else if(sync.mode==='DELTA')result.push(`相对完整基线：新增 ${sync.added} · 修改 ${sync.updated}`,`撤回 ${sync.withdrawn} · 未纳入所选范围 ${sync.scopeExcluded}`);
 if(sync.mode==='FULL'&&sync.reason){const reason:Record<string,string>={NO_COMPATIBLE_COMPLETE_BASELINE:'首次建立或重新建立完整基线',SELECTED_COMPLETE_REFRESH:'按所选方式完整刷新',BASELINE_OLDER_THAN_SEVEN_DAYS:'完整基线已满7天',COVERAGE_WINDOW_WILL_EXPIRE:'修改源覆盖窗口即将超出',PREVIOUS_UPDATE_NO_LONGER_IN_MODIFIED_SOURCE:'先前修改已离开修改源窗口',BASELINE_RECORD_FINGERPRINTS_INCOMPLETE:'旧基线缺少完整记录指纹',CHANGE_BYTES_EXCEED_16MIB:'变化原文超过16MiB'};result.push(reason[sync.reason]||'更新范围不适合直接增量，已重新核验完整来源');}
 return result;
}
