import {expect,it} from 'vitest';
import {approveCompatibleLibrary,LibraryBulkApprovalError} from './probe-rule-library-bulk';
const snapshot={sha256:'a'.repeat(64),indexSha256:'b'.repeat(64)};
const entries=(length:number,variants=1)=>Array.from({length},(_,i)=>({id:'rule-'+i,compatible:true,variants}));
function catalog(items:ReturnType<typeof entries>,path:string,pointer=snapshot){const q=new URLSearchParams(path.split('?')[1]),page=Number(q.get('page'));return {snapshot:pointer,total:items.length,page,pageSize:100,items:items.slice((page-1)*100,page*100)}}
it('reads every pinned compatible page before approval and packs by variants rather than IDs',async()=>{
 const items=entries(201,3),calls:string[]=[],batches:string[][]=[];
 const result=await approveCompatibleLibrary(snapshot,items.length,async(path,body)=>{calls.push(path);if(!body)return catalog(items,path);const ids=body.ids as string[];batches.push(ids);return {created:ids.length*3,existing:0,skipped:0}});
 expect(calls.slice(0,3).map(v=>new URLSearchParams(v.split('?')[1]).get('page'))).toEqual(['1','2','3']);expect(batches.map(v=>v.length)).toEqual([166,35]);expect(batches.flat()).toEqual(items.map(v=>v.id));expect(result).toMatchObject({created:603,completedBatches:2,totalBatches:2,completedRules:201,totalVariants:603});
});
it('aborts changed snapshot or duplicate catalog before approving anything',async()=>{
 for(const kind of ['archive','index','duplicate']){let writes=0;const items=entries(101);if(kind==='duplicate')items[100].id=items[0].id;
 await expect(approveCompatibleLibrary(snapshot,101,async(path,body)=>{if(body){writes++;return {created:1,existing:0,skipped:0}}const page=Number(new URLSearchParams(path.split('?')[1]).get('page'));return catalog(items,path,page===2&&kind!=='duplicate'?{...snapshot,[kind==='index'?'indexSha256':'sha256']:'c'.repeat(64)}:snapshot)})).rejects.toThrow();expect(writes).toBe(0);
 }
});
it('stops later batches on failure and preserves only confirmed partial counts',async()=>{
 const items=entries(3,300);let writes=0;
 try{await approveCompatibleLibrary(snapshot,3,async(path,body)=>{if(!body)return catalog(items,path);writes++;if(writes===2)throw Error('网络中断');return {created:200,existing:90,skipped:10}});throw Error('expected failure')}catch(error){expect(error).toBeInstanceOf(LibraryBulkApprovalError);if(error instanceof LibraryBulkApprovalError){expect(error.progress).toMatchObject({created:200,existing:90,skipped:10,completedBatches:1,totalBatches:3,completedRules:1});expect(error.message).toContain('本批结果未确认')}}expect(writes).toBe(2);
});
it('rejects invalid or oversized variant counts before approval',async()=>{
 for(const variants of [0,501,5001]){let writes=0;await expect(approveCompatibleLibrary(snapshot,1,async(path,body)=>{if(body)writes++;return catalog(entries(1,variants),path)})).rejects.toThrow();expect(writes).toBe(0)}
 let writes=0;await expect(approveCompatibleLibrary(snapshot,11,async(path,body)=>{if(body)writes++;return catalog(entries(11,500),path)})).rejects.toThrow('5000');expect(writes).toBe(0);
});
it('stops when the pinned index changes between committed batches',async()=>{
 const items=entries(2,300);let writes=0;
 try{await approveCompatibleLibrary(snapshot,2,async(path,body)=>{if(!body)return catalog(items,path,writes?{...snapshot,indexSha256:'c'.repeat(64)}:snapshot);writes++;return {created:300,existing:0,skipped:0}});throw Error('expected failure')}catch(error){expect(error).toBeInstanceOf(LibraryBulkApprovalError);if(error instanceof LibraryBulkApprovalError){expect(error.progress.completedBatches).toBe(1);expect(error.progress.created).toBe(300);expect(error.message).toContain('版本已变化');expect(error.message).not.toContain('本批结果未确认')}}expect(writes).toBe(1);
});
