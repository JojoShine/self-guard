export type LibraryPointer={sha256:string;indexSha256:string};
export type BulkApprovalProgress={phase:'READING'|'APPROVING';completedRules:number;totalRules:number;totalVariants:number;completedBatches:number;totalBatches:number;created:number;existing:number;skipped:number};
type Request=(path:string,body?:Record<string,unknown>)=>Promise<unknown>;
type Entry={id:string;variants:number};
export class LibraryBulkApprovalError extends Error{
 constructor(message:string,readonly progress:BulkApprovalProgress){super(message);this.name='LibraryBulkApprovalError'}
}
function object(value:unknown):value is Record<string,unknown>{return typeof value==='object'&&value!==null&&!Array.isArray(value)}
function count(value:unknown):value is number{return typeof value==='number'&&Number.isSafeInteger(value)&&value>=0}
export async function approveCompatibleLibrary(pointer:LibraryPointer,totalRules:number,request:Request,onProgress:(progress:BulkApprovalProgress)=>void=()=>{}):Promise<BulkApprovalProgress>{
 const progress:BulkApprovalProgress={phase:'READING',completedRules:0,totalRules,totalVariants:0,completedBatches:0,totalBatches:0,created:0,existing:0,skipped:0};
 let approvalPending=false;
 function report(){onProgress({...progress})}
 function verifyPage(value:unknown){
  if(!object(value)||!object(value.snapshot)||value.snapshot.sha256!==pointer.sha256||value.snapshot.indexSha256!==pointer.indexSha256)throw Error('规则库版本已变化，请刷新后重新批准');
  if(value.total!==totalRules)throw Error('兼容规则数量已变化，请刷新后重新批准');
  return value;
 }
 const pagePath=(page:number)=>'/probe-rule-library?'+new URLSearchParams({page:String(page),pageSize:'100',status:'compatible'});
 try{
  if(!/^[a-f0-9]{64}$/.test(pointer.sha256)||!/^[a-f0-9]{64}$/.test(pointer.indexSha256))throw Error('规则库摘要不完整，请刷新后重试');
  if(!count(totalRules)||totalRules<1||totalRules>5000)throw Error('全部兼容规则最多支持5000个执行检查，请缩小范围');
  const entries:Entry[]=[],seen=new Set<string>();report();
  for(let page=1;page<=Math.ceil(totalRules/100);page++){
   const value=verifyPage(await request(pagePath(page))),expected=Math.min(100,totalRules-entries.length);
   if(value.page!==page||value.pageSize!==100||!Array.isArray(value.items)||value.items.length!==expected)throw Error('兼容规则分页不完整，请刷新后重试');
   for(const entry of value.items){
    if(!object(entry)||typeof entry.id!=='string'||!entry.id||entry.id.length>512||seen.has(entry.id)||entry.compatible!==true||!count(entry.variants)||entry.variants<1||entry.variants>500)throw Error('兼容规则身份或执行数量无效，尚未批准规则');
    seen.add(entry.id);entries.push({id:entry.id,variants:entry.variants});progress.totalVariants+=entry.variants;
    if(progress.totalVariants>5000)throw Error('全部兼容规则超过5000个执行检查，请缩小范围');
   }
  }
  const batches:Entry[][]=[];let batch:Entry[]=[],variants=0;
  for(const entry of entries){if(variants+entry.variants>500){batches.push(batch);batch=[];variants=0}batch.push(entry);variants+=entry.variants}if(batch.length)batches.push(batch);
  progress.phase='APPROVING';progress.totalBatches=batches.length;report();
  for(const group of batches){
   // Recheck the pointer before each independently committed server batch.
   verifyPage(await request(pagePath(1)));
   approvalPending=true;
   const result=await request('/probe-rule-library/activate',{snapshotSha256:pointer.sha256,ids:group.map(entry=>entry.id)});
   if(!object(result)||!count(result.created)||!count(result.existing)||!count(result.skipped)||result.created+result.existing+result.skipped!==group.reduce((sum,entry)=>sum+entry.variants,0))throw Error('批准结果未完整返回，请刷新模板状态后重试');
   progress.created+=result.created;progress.existing+=result.existing;progress.skipped+=result.skipped;progress.completedBatches++;progress.completedRules+=group.length;approvalPending=false;report();
  }
  return {...progress};
 }catch(error){const detail=error instanceof Error?error.message:'请求未完成';throw new LibraryBulkApprovalError(`${approvalPending?'本批结果未确认；':''}${progress.totalBatches?`已确认完成 ${progress.completedBatches}/${progress.totalBatches} 批，${progress.completedRules}/${totalRules} 条规则；新建 ${progress.created}、已存在 ${progress.existing}、跳过 ${progress.skipped}。已停止剩余批次。`:'目录核对未完成，尚未批准任何规则。'}${detail}`,{...progress})}
}
