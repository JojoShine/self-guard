import {Prisma} from '@prisma/client';
export async function stopFailedBatch(tx:Prisma.TransactionClient,batchId:string|null){
 if(!batchId)return;const b=await tx.taskBatch.findUnique({where:{id:batchId}});if(!b||!b.stopOnFailure||b.status!=='RUNNING')return;
 await tx.taskBatch.update({where:{id:batchId},data:{status:'STOPPED'}});
 await tx.task.updateMany({where:{batchId,status:{in:['PENDING','APPROVED']}},data:{status:'CANCELLED',reason:'批次任务失败或结果未知，停止剩余执行'}});
}
