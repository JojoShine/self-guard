import {BadRequestException,Controller,Get,Inject,Query,Req,UseGuards} from '@nestjs/common';
import {Prisma} from '@prisma/client';
import {z} from 'zod';
import {AuthGuard} from './auth';
import {Db} from './db';
import {resourceWhere,restricted} from './scope';
import {parse} from './validation';

const activeFindings=['OPEN','CONFIRMED','IN_PROGRESS','VERIFYING'];
const activeTasks=['PENDING','APPROVED','RUNNING','VERIFYING','UNKNOWN'];
const repairTemplates=['FILE_PERMISSION','CONFIG_VALUE','SERVICE_STATE'];
const dayInput=z.string().regex(/^\d{4}-\d{2}-\d{2}$/).refine(value=>{const parsed=new Date(value+'T00:00:00Z');return Number.isFinite(parsed.getTime())&&parsed.toISOString().slice(0,10)===value;},'日期无效');
type Business={business:string;assetsCreated:number;risksCreated:number;alertsCreated:number;tasksCreated:number};
type Trend={day:string;assetsCreated:number;risksCreated:number;alertsCreated:number;tasksCreated:number;closedFindings:number};

@Controller('reports')
@UseGuards(AuthGuard)
export class ReportsController {
  constructor(@Inject(Db) private db:Db){}
  @Get('detailed')
  async detailed(@Req() req:any,@Query() query:any){
    const now=new Date(),today=now.toISOString().slice(0,10);
    const filters=parse(z.object({from:dayInput.default(new Date(Date.parse(today)-29*86400000).toISOString().slice(0,10)),to:dayInput.default(today),business:z.string().min(1).max(200).optional()}).strict(),query);
    const start=new Date(filters.from+'T00:00:00Z'),end=new Date(Date.parse(filters.to+'T00:00:00Z')+86400000);
    const days=(end.getTime()-start.getTime())/86400000;
    if(days<1||days>366)throw new BadRequestException('请选择按顺序排列且不超过366天的日期范围');
    const user=req.user;
    const [assetScope,findingScope,taskScope]=await Promise.all([resourceWhere(this.db,user,'assets'),resourceWhere(this.db,user,'findings'),resourceWhere(this.db,user,'tasks')]);
    const business=filters.business?{business:filters.business}:{};
    const createdAt={gte:start,lt:end};
    const findingWhere={AND:[findingScope,{createdAt},...(filters.business?[{asset:{is:business}}]:[])]};
    const taskWhere={AND:[taskScope,{createdAt},...(filters.business?[{asset:{is:business}}]:[])]};
    const [assets,assetGroups,findingGroups,taskGroups,assignedOpenFindings,overdueFindings,myActiveTasks]=await Promise.all([
      this.db.asset.findMany({where:{AND:[assetScope,business]},select:{id:true,business:true}}),
      this.db.asset.groupBy({by:['business'],where:{AND:[assetScope,business,{createdAt}]},_count:{_all:true}}),
      this.db.finding.groupBy({by:['assetId','kind','status'],where:findingWhere,_count:{_all:true}}),
      this.db.task.groupBy({by:['assetId','status','template'],where:taskWhere,_count:{_all:true}}),
      this.db.finding.count({where:{AND:[findingWhere,{owner:{in:[user.email,user.name]},status:{in:activeFindings}}]}}),
      this.db.finding.count({where:{AND:[findingWhere,{owner:{in:[user.email,user.name]},status:{in:activeFindings},dueAt:{lt:now}}]}}),
      this.db.task.count({where:{AND:[taskWhere,{requestedBy:user.email,status:{in:activeTasks}}]}}),
    ]);
    const ids=assets.map(asset=>asset.id),businessById=new Map(assets.map(asset=>[asset.id,asset.business||'未分组']));
    const scopedFinding=restricted(user)||filters.business?Prisma.sql`AND "assetId" = ANY(${ids}::text[])`:Prisma.empty;
    const rows=await this.db.$queryRaw<Array<{day:string;metric:string;count:bigint}>>(Prisma.sql`
      SELECT to_char("createdAt" AT TIME ZONE 'UTC','YYYY-MM-DD') AS day,'assetsCreated' AS metric,count(*) AS count FROM "Asset" WHERE "createdAt">=${start} AND "createdAt"<${end} AND id=ANY(${ids}::text[]) GROUP BY 1
      UNION ALL SELECT to_char("createdAt" AT TIME ZONE 'UTC','YYYY-MM-DD'),CASE WHEN kind='RISK' THEN 'risksCreated' ELSE 'alertsCreated' END,count(*) FROM "Finding" WHERE "createdAt">=${start} AND "createdAt"<${end} ${scopedFinding} GROUP BY 1,2
      UNION ALL SELECT to_char("createdAt" AT TIME ZONE 'UTC','YYYY-MM-DD'),'closedFindings',count(*) FROM "Finding" WHERE "createdAt">=${start} AND "createdAt"<${end} AND status IN ('CLOSED','RESOLVED') ${scopedFinding} GROUP BY 1
      UNION ALL SELECT to_char("createdAt" AT TIME ZONE 'UTC','YYYY-MM-DD'),'tasksCreated',count(*) FROM "Task" WHERE "createdAt">=${start} AND "createdAt"<${end} AND "assetId"=ANY(${ids}::text[]) GROUP BY 1`);
    const trends:Trend[]=Array.from({length:days},(_,i)=>({day:new Date(start.getTime()+i*86400000).toISOString().slice(0,10),assetsCreated:0,risksCreated:0,alertsCreated:0,tasksCreated:0,closedFindings:0}));
    const byDay=new Map(trends.map(row=>[row.day,row]));
    for(const row of rows){const target=byDay.get(row.day);if(target&&['assetsCreated','risksCreated','alertsCreated','tasksCreated','closedFindings'].includes(row.metric))(target as any)[row.metric]=Number(row.count);}
    const totals={assetsCreated:0,risksCreated:0,alertsCreated:0,openFindings:0,closedFindings:0,tasksCreated:0};
    const repairOutcomes={succeeded:0,failed:0,rolledBack:0};
    const groups=new Map<string,Business>();
    const group=(name:string)=>{let row=groups.get(name);if(!row){row={business:name,assetsCreated:0,risksCreated:0,alertsCreated:0,tasksCreated:0};groups.set(name,row);}return row;};
    for(const row of assetGroups){totals.assetsCreated+=row._count._all;group(row.business||'未分组').assetsCreated+=row._count._all;}
    for(const row of findingGroups){const count=row._count._all,b=group(row.assetId?businessById.get(row.assetId)||'未关联资产':'未关联资产');if(row.kind==='RISK'){totals.risksCreated+=count;b.risksCreated+=count;}else{totals.alertsCreated+=count;b.alertsCreated+=count;}if(activeFindings.includes(row.status))totals.openFindings+=count;if(['CLOSED','RESOLVED'].includes(row.status))totals.closedFindings+=count;}
    for(const row of taskGroups){const count=row._count._all;totals.tasksCreated+=count;group(businessById.get(row.assetId)||'未关联资产').tasksCreated+=count;if(repairTemplates.includes(row.template)){if(row.status==='SUCCEEDED')repairOutcomes.succeeded+=count;if(row.status==='FAILED')repairOutcomes.failed+=count;if(row.status==='ROLLED_BACK')repairOutcomes.rolledBack+=count;}}
    return {
      generatedAt:now.toISOString(),timezone:'UTC',filters:{from:filters.from,to:filters.to,business:filters.business||null},
      basis:'按UTC创建日期筛选，包含归档资产。关闭、修复结果与逾期反映所选创建日期记录的当前状态，不代表当日关闭或完成次数。待处理发现不含已接受、已关闭、已解决与误报；修复结果不重复计入复测或回滚子任务。',
      totals,personal:{assignedOpenFindings,overdueFindings,myActiveTasks},repairOutcomes,
      businesses:[...groups.values()].sort((a,b)=>b.risksCreated-a.risksCreated||a.business.localeCompare(b.business)),trends,
    };
  }
}
