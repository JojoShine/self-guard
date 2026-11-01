import {z} from 'zod';
import {Controller,Get,Inject,Query,Req,UseGuards} from '@nestjs/common';
import {AuthGuard} from './auth';
import {Db} from './db';
import {resourceWhere} from './scope';
import {approvalPolicyInput} from './governance';
import {parse} from './validation';

const activeFindings=['OPEN','CONFIRMED','IN_PROGRESS','VERIFYING'];
const activeTasks=['PENDING','APPROVED','RUNNING','VERIFYING','UNKNOWN'];
const repairTemplates=['FILE_PERMISSION','CONFIG_VALUE','SERVICE_STATE'];
const findingSummary={id:true,title:true,kind:true,status:true,dueAt:true,assetId:true} as const;
const taskSummary={id:true,title:true,status:true,assetId:true} as const;
const sampleLimit=5;

@Controller('workload')
@UseGuards(AuthGuard)
export class WorkloadController {
  constructor(@Inject(Db) private db:Db){}
  private async filters(user:any,now:Date){
    const cutoff=new Date(now.getTime()-90*1000);
    const [assetScope,findingScope,taskScope,policyRow]=await Promise.all([
      resourceWhere(this.db,user,'assets'),resourceWhere(this.db,user,'findings'),resourceWhere(this.db,user,'tasks'),
      this.db.setting.findUnique({where:{key:'approval-policy'}}),
    ]);
    const policy=parse(approvalPolicyInput,policyRow?.value||{approverRoles:['ADMIN'],allowSelfApproval:true});
    const eligible=policy.approverRoles.includes(user.role);
    const activeAssets={AND:[assetScope,{archivedAt:null}]};
    const assignedWhere={AND:[findingScope,{owner:{in:[user.email,user.name]},status:{in:activeFindings}}]};
    const overdueWhere={AND:[assignedWhere,{dueAt:{lt:now}}]};
    const myTasksWhere={AND:[taskScope,{requestedBy:user.email,status:{in:activeTasks}}]};
    const approvalsWhere={AND:[taskScope,{status:'PENDING',expiresAt:{gt:now},...(!policy.allowSelfApproval?{requestedBy:{not:user.email}}:{})}]};
    const groups:Record<string,{resource:string;where:any}>={
      overviewAssets:{resource:'assets',where:assetScope},
      overviewRisks:{resource:'findings',where:{AND:[findingScope,{kind:'RISK',status:{notIn:['CLOSED','FALSE_POSITIVE']}}]}},
      overviewAlerts:{resource:'findings',where:{AND:[findingScope,{kind:'ALERT',status:{notIn:['RESOLVED','FALSE_POSITIVE']}}]}},
      overviewTasks:{resource:'tasks',where:{AND:[taskScope,{status:{in:activeTasks}}]}},
      overviewCritical:{resource:'findings',where:{AND:[findingScope,{kind:'RISK',severity:'CRITICAL',status:{notIn:['CLOSED','FALSE_POSITIVE']}}]}},
      wafNodes:{resource:'waf-nodes',where:{AND:[await resourceWhere(this.db,user,'waf-nodes'),{lastSeen:{gte:cutoff}}]}},
      wafEvents:{resource:'waf-events',where:await resourceWhere(this.db,user,'waf-events')},
      wafBlocked:{resource:'waf-events',where:{AND:[await resourceWhere(this.db,user,'waf-events'),{action:'BLOCK'}]}},
      online:{resource:'assets',where:{AND:[activeAssets,{lastSeen:{gte:cutoff}}]}},
      stale:{resource:'assets',where:{AND:[activeAssets,{lastSeen:{lt:cutoff}}]}},
      neverSeen:{resource:'assets',where:{AND:[activeAssets,{lastSeen:null}]}},
      archived:{resource:'assets',where:{AND:[assetScope,{archivedAt:{not:null}}]}},
      assigned:{resource:'findings',where:assignedWhere},overdue:{resource:'findings',where:overdueWhere},
      myTasks:{resource:'tasks',where:myTasksWhere},
      approvals:{resource:'tasks',where:eligible?approvalsWhere:{id:{in:[]}}},
      verifyFindings:{resource:'findings',where:{AND:[findingScope,{status:'VERIFYING'}]}},
      verifyTasks:{resource:'tasks',where:{AND:[taskScope,{status:'VERIFYING'}]}},
    };
    for(const [group,status]of [['succeeded','SUCCEEDED'],['failed','FAILED'],['rolledBack','ROLLED_BACK']])groups[group]={resource:'tasks',where:{AND:[taskScope,{template:{in:repairTemplates},status}]}};
    return {assetScope,findingScope,taskScope,activeAssets,assignedWhere,overdueWhere,myTasksWhere,approvalsWhere,eligible,groups,cutoff};
  }
  @Get('details')
  async details(@Req() req:any,@Query() query:any){
    const v=parse(z.object({group:z.enum(['online','stale','neverSeen','archived','assigned','overdue','myTasks','approvals','verifyFindings','verifyTasks','succeeded','failed','rolledBack','businessAssets','businessRisks','overviewAssets','overviewRisks','overviewAlerts','overviewIncidents','overviewTasks','overviewCritical','wafEvents','wafBlocked','wafNodes']),business:z.string().min(1).max(200).optional(),page:z.coerce.number().int().min(1).default(1),pageSize:z.coerce.number().int().min(1).max(100).default(20)}).superRefine((v,ctx)=>{if(v.group.startsWith('business')&&!v.business)ctx.addIssue({code:'custom',path:['business'],message:'需要业务分组名称'});}),query);
    const now=new Date(),f=await this.filters(req.user,now);
    if(v.group==='overviewIncidents')f.groups.overviewIncidents={resource:'incidents',where:{AND:[await resourceWhere(this.db,req.user,'incidents'),{status:{not:'CLOSED'}}]}};
    const business=v.business==='未分组'?{OR:[{business:null},{business:''},{business:'未分组'}]}:{business:v.business};
    const target=v.group==='businessAssets'?{resource:'assets',where:{AND:[f.activeAssets,business]}}:v.group==='businessRisks'?{resource:'findings',where:{AND:[f.findingScope,{kind:'RISK',status:{in:activeFindings},asset:{is:{AND:[{archivedAt:null},business]}}}]}}:f.groups[v.group];
    const delegate=target.resource==='assets'?this.db.asset:target.resource==='findings'?this.db.finding:target.resource==='incidents'?this.db.incident:target.resource==='waf-events'?this.db.wafEvent:target.resource==='waf-nodes'?this.db.wafNode:this.db.task;
    const select=target.resource==='assets'?{id:true,hostname:true,business:true,owner:true,lastSeen:true,archivedAt:true}:target.resource==='findings'?findingSummary:target.resource==='incidents'?{id:true,title:true,status:true,severity:true,owner:true}:target.resource==='waf-events'?{id:true,siteId:true,ruleId:true,method:true,action:true,timestamp:true}:target.resource==='waf-nodes'?{id:true,version:true,lastSeen:true,startedAt:true,stats:true}:taskSummary;
    const [items,total]=await Promise.all([(delegate as any).findMany({where:target.where,select,orderBy:[{[target.resource==='waf-nodes'?'lastSeen':'createdAt']:'desc'},{id:'asc'}],skip:(v.page-1)*v.pageSize,take:v.pageSize}),(delegate as any).count({where:target.where})]);
    if(target.resource==='waf-nodes')for(const item of items)item.stats=Object.fromEntries(['totalRequests','blockedRequests','observedRequests','upstreamErrors','droppedEvents','accessLogDropped'].map(key=>[key,typeof item.stats?.[key]==='number'&&Number.isFinite(item.stats[key])?item.stats[key]:0]));
    return {items,total,page:v.page,pageSize:v.pageSize,group:v.group,business:v.business||null,resource:target.resource,generatedAt:now.toISOString(),timezone:'UTC',freshnessSeconds:90,basis:'按打开明细时的权限、审批策略和当前时间重新统计，数据变化可能使数量与较早的概览不同。'};
  }
  @Get()
  async workload(@Req() req:any){
    const now=new Date(),freshnessSeconds=90;
    const {assetScope,findingScope,taskScope,activeAssets,assignedWhere,overdueWhere,myTasksWhere,approvalsWhere,eligible,groups,cutoff}=await this.filters(req.user,now);
    const [online,stale,neverSeen,archived,assignedCount,assignedItems,overdueCount,overdueItems,myTaskCount,myTaskItems,approvalCount,approvalItems,verifyingFindings,verifyingTasks,outcomes,assetGroups,riskGroups]=await Promise.all([
      this.db.asset.count({where:groups.online.where}),
      this.db.asset.count({where:groups.stale.where}),
      this.db.asset.count({where:groups.neverSeen.where}),
      this.db.asset.count({where:groups.archived.where}),
      this.db.finding.count({where:assignedWhere}),
      this.db.finding.findMany({where:assignedWhere,select:findingSummary,orderBy:{updatedAt:'desc'},take:sampleLimit}),
      this.db.finding.count({where:overdueWhere}),
      this.db.finding.findMany({where:overdueWhere,select:findingSummary,orderBy:{dueAt:'asc'},take:sampleLimit}),
      this.db.task.count({where:myTasksWhere}),
      this.db.task.findMany({where:myTasksWhere,select:taskSummary,orderBy:{updatedAt:'desc'},take:sampleLimit}),
      eligible?this.db.task.count({where:approvalsWhere}):Promise.resolve(0),
      eligible?this.db.task.findMany({where:approvalsWhere,select:taskSummary,orderBy:{createdAt:'asc'},take:sampleLimit}):Promise.resolve([]),
      this.db.finding.count({where:groups.verifyFindings.where}),
      this.db.task.count({where:groups.verifyTasks.where}),
      this.db.task.groupBy({by:['status'],where:{AND:[taskScope,{template:{in:repairTemplates},status:{in:['SUCCEEDED','FAILED','ROLLED_BACK']}}]},_count:{_all:true}}),
      this.db.asset.groupBy({by:['business'],where:activeAssets,_count:{_all:true}}),
      this.db.finding.groupBy({by:['assetId'],where:{AND:[findingScope,{kind:'RISK',status:{in:activeFindings},asset:{is:{archivedAt:null}}}]},_count:{_all:true}}),
    ]);
    // Only aggregate counts and asset/business identifiers enter this distribution; evidence is never selected.
    const riskAssetIds=riskGroups.flatMap(group=>group.assetId?[group.assetId]:[]);
    const riskAssets=await this.db.asset.findMany({where:{AND:[activeAssets,{id:{in:riskAssetIds}}]},select:{id:true,business:true}});
    const businessByAsset=new Map(riskAssets.map(asset=>[asset.id,asset.business||'未分组']));
    const businesses=new Map<string,{business:string;assets:number;openRisks:number}>();
    for(const group of assetGroups){const business=group.business||'未分组';const row=businesses.get(business)||{business,assets:0,openRisks:0};row.assets+=group._count._all;businesses.set(business,row);}
    for(const group of riskGroups){const business=group.assetId?businessByAsset.get(group.assetId):undefined;if(business!==undefined){const row=businesses.get(business);if(row)row.openRisks+=group._count._all;}}
    const outcomeCounts=Object.fromEntries(outcomes.map(row=>[row.status,row._count._all]));
    return {
      generatedAt:now.toISOString(),timezone:'UTC',freshnessSeconds,freshnessCutoff:cutoff.toISOString(),sampleLimit,
      assets:{online,stale,neverSeen,archived},
      personal:{
        assignedFindings:{count:assignedCount,items:assignedItems},
        overdueFindings:{count:overdueCount,items:overdueItems},
        myTasks:{count:myTaskCount,items:myTaskItems},
        approvals:{eligible,count:approvalCount,items:approvalItems},
      },
      pendingVerification:{findings:verifyingFindings,tasks:verifyingTasks},
      repairOutcomes:{succeeded:outcomeCounts.SUCCEEDED||0,failed:outcomeCounts.FAILED||0,rolledBack:outcomeCounts.ROLLED_BACK||0},
      businesses:[...businesses.values()].sort((a,b)=>b.openRisks-a.openRisks||b.assets-a.assets||a.business.localeCompare(b.business)),
    };
  }
}
