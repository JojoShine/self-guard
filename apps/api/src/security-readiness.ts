import {Controller,Get,Inject,Req,UseGuards} from '@nestjs/common';
import {Prisma} from '@prisma/client';
import {AuthGuard} from './auth';
import {Db} from './db';
import {assetScope,evidenceAllowed,resourceWhere,restricted} from './scope';
import {instanceScope} from './database-instances';
import type {SecurityRequest} from './database-contract';

@Controller('security-readiness') @UseGuards(AuthGuard)
export class SecurityReadinessController {
 constructor(@Inject(Db) private db:Db){}
 @Get() async summary(@Req() req:SecurityRequest){
  const now=new Date(),recent=new Date(now.getTime()-3600000),agentRecent=new Date(now.getTime()-90000),reportRecent=new Date(now.getTime()-180000);
  const user=req.user,canRead=evidenceAllowed(user);
  const assets:Prisma.AssetWhereInput={AND:[assetScope(user),{archivedAt:null}]};
  const instances:Prisma.DatabaseInstanceWhereInput={AND:[instanceScope(user),{archivedAt:null}]};
  const source:Prisma.AccessSourceWhereInput={asset:{is:assets},OR:[{instanceId:null},{instance:{is:instances}}]};
  const traffic:Prisma.TrafficMonitorWhereInput={asset:{is:assets}};
  const sensors:Prisma.NetworkSensorWhereInput={asset:{is:assets}};
  const active:Prisma.FindingWhereInput={AND:[await resourceWhere(this.db,user,'findings'),{kind:{in:['RISK','ALERT']},status:{in:['OPEN','CONFIRMED','IN_PROGRESS','VERIFYING']}}]};
  const [registered,agentLive,neverReported,stale,instanceCount,trafficCounts,sensorCounts,accessCounts,nativeEvents,scanCounts,activeCount,unassigned,verifying,overdue]=await Promise.all([
   this.db.asset.count({where:assets}),
   this.db.asset.count({where:{AND:[assets,{lastSeen:{gte:agentRecent}}]}}),
   this.db.asset.count({where:{AND:[assets,{lastSeen:null}]}}),
   this.db.asset.count({where:{AND:[assets,{lastSeen:{lt:agentRecent}}]}}),
   this.db.databaseInstance.count({where:instances}),
   canRead?Promise.all([
    this.db.trafficMonitor.count({where:traffic}),
    this.db.trafficMonitor.count({where:{...traffic,desiredState:'RUNNING'}}),
    this.db.trafficMonitor.count({where:{...traffic,desiredState:'RUNNING',status:'RUNNING',lastReportAt:{gte:reportRecent}}}),
    this.db.trafficMonitorWindow.count({where:{asset:{is:assets},endedAt:{gte:recent,lte:now}}}),
   ]):null,
   canRead?Promise.all([
    this.db.networkSensor.count({where:sensors}),
    this.db.networkSensor.count({where:{...sensors,enabled:true}}),
    this.db.networkSensor.count({where:{...sensors,enabled:true,lastMode:'LIVE',lastReportedAt:{gte:agentRecent}}}),
    this.db.networkSensor.count({where:{...sensors,enabled:true,lastMode:'LIVE',lastReportedAt:{gte:agentRecent},lastStatsAt:{gte:reportRecent}}}),
    this.db.networkSensor.count({where:{...sensors,lastMode:'REPLAY'}}),
   ]):null,
   canRead?Promise.all([
    this.db.accessSource.count({where:source}),
    this.db.accessSource.count({where:{AND:[source,{enabled:true}]}}),
    this.db.accessSource.count({where:{AND:[source,{enabled:true,lastReportAt:{gte:reportRecent}}]}}),
    this.db.accessObservation.count({where:{source:{is:source},startedAt:{gte:recent,lte:now}}}),
   ]):null,
   canRead?this.db.databaseAudit.count({where:{instance:{is:instances},timestamp:{gte:recent,lte:now}}}):null,
   canRead&&!restricted(user)?Promise.all([
    this.db.scanPlan.count(),this.db.scanPlan.count({where:{enabled:true}}),
    this.db.scanRun.count({where:{createdAt:{gte:recent,lte:now}}}),
    this.db.scanRun.count({where:{createdAt:{gte:recent,lte:now},status:'FAILED'}}),
   ]):null,
   this.db.finding.count({where:active}),
   this.db.finding.count({where:{AND:[active,{OR:[{owner:null},{owner:''}]}]}}),
   this.db.finding.count({where:{AND:[active,{status:'VERIFYING'}]}}),
   this.db.finding.count({where:{AND:[active,{dueAt:{lt:now}}]}}),
  ]);
  return {checkedAt:now.toISOString(),windowMinutes:60,
   agents:{registered,recent:agentLive,neverReported,stale},instances:instanceCount,
   traffic:trafficCounts?{configured:trafficCounts[0],enabled:trafficCounts[1],reporting:trafficCounts[2],recentWindows:trafficCounts[3]}:null,
   sensors:sensorCounts?{configured:sensorCounts[0],enabled:sensorCounts[1],liveReporting:sensorCounts[2],recentEngineStats:sensorCounts[3],replay:sensorCounts[4]}:null,
   access:accessCounts?{configured:accessCounts[0],enabled:accessCounts[1],reporting:accessCounts[2],recentEvents:accessCounts[3]}:null,
   nativeAudit:nativeEvents===null?null:{recentEvents:nativeEvents},
   scans:scanCounts?{configured:scanCounts[0],enabled:scanCounts[1],recentRuns:scanCounts[2],failedRuns:scanCounts[3]}:null,
   handling:{active:activeCount,unassigned,verifying,overdue},
  };
 }
}
