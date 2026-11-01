import {queueDueActiveScans,processActiveScans} from './active-scans';
import {queueDueScanPlans,processInventoryScans} from './scans';
import {syncDueVulnerabilityFeeds} from './intelligence';
import {sweepStorage} from "./storage";
import {syncAdvisory} from "./advisories";
import {stopFailedBatch} from "./batches";
import {GovernanceController} from "./governance";
import {
  Injectable,
  Inject,
  OnModuleInit,
  OnModuleDestroy,
  Logger,
} from "@nestjs/common";
import { Db } from "./db";
import { Platform } from "./platform";
@Injectable()
export class Lifecycle implements OnModuleInit, OnModuleDestroy {
  private timer?: ReturnType<typeof setInterval>;
  private running = false;
  private intelligenceRunning = false;
  private activeScanRunning = false;
  private activeScanAbort = new AbortController();
  constructor(
    @Inject(Db) private db: Db,
    @Inject(Platform) private p: Platform,
  ) {}
  onModuleInit() {
    this.timer = setInterval(() => {void this.sweep();void this.syncIntelligence();void this.scanActive()}, 60000);
    this.timer.unref();
  }
  onModuleDestroy() {
    if (this.timer) clearInterval(this.timer);
    this.activeScanAbort.abort();
  }
  private async scanActive(){
    if(this.activeScanRunning||this.activeScanAbort.signal.aborted)return;
    this.activeScanRunning=true;
    try{await queueDueActiveScans(this.db);await processActiveScans(this.db,this.p,this.activeScanAbort.signal);await this.db.scanBudgetBucket.deleteMany({where:{updatedAt:{lt:new Date(Date.now()-86400000)},nextAllowedAt:{lt:new Date(Date.now()-86400000)}}})}catch{Logger.warn('Active scan processing incomplete; committed checks remain available','Lifecycle')}finally{this.activeScanRunning=false}
  }
  private async syncIntelligence(){
    if(this.intelligenceRunning)return;
    this.intelligenceRunning=true;
    try{await syncDueVulnerabilityFeeds(this.db)}catch{Logger.warn('Intelligence refresh failed; last valid snapshots remain available','Lifecycle')}finally{this.intelligenceRunning=false}
  }
  async sweep() {
    if (this.running) return;
    this.running = true;
    try {
      await this.db.$transaction(async (tx) => {
        const expired = await tx.finding.updateMany({
          where: { status: "ACCEPTED", expiresAt: { lte: new Date() } },
          data: { status: "OPEN" },
        });
        const pending = await tx.task.updateMany({
          where: {
            status: { in: ["PENDING", "APPROVED"] },
            expiresAt: { lte: new Date() },
          },
          data: { status: "EXPIRED" },
        });
        const unknown = await tx.task.updateMany({
          where: {
            status: "RUNNING",
            claimedAt: { lt: new Date(Date.now() - 15 * 60000) },
          },
          data: { status: "UNKNOWN" },
        });
        for(const failed of await tx.task.findMany({where:{batchId:{not:null},status:{in:['FAILED','UNKNOWN']}},distinct:['batchId'],select:{batchId:true}}))await stopFailedBatch(tx,failed.batchId);
        if (expired.count || pending.count || unknown.count)
          await tx.audit.create({
            data: {
              actor: "system",
              action: "LIFECYCLE_SWEEP",
              resource: "platform",
              detail: {
                expiredAcceptances: expired.count,
                expiredTasks: pending.count,
                unknownTasks: unknown.count,
              },
            },
          });
      });
      await this.db.importBatch.updateMany({where:{status:'RUNNING',updatedAt:{lt:new Date(Date.now()-300000)}},data:{status:'FAILED',error:'导入进程中断或超时，可安全重试'}});
      await this.db.telemetryEvent.deleteMany({where:{expiresAt:{lt:new Date()}}});
      await sweepStorage(this.db);
      await this.db.session.deleteMany({where:{expiresAt:{lt:new Date()}}});
      const governance=new GovernanceController(this.db,this.p);let userCursor:string|undefined;
      for(;;){const users=await this.db.user.findMany({where:{disabled:false,...(userCursor?{id:{gt:userCursor}}:{})},orderBy:{id:'asc'},take:100,select:{id:true,email:true,name:true,role:true,dataScope:true}});if(!users.length)break;for(const user of users)await governance.syncNotifications({user});userCursor=users[users.length-1].id;}
      await queueDueScanPlans(this.db);
      await processInventoryScans(this.db,this.p);
      const cutoff=new Date(Date.now()-3600000);
      const sources=await this.db.advisorySource.findMany({where:{enabled:true,OR:[{status:'IDLE'},{status:{in:['SUCCEEDED','PARTIAL','FAILED']},updatedAt:{lt:cutoff}}]},orderBy:{updatedAt:'asc'},take:5});
      for(const source of sources){try{await syncAdvisory(this.db,source.id,'scheduler');}catch{Logger.warn('Advisory source refresh failed; retry is recorded','Lifecycle');}}
      const due = await this.db.rule.findMany({
        where: {
          enabled: true,
          kind: "VULNERABILITY",
          nextRunAt: { lte: new Date() },
        },
        take: 20,
      });
      for (const rule of due) {
        if (!rule.intervalSeconds) continue;
        const claimed = await this.db.rule.updateMany({
          where: { id: rule.id, nextRunAt: rule.nextRunAt },
          data: {
            nextRunAt: new Date(Date.now() + rule.intervalSeconds * 1000),
          },
        });
        if (!claimed.count) continue;
        try {
          await this.p.runRule(rule.id, {}, "scheduler");
        } catch {
          await this.db.audit.create({
            data: {
              actor: "scheduler",
              action: "DETECTION_FAILED",
              resource: "rules",
              resourceId: rule.id,
            },
          });
        }
      }
    } catch {
      Logger.error(
        "Lifecycle sweep failed; next cycle will retry",
        "Lifecycle",
      );
    } finally {
      this.running = false;
    }
  }
}
