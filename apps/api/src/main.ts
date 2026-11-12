import {DatabaseOnboardingController,DatabaseOnboardingService,AgentDatabaseMonitorController} from './database-onboarding';
import {auditDatabaseProvider} from './audit-db';
import {AgentDatabaseAuditController,DatabaseAuditImportController,AuditAuthGuard} from './database-audit-ingress';
import {ProbeDeploymentsController,ProbeDeploymentsService} from './probe-deployments';
import {ProbeRuleLibraryController} from './probe-rule-library';
import {VulnerabilityWorkspaceController} from './vulnerability-workspace';
import {PostgresMonitoringController,PostgresMonitoringService} from './postgres-monitor';
import {MonitoringController} from './monitoring';
import {FindingTriageController} from './finding-triage';
import {SecurityReadinessController} from './security-readiness';
import {NetworkSensorsController,SensorIngestController} from './network-sensors';
import {RuleSourceStatusController} from './rule-source-status';
import {AccessObservationService,AccessObservationsController,AccessSourcesController,AccessProbeController} from './access-observation';
import {DatabaseInstancesController} from './database-instances';
import {AssetDiscoveryController} from './asset-discovery';
import {DataGovernanceController} from './data-governance';
import {DeploymentHealthController} from './deployment-health';
import {basePath} from './platform-path';
import {AgentPlatformController} from './agent-platform';
import {AssetRemoteController,AssetRemoteService} from './asset-remote';
import {HostWafController} from './host-waf';
import {ActiveScansController} from './active-scans';
import {ScanExecutionIdentitiesController} from './scan-execution-identities';
import {RecordOptionsController} from './record-options';
import {ScanTemplatesController} from './scan-templates';
import {ScanEndpointsController} from './scan-endpoints';
import {ScansController} from './scans';
import {VulnerabilityFeedsController} from './intelligence';
import {WafBundlesController} from './waf-bundles';
import {WafDeploymentsController} from './waf-deployments';
import {SshInstallationService,SshInstallationsController} from './ssh-installations';
import {InstallationService,AgentReleasesController,InstallationsController,AgentBootstrapController} from './installations';
import {RuleToolsController} from "./rule-tools";
import {RepairTemplatesController} from "./templates";
import {StorageController} from "./storage";
import {ReportsController} from "./reports";
import {WorkloadController} from "./workload";
import {AssetHistoryController} from "./asset-history";
import {readFileSync} from "node:fs";
import {CertificateService,CertificateController,WafCertificatesController} from "./certificates";
import {TelemetryController,CorrelationController,CorrelationService,WafPolicyTestController} from "./correlation";
import {APP_INTERCEPTOR} from "@nestjs/core";
import {ScopeResponseInterceptor} from "./scope";
import {MaintenanceController,DeliveryService,ReadinessController} from "./maintenance";
import {RolloutsController,AgentRolloutController,RepairController} from "./rollouts";
import {AdvisoriesController} from "./advisories";
import "reflect-metadata";
import {
  Module,
  RequestMethod,
  Catch,
  ExceptionFilter,
  ArgumentsHost,
  HttpException,
  Logger,
} from "@nestjs/common";
import { NestFactory } from "@nestjs/core";
import { Prisma } from "@prisma/client";
import helmet from "helmet";
import { json } from "express";
import { GovernanceController } from "./governance";
import { WorkflowsController } from "./workflows";
import { Db } from "./db";
import { Lifecycle } from "./lifecycle";
import { AuthController, AuthGuard } from "./auth";
import { Platform } from "./platform";
import { OperationsController } from "./operations";
import { AttachmentsController } from "./attachments";
import { PlatformController } from "./controllers";
import { AgentController, WafController } from "./components";
@Catch()
class Errors implements ExceptionFilter {
  catch(error: any, host: ArgumentsHost) {
    let status = 500,
      message = "服务暂时不可用";
    if (error instanceof HttpException) {
      status = error.getStatus();
      const r = error.getResponse();
      message = typeof r === "string" ? r : (r as any).message;
    } else if (error instanceof Prisma.PrismaClientKnownRequestError) {
      if (error.code === "P2002") {
        status = 409;
        message = "记录已存在";
      } else if (error.code === "P2025") {
        status = 404;
        message = "记录不存在";
      } else if (error.code === "P2003") {
        status = 400;
        message = "关联记录无效";
      }
    } else if (error.status === 400) {
      status = 400;
      message = "请求内容格式无效";
    } else if (error.status === 413) {
      status = 413;
      message = "请求体过大";
    }
    if (status === 500) Logger.error(error?.message || "unknown error", "API");
    host.switchToHttp().getResponse().status(status).json({ message });
  }
}
@Module({
  controllers: [DatabaseOnboardingController,AgentDatabaseMonitorController,AgentDatabaseAuditController,DatabaseAuditImportController,ProbeDeploymentsController,ProbeRuleLibraryController,VulnerabilityWorkspaceController,PostgresMonitoringController,MonitoringController,FindingTriageController,SecurityReadinessController,NetworkSensorsController,SensorIngestController,AccessObservationsController,AccessSourcesController,AccessProbeController,RuleSourceStatusController,DatabaseInstancesController,AssetDiscoveryController,DataGovernanceController,DeploymentHealthController,AgentPlatformController,AssetRemoteController,HostWafController,ScanExecutionIdentitiesController,RecordOptionsController,ActiveScansController,ScanTemplatesController,ScanEndpointsController,ScansController,VulnerabilityFeedsController,WafBundlesController,WafDeploymentsController,SshInstallationsController,AgentReleasesController,InstallationsController,AgentBootstrapController,
    CertificateController,WafCertificatesController,
    AssetHistoryController,StorageController,RuleToolsController,RepairTemplatesController,
    ReadinessController,
    MaintenanceController,
    RolloutsController,AgentRolloutController,RepairController,
    TelemetryController,CorrelationController,WafPolicyTestController,
    AuthController,
    AgentController,
    WafController,
    OperationsController,
    AttachmentsController,
    WorkflowsController,
    GovernanceController,
    AdvisoriesController,
    ReportsController,
    WorkloadController,
    PlatformController,
  ],
  providers: [DatabaseOnboardingService,auditDatabaseProvider,AuditAuthGuard,ProbeDeploymentsService,PostgresMonitoringService,AccessObservationService,AssetRemoteService,SshInstallationService,InstallationService,Db, AuthGuard, Platform, Lifecycle,DeliveryService,CorrelationService,CertificateService,{provide:APP_INTERCEPTOR,useClass:ScopeResponseInterceptor}],
})
class AppModule {}
async function main() {
  if (
    !process.env.ENROLLMENT_TOKEN ||
    process.env.ENROLLMENT_TOKEN.length < 24 ||
    (process.env.WAF_TOKEN !== undefined && process.env.WAF_TOKEN.length < 24) ||
    (process.env.WAF_RULE_RUNTIME_ENABLED === 'true' && !process.env.WAF_TOKEN)
  )
    throw new Error("Component tokens must have at least 24 characters");
  if(!!process.env.API_TLS_CERT!==!!process.env.API_TLS_KEY)throw new Error('API TLS requires both certificate and key');
  const httpsOptions=process.env.API_TLS_CERT?{cert:readFileSync(process.env.API_TLS_CERT),key:readFileSync(process.env.API_TLS_KEY!)}:undefined;
  const app = await NestFactory.create(AppModule, { bodyParser: false,httpsOptions });
  if(process.env.TRUSTED_PROXY_CIDRS)app.getHttpAdapter().getInstance().set("trust proxy",process.env.TRUSTED_PROXY_CIDRS.split(","));
  app.use(helmet());
  app.use(json({ limit: "2mb" }));
  const prefix=basePath(process.env.BASE_PATH||"");
  app.setGlobalPrefix(prefix+"/api",{exclude:[{path:prefix+"/healthz",method:RequestMethod.GET},{path:prefix+"/livez",method:RequestMethod.GET}]});
  app.useGlobalFilters(new Errors());
  app.enableShutdownHooks();
  await app.listen(Number(process.env.PORT || 4000), "0.0.0.0");
}
main();
