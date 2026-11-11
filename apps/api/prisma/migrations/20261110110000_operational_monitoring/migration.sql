CREATE TABLE "OperationalMonitor" (
 "id" TEXT PRIMARY KEY,"kind" TEXT NOT NULL,"assetId" TEXT,"instanceId" TEXT,"ownerId" TEXT,
 "enabled" BOOLEAN NOT NULL DEFAULT true,"config" JSONB NOT NULL,"credential" TEXT,"version" INTEGER NOT NULL DEFAULT 0,
 "status" TEXT NOT NULL DEFAULT 'WAITING',"lastAttemptAt" TIMESTAMP(3),"lastSuccessAt" TIMESTAMP(3),"lastMetric" JSONB,"lastError" TEXT,
 "failureCount" INTEGER NOT NULL DEFAULT 0,"leaseUntil" TIMESTAMP(3),"leaseToken" TEXT,"createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,"updatedAt" TIMESTAMP(3) NOT NULL,
 CONSTRAINT "OperationalMonitor_assetId_fkey" FOREIGN KEY ("assetId") REFERENCES "Asset"("id") ON DELETE RESTRICT ON UPDATE CASCADE,
 CONSTRAINT "OperationalMonitor_instanceId_fkey" FOREIGN KEY ("instanceId") REFERENCES "DatabaseInstance"("id") ON DELETE RESTRICT ON UPDATE CASCADE,
 CONSTRAINT "OperationalMonitor_ownerId_fkey" FOREIGN KEY ("ownerId") REFERENCES "User"("id") ON DELETE RESTRICT ON UPDATE CASCADE,
 CONSTRAINT "OperationalMonitor_target" CHECK (("kind"='HOST' AND "assetId" IS NOT NULL AND "instanceId" IS NULL) OR ("kind"='POSTGRESQL' AND "instanceId" IS NOT NULL AND "assetId" IS NULL))
);
CREATE UNIQUE INDEX "OperationalMonitor_assetId_key" ON "OperationalMonitor"("assetId");
CREATE UNIQUE INDEX "OperationalMonitor_instanceId_key" ON "OperationalMonitor"("instanceId");
CREATE INDEX "OperationalMonitor_kind_enabled_lastAttemptAt_idx" ON "OperationalMonitor"("kind","enabled","lastAttemptAt");
CREATE TABLE "MonitoringSample" ("id" TEXT PRIMARY KEY,"monitorId" TEXT NOT NULL,"bucket" TIMESTAMP(3) NOT NULL,"capturedAt" TIMESTAMP(3) NOT NULL,"data" JSONB NOT NULL,
 CONSTRAINT "MonitoringSample_monitorId_fkey" FOREIGN KEY ("monitorId") REFERENCES "OperationalMonitor"("id") ON DELETE CASCADE ON UPDATE CASCADE);
CREATE UNIQUE INDEX "MonitoringSample_monitorId_bucket_key" ON "MonitoringSample"("monitorId","bucket");
CREATE INDEX "MonitoringSample_monitorId_capturedAt_idx" ON "MonitoringSample"("monitorId","capturedAt");
CREATE INDEX "MonitoringSample_capturedAt_idx" ON "MonitoringSample"("capturedAt");
