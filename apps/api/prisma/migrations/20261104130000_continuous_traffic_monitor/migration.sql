CREATE TABLE "TrafficMonitor" (
 "id" TEXT NOT NULL,"assetId" TEXT NOT NULL,"ownerId" TEXT NOT NULL,"config" JSONB NOT NULL,
 "desiredState" TEXT NOT NULL DEFAULT 'RUNNING',"status" TEXT NOT NULL DEFAULT 'STARTING',
 "detail" TEXT NOT NULL DEFAULT '正在启用持续监测',"lastSequence" INTEGER NOT NULL DEFAULT 0,
 "droppedWindows" INTEGER NOT NULL DEFAULT 0,"lastReportAt" TIMESTAMP(3),
 "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,"updatedAt" TIMESTAMP(3) NOT NULL,
 CONSTRAINT "TrafficMonitor_pkey" PRIMARY KEY ("id"),
 CONSTRAINT "TrafficMonitor_assetId_fkey" FOREIGN KEY ("assetId") REFERENCES "Asset"("id") ON DELETE CASCADE ON UPDATE CASCADE
);
CREATE TABLE "TrafficMonitorWindow" (
 "id" TEXT NOT NULL,"monitorId" TEXT NOT NULL,"assetId" TEXT NOT NULL,"sequence" INTEGER NOT NULL,
 "startedAt" TIMESTAMP(3) NOT NULL,"endedAt" TIMESTAMP(3) NOT NULL,"summary" JSONB NOT NULL,
 "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
 CONSTRAINT "TrafficMonitorWindow_pkey" PRIMARY KEY ("id"),
 CONSTRAINT "TrafficMonitorWindow_monitorId_fkey" FOREIGN KEY ("monitorId") REFERENCES "TrafficMonitor"("id") ON DELETE CASCADE ON UPDATE CASCADE,
 CONSTRAINT "TrafficMonitorWindow_assetId_fkey" FOREIGN KEY ("assetId") REFERENCES "Asset"("id") ON DELETE CASCADE ON UPDATE CASCADE
);
CREATE INDEX "TrafficMonitor_assetId_createdAt_idx" ON "TrafficMonitor"("assetId","createdAt");
CREATE UNIQUE INDEX "TrafficMonitorWindow_monitorId_sequence_key" ON "TrafficMonitorWindow"("monitorId","sequence");
CREATE INDEX "TrafficMonitorWindow_assetId_startedAt_idx" ON "TrafficMonitorWindow"("assetId","startedAt");
CREATE INDEX "TrafficMonitorWindow_endedAt_idx" ON "TrafficMonitorWindow"("endedAt");
