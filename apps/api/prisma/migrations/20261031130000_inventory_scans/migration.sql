CREATE TABLE "ScanPlan" (
    "id" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "kind" TEXT NOT NULL DEFAULT 'INVENTORY',
    "creatorId" TEXT NOT NULL,
    "scope" JSONB NOT NULL,
    "feedIds" TEXT[],
    "enabled" BOOLEAN NOT NULL DEFAULT true,
    "intervalSeconds" INTEGER,
    "nextRunAt" TIMESTAMP(3),
    "version" INTEGER NOT NULL DEFAULT 1,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "ScanPlan_pkey" PRIMARY KEY ("id")
);

CREATE TABLE "ScanRun" (
    "id" TEXT NOT NULL,
    "planId" TEXT NOT NULL,
    "planVersion" INTEGER NOT NULL,
    "trigger" TEXT NOT NULL,
    "status" TEXT NOT NULL DEFAULT 'QUEUED',
    "scope" JSONB NOT NULL,
    "sources" JSONB NOT NULL,
    "leaseId" TEXT,
    "leaseUntil" TIMESTAMP(3),
    "error" TEXT,
    "summary" JSONB NOT NULL DEFAULT '{}',
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "completedAt" TIMESTAMP(3),

    CONSTRAINT "ScanRun_pkey" PRIMARY KEY ("id")
);

CREATE TABLE "ScanTarget" (
    "id" TEXT NOT NULL,
    "runId" TEXT NOT NULL,
    "assetId" TEXT NOT NULL,
    "hostname" TEXT NOT NULL,
    "inventory" JSONB NOT NULL,
    "inventoryAt" TIMESTAMP(3),
    "inventorySha256" TEXT NOT NULL,
    "status" TEXT NOT NULL DEFAULT 'PENDING',
    "reason" TEXT,
    "result" JSONB,
    "attempts" INTEGER NOT NULL DEFAULT 0,
    "completedAt" TIMESTAMP(3),

    CONSTRAINT "ScanTarget_pkey" PRIMARY KEY ("id")
);

CREATE INDEX "ScanPlan_enabled_nextRunAt_idx" ON "ScanPlan"("enabled", "nextRunAt");

CREATE INDEX "ScanRun_status_leaseUntil_idx" ON "ScanRun"("status", "leaseUntil");

CREATE INDEX "ScanTarget_runId_status_idx" ON "ScanTarget"("runId", "status");

CREATE UNIQUE INDEX "ScanTarget_runId_assetId_key" ON "ScanTarget"("runId", "assetId");

ALTER TABLE "ScanRun" ADD CONSTRAINT "ScanRun_planId_fkey" FOREIGN KEY ("planId") REFERENCES "ScanPlan"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

ALTER TABLE "ScanTarget" ADD CONSTRAINT "ScanTarget_runId_fkey" FOREIGN KEY ("runId") REFERENCES "ScanRun"("id") ON DELETE CASCADE ON UPDATE CASCADE;
