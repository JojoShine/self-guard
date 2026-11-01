ALTER TABLE "ScanPlan" ADD COLUMN "configuration" JSONB;
CREATE TABLE "ScanProbe" (
 "id" TEXT NOT NULL,
 "targetId" TEXT NOT NULL,
 "endpointId" TEXT NOT NULL,
 "templateId" TEXT NOT NULL,
 "endpointIndex" INTEGER NOT NULL,
 "checkIndex" INTEGER NOT NULL,
 "endpointName" TEXT NOT NULL,
 "templateName" TEXT NOT NULL,
 "severity" TEXT NOT NULL,
 "remediation" TEXT NOT NULL,
 "status" TEXT NOT NULL DEFAULT 'PENDING',
 "reason" TEXT,
 "attempts" INTEGER NOT NULL DEFAULT 0,
 "result" JSONB,
 "findingId" TEXT,
 "startedAt" TIMESTAMP(3),
 "completedAt" TIMESTAMP(3),
 "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
 CONSTRAINT "ScanProbe_pkey" PRIMARY KEY ("id")
);
CREATE UNIQUE INDEX "ScanProbe_targetId_endpointIndex_checkIndex_key" ON "ScanProbe"("targetId", "endpointIndex", "checkIndex");
CREATE INDEX "ScanProbe_targetId_status_idx" ON "ScanProbe"("targetId", "status");
ALTER TABLE "ScanProbe" ADD CONSTRAINT "ScanProbe_targetId_fkey" FOREIGN KEY ("targetId") REFERENCES "ScanTarget"("id") ON DELETE CASCADE ON UPDATE CASCADE;
