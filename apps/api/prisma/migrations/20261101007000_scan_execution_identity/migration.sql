CREATE TABLE "ScanExecutionIdentity" (
    "id" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "scope" JSONB NOT NULL,
    "enabled" BOOLEAN NOT NULL DEFAULT true,
    "version" INTEGER NOT NULL DEFAULT 1,
    "approvedBy" TEXT NOT NULL,
    "approvedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,
    CONSTRAINT "ScanExecutionIdentity_pkey" PRIMARY KEY ("id"),
    CONSTRAINT "ScanExecutionIdentity_version_positive" CHECK ("version" > 0)
);
ALTER TABLE "ScanPlan" ADD COLUMN "executionIdentityId" TEXT,
    ADD COLUMN "executionIdentityVersion" INTEGER;
ALTER TABLE "ScanPlan" ADD CONSTRAINT "ScanPlan_executionIdentityId_fkey"
    FOREIGN KEY ("executionIdentityId") REFERENCES "ScanExecutionIdentity"("id") ON DELETE RESTRICT ON UPDATE CASCADE;
ALTER TABLE "ScanPlan" ADD CONSTRAINT "ScanPlan_executionIdentity_binding"
    CHECK (("executionIdentityId" IS NULL AND "executionIdentityVersion" IS NULL)
        OR ("executionIdentityId" IS NOT NULL AND "executionIdentityVersion" IS NOT NULL AND "executionIdentityVersion" > 0));
ALTER TABLE "ScanRun" ADD COLUMN "executionIdentity" JSONB;
CREATE INDEX "ScanExecutionIdentity_enabled_createdAt_idx" ON "ScanExecutionIdentity"("enabled", "createdAt");
CREATE INDEX "ScanPlan_executionIdentityId_idx" ON "ScanPlan"("executionIdentityId");
