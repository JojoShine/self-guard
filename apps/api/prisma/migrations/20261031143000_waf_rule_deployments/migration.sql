-- Additive only. No shadow database, reset, replacement or data removal.
ALTER TABLE "Site" ADD COLUMN "ruleDeploymentId" TEXT;
ALTER TABLE "WafEvent" ADD COLUMN "inspection" JSONB;
CREATE TABLE "WafRuleReplay" (
 "id" TEXT NOT NULL, "bundleId" TEXT NOT NULL, "bundleSha256" TEXT NOT NULL,
 "engine" TEXT NOT NULL, "sampleSha256" TEXT NOT NULL, "threshold" INTEGER NOT NULL DEFAULT 5,
 "expectedBlocked" BOOLEAN NOT NULL, "actualBlocked" BOOLEAN NOT NULL,
 "expectedStatus" INTEGER, "actualStatus" INTEGER NOT NULL,
 "passed" BOOLEAN NOT NULL, "result" JSONB NOT NULL, "actor" TEXT NOT NULL,
 "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
 CONSTRAINT "WafRuleReplay_pkey" PRIMARY KEY ("id")
);
CREATE INDEX "WafRuleReplay_bundleId_createdAt_idx" ON "WafRuleReplay"("bundleId", "createdAt");
CREATE TABLE "WafRuleDeployment" (
 "id" TEXT NOT NULL, "siteId" TEXT NOT NULL, "siteVersion" INTEGER NOT NULL,
 "bundleId" TEXT, "bundleSha256" TEXT NOT NULL, "mode" TEXT NOT NULL,
 "threshold" INTEGER NOT NULL, "envelope" JSONB NOT NULL,
 "previousId" TEXT, "actor" TEXT NOT NULL, "reason" TEXT NOT NULL,
 "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
 CONSTRAINT "WafRuleDeployment_pkey" PRIMARY KEY ("id")
);
CREATE UNIQUE INDEX "WafRuleDeployment_siteId_siteVersion_key" ON "WafRuleDeployment"("siteId", "siteVersion");
CREATE INDEX "WafRuleDeployment_bundleId_createdAt_idx" ON "WafRuleDeployment"("bundleId", "createdAt");
