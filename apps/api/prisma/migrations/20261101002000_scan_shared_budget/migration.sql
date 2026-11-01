ALTER TABLE "ScanTarget" ADD COLUMN "httpRequests" INTEGER NOT NULL DEFAULT 0;
CREATE TABLE "ScanBudgetBucket" (
 "key" TEXT NOT NULL,
 "nextAllowedAt" TIMESTAMP(3) NOT NULL,
 "updatedAt" TIMESTAMP(3) NOT NULL,
 CONSTRAINT "ScanBudgetBucket_pkey" PRIMARY KEY ("key")
);
CREATE INDEX "ScanBudgetBucket_updatedAt_idx" ON "ScanBudgetBucket"("updatedAt");
