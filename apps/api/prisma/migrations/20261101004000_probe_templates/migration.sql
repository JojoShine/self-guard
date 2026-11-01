CREATE TABLE "ProbeTemplate" (
 "id" TEXT NOT NULL,
 "name" TEXT NOT NULL,
 "purpose" TEXT NOT NULL,
 "severity" TEXT NOT NULL,
 "sourceKind" TEXT NOT NULL DEFAULT 'LOCAL',
 "definition" JSONB NOT NULL,
 "samples" JSONB NOT NULL,
 "status" TEXT NOT NULL DEFAULT 'DRAFT',
 "version" INTEGER NOT NULL DEFAULT 1,
 "configHash" TEXT NOT NULL,
 "validationReport" JSONB,
 "validatedHash" TEXT,
 "validatedAt" TIMESTAMP(3),
 "approvalHash" TEXT,
 "approvedAt" TIMESTAMP(3),
 "approvedBy" TEXT,
 "creatorId" TEXT NOT NULL,
 "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
 "updatedAt" TIMESTAMP(3) NOT NULL,
 CONSTRAINT "ProbeTemplate_pkey" PRIMARY KEY ("id")
);
CREATE INDEX "ProbeTemplate_status_purpose_idx" ON "ProbeTemplate"("status", "purpose");
