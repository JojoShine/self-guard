CREATE TABLE "Evaluation" (
 "id" TEXT NOT NULL, "ruleId" TEXT NOT NULL, "ruleName" TEXT NOT NULL, "kind" TEXT NOT NULL, "assetId" TEXT NOT NULL,
 "status" TEXT NOT NULL, "matched" BOOLEAN NOT NULL, "evidence" TEXT NOT NULL, "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
 CONSTRAINT "Evaluation_pkey" PRIMARY KEY ("id")
);
CREATE INDEX "Evaluation_ruleId_createdAt_idx" ON "Evaluation"("ruleId","createdAt");
