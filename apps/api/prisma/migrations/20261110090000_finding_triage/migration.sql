CREATE TABLE "FindingTriage" (
 "findingId" TEXT PRIMARY KEY, "conclusion" TEXT NOT NULL, "duplicateOfId" TEXT,
 "reason" TEXT NOT NULL, "updatedBy" TEXT NOT NULL, "updatedAt" TIMESTAMP(3) NOT NULL,
 CONSTRAINT "FindingTriage_findingId_fkey" FOREIGN KEY ("findingId") REFERENCES "Finding"("id") ON DELETE CASCADE ON UPDATE CASCADE,
 CONSTRAINT "FindingTriage_duplicateOfId_fkey" FOREIGN KEY ("duplicateOfId") REFERENCES "Finding"("id") ON DELETE RESTRICT ON UPDATE CASCADE,
 CONSTRAINT "FindingTriage_shape" CHECK (("conclusion"='DUPLICATE' AND "duplicateOfId" IS NOT NULL) OR ("conclusion"='INSUFFICIENT_EVIDENCE' AND "duplicateOfId" IS NULL))
);
CREATE INDEX "FindingTriage_duplicateOfId_idx" ON "FindingTriage"("duplicateOfId");
