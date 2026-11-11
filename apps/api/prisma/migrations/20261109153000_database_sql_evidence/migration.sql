CREATE TABLE "DatabaseSqlEvidence" (
 "id" TEXT NOT NULL, "auditId" TEXT NOT NULL, "ciphertext" TEXT NOT NULL,
 "bytes" INTEGER NOT NULL, "expiresAt" TIMESTAMP(3) NOT NULL,
 CONSTRAINT "DatabaseSqlEvidence_pkey" PRIMARY KEY ("id"),
 CONSTRAINT "DatabaseSqlEvidence_auditId_fkey" FOREIGN KEY ("auditId") REFERENCES "DatabaseAudit"("id") ON DELETE CASCADE ON UPDATE CASCADE
);
CREATE UNIQUE INDEX "DatabaseSqlEvidence_auditId_key" ON "DatabaseSqlEvidence"("auditId");
CREATE INDEX "DatabaseSqlEvidence_expiresAt_idx" ON "DatabaseSqlEvidence"("expiresAt");
