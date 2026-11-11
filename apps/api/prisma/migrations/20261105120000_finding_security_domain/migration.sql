CREATE TYPE "SecurityDomain" AS ENUM ('NETWORK', 'DATA', 'UNCLASSIFIED');
ALTER TABLE "Finding" ADD COLUMN "securityDomain" "SecurityDomain" NOT NULL DEFAULT 'UNCLASSIFIED';
UPDATE "Finding" SET "securityDomain" = 'DATA' WHERE source = 'database-security';
UPDATE "Finding" SET "securityDomain" = 'NETWORK' WHERE source IN ('vulnerability', 'active-scan', 'agent-fim');
CREATE INDEX "Finding_securityDomain_createdAt_idx" ON "Finding"("securityDomain", "createdAt");
