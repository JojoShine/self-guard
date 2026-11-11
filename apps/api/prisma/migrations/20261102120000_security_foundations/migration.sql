-- AlterTable
ALTER TABLE "Finding" ADD COLUMN     "instanceId" TEXT;

-- CreateTable
CREATE TABLE "DatabaseInstance" (
    "id" TEXT NOT NULL,
    "stableKey" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "engine" TEXT NOT NULL,
    "version" TEXT,
    "business" TEXT,
    "owner" TEXT NOT NULL,
    "hostIds" TEXT[] DEFAULT ARRAY[]::TEXT[],
    "auditSources" JSONB NOT NULL DEFAULT '[]',
    "endpoints" JSONB NOT NULL DEFAULT '[]',
    "archivedAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "DatabaseInstance_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "AssetCandidate" (
    "id" TEXT NOT NULL,
    "key" TEXT NOT NULL,
    "sourceAssetId" TEXT NOT NULL,
    "address" TEXT NOT NULL,
    "port" INTEGER NOT NULL,
    "protocol" TEXT NOT NULL,
    "basis" TEXT NOT NULL,
    "status" TEXT NOT NULL DEFAULT 'PENDING',
    "lastReportKey" TEXT,
    "observations" INTEGER NOT NULL DEFAULT 1,
    "targetAssetId" TEXT,
    "instanceId" TEXT,
    "reason" TEXT,
    "firstSeen" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "lastSeen" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "AssetCandidate_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "DataClassification" (
    "id" TEXT NOT NULL,
    "instanceId" TEXT NOT NULL,
    "engine" TEXT NOT NULL,
    "database" TEXT NOT NULL,
    "schema" TEXT NOT NULL DEFAULT '',
    "table" TEXT NOT NULL DEFAULT '',
    "column" TEXT NOT NULL DEFAULT '',
    "category" TEXT NOT NULL,
    "level" INTEGER NOT NULL,
    "requirements" JSONB NOT NULL DEFAULT '{}',
    "handling" TEXT NOT NULL,
    "status" TEXT NOT NULL DEFAULT 'DRAFT',
    "version" INTEGER NOT NULL DEFAULT 1,
    "reason" TEXT NOT NULL,
    "confirmedBy" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "DataClassification_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "DataObject" (
    "id" TEXT NOT NULL,
    "instanceId" TEXT NOT NULL,
    "database" TEXT NOT NULL,
    "schema" TEXT NOT NULL DEFAULT '',
    "table" TEXT NOT NULL DEFAULT '',
    "column" TEXT NOT NULL DEFAULT '',
    "source" TEXT NOT NULL,
    "firstSeen" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "lastSeen" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "DataObject_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "DatabaseAudit" (
    "id" TEXT NOT NULL,
    "dedupKey" TEXT NOT NULL,
    "eventId" TEXT NOT NULL,
    "instanceId" TEXT NOT NULL,
    "collectorAssetId" TEXT,
    "findingId" TEXT,
    "engine" TEXT NOT NULL,
    "database" TEXT,
    "schema" TEXT,
    "table" TEXT,
    "user" TEXT NOT NULL,
    "sourceIp" TEXT,
    "operation" TEXT NOT NULL,
    "timestamp" TIMESTAMP(3) NOT NULL,
    "level" INTEGER,
    "classification" JSONB NOT NULL,
    "details" JSONB NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "DatabaseAudit_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "DatabaseInstance_stableKey_key" ON "DatabaseInstance"("stableKey");

-- CreateIndex
CREATE INDEX "DatabaseInstance_business_engine_idx" ON "DatabaseInstance"("business", "engine");

-- CreateIndex
CREATE UNIQUE INDEX "AssetCandidate_key_key" ON "AssetCandidate"("key");

-- CreateIndex
CREATE INDEX "AssetCandidate_sourceAssetId_status_lastSeen_idx" ON "AssetCandidate"("sourceAssetId", "status", "lastSeen");

-- CreateIndex
CREATE UNIQUE INDEX "DataClassification_instanceId_database_schema_table_column_key" ON "DataClassification"("instanceId", "database", "schema", "table", "column");

-- CreateIndex
CREATE UNIQUE INDEX "DataObject_instanceId_database_schema_table_column_key" ON "DataObject"("instanceId", "database", "schema", "table", "column");

-- CreateIndex
CREATE UNIQUE INDEX "DatabaseAudit_dedupKey_key" ON "DatabaseAudit"("dedupKey");

-- CreateIndex
CREATE INDEX "DatabaseAudit_instanceId_engine_database_timestamp_idx" ON "DatabaseAudit"("instanceId", "engine", "database", "timestamp");

-- CreateIndex
CREATE INDEX "DatabaseAudit_findingId_idx" ON "DatabaseAudit"("findingId");

-- AddForeignKey
ALTER TABLE "Finding" ADD CONSTRAINT "Finding_instanceId_fkey" FOREIGN KEY ("instanceId") REFERENCES "DatabaseInstance"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "DataClassification" ADD CONSTRAINT "DataClassification_instanceId_fkey" FOREIGN KEY ("instanceId") REFERENCES "DatabaseInstance"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "DataObject" ADD CONSTRAINT "DataObject_instanceId_fkey" FOREIGN KEY ("instanceId") REFERENCES "DatabaseInstance"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "DatabaseAudit" ADD CONSTRAINT "DatabaseAudit_instanceId_fkey" FOREIGN KEY ("instanceId") REFERENCES "DatabaseInstance"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

