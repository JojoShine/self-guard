-- CreateTable
CREATE TABLE "AccessSource" (
    "id" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "assetId" TEXT NOT NULL,
    "instanceId" TEXT,
    "protocol" TEXT NOT NULL,
    "mode" TEXT NOT NULL,
    "interface" TEXT NOT NULL,
    "address" TEXT NOT NULL,
    "port" INTEGER NOT NULL,
    "enabled" BOOLEAN NOT NULL DEFAULT false,
    "version" INTEGER NOT NULL DEFAULT 1,
    "tokenHash" TEXT,
    "issuedAssetTokenHash" TEXT,
    "maxQueueBytes" INTEGER NOT NULL DEFAULT 268435456,
    "rules" JSONB NOT NULL DEFAULT '[]',
    "health" JSONB NOT NULL DEFAULT '{}',
    "lastReportAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "AccessSource_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "AccessObservation" (
    "id" TEXT NOT NULL,
    "sourceId" TEXT NOT NULL,
    "eventId" TEXT NOT NULL,
    "manifestSha256" TEXT NOT NULL,
    "startedAt" TIMESTAMP(3) NOT NULL,
    "endedAt" TIMESTAMP(3) NOT NULL,
    "sessionId" TEXT NOT NULL,
    "operation" TEXT NOT NULL,
    "route" TEXT,
    "sourceIp" TEXT,
    "databaseUser" TEXT,
    "result" TEXT NOT NULL,
    "completeness" TEXT NOT NULL,
    "requestBytes" BIGINT NOT NULL,
    "responseBytes" BIGINT NOT NULL,
    "level" INTEGER,
    "classification" JSONB NOT NULL,
    "metadata" JSONB NOT NULL,
    "findingIds" TEXT[] DEFAULT ARRAY[]::TEXT[],
    "chunkIds" TEXT[] DEFAULT ARRAY[]::TEXT[],
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "AccessObservation_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "AccessEvidenceChunk" (
    "id" TEXT NOT NULL,
    "sourceId" TEXT NOT NULL,
    "eventId" TEXT NOT NULL,
    "direction" TEXT NOT NULL,
    "sequence" INTEGER NOT NULL,
    "capturedAt" TIMESTAMP(3) NOT NULL,
    "expiresAt" TIMESTAMP(3) NOT NULL,
    "sha256" TEXT NOT NULL,
    "bytes" INTEGER NOT NULL,
    "object" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "AccessEvidenceChunk_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "AccessSource_tokenHash_key" ON "AccessSource"("tokenHash");

-- CreateIndex
CREATE INDEX "AccessSource_assetId_enabled_idx" ON "AccessSource"("assetId", "enabled");

-- CreateIndex
CREATE INDEX "AccessSource_instanceId_idx" ON "AccessSource"("instanceId");

-- CreateIndex
CREATE INDEX "AccessObservation_sourceId_startedAt_idx" ON "AccessObservation"("sourceId", "startedAt");

-- CreateIndex
CREATE INDEX "AccessObservation_sessionId_startedAt_idx" ON "AccessObservation"("sessionId", "startedAt");

-- CreateIndex
CREATE INDEX "AccessObservation_completeness_startedAt_idx" ON "AccessObservation"("completeness", "startedAt");

-- CreateIndex
CREATE UNIQUE INDEX "AccessObservation_sourceId_eventId_key" ON "AccessObservation"("sourceId", "eventId");

-- CreateIndex
CREATE INDEX "AccessEvidenceChunk_expiresAt_idx" ON "AccessEvidenceChunk"("expiresAt");

-- CreateIndex
CREATE UNIQUE INDEX "AccessEvidenceChunk_sourceId_eventId_direction_sequence_key" ON "AccessEvidenceChunk"("sourceId", "eventId", "direction", "sequence");

-- AddForeignKey
ALTER TABLE "AccessSource" ADD CONSTRAINT "AccessSource_assetId_fkey" FOREIGN KEY ("assetId") REFERENCES "Asset"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "AccessSource" ADD CONSTRAINT "AccessSource_instanceId_fkey" FOREIGN KEY ("instanceId") REFERENCES "DatabaseInstance"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "AccessObservation" ADD CONSTRAINT "AccessObservation_sourceId_fkey" FOREIGN KEY ("sourceId") REFERENCES "AccessSource"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "AccessEvidenceChunk" ADD CONSTRAINT "AccessEvidenceChunk_sourceId_fkey" FOREIGN KEY ("sourceId") REFERENCES "AccessSource"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

