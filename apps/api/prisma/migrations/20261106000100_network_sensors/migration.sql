-- CreateTable
CREATE TABLE "NetworkSensor" (
    "id" TEXT NOT NULL,
    "assetId" TEXT NOT NULL,
    "ownerId" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "enabled" BOOLEAN NOT NULL DEFAULT false,
    "version" INTEGER NOT NULL DEFAULT 1,
    "tokenHash" TEXT,
    "evePath" TEXT NOT NULL,
    "engineVersion" TEXT NOT NULL DEFAULT '',
    "ruleFile" TEXT,
    "ruleSetName" TEXT NOT NULL DEFAULT '',
    "ruleSetVersion" TEXT NOT NULL DEFAULT '',
    "ruleSourceUrl" TEXT,
    "expectedRuleSha256" TEXT,
    "updateEveryHours" INTEGER NOT NULL DEFAULT 24,
    "lastReportedAt" TIMESTAMP(3),
    "lastEventAt" TIMESTAMP(3),
    "lastStatsAt" TIMESTAMP(3),
    "lastMode" TEXT,
    "health" JSONB NOT NULL DEFAULT '{}',
    "stats" JSONB NOT NULL DEFAULT '{}',
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "NetworkSensor_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "NetworkSensorEvent" (
    "id" TEXT NOT NULL,
    "sensorId" TEXT NOT NULL,
    "assetId" TEXT NOT NULL,
    "eventId" TEXT NOT NULL,
    "sourceSha256" TEXT NOT NULL,
    "contentSha256" TEXT NOT NULL,
    "occurredAt" TIMESTAMP(3) NOT NULL,
    "eventType" TEXT NOT NULL,
    "flowId" TEXT,
    "sourceIp" TEXT,
    "destinationIp" TEXT,
    "sourcePort" INTEGER,
    "destinationPort" INTEGER,
    "protocol" TEXT,
    "appProtocol" TEXT,
    "metadata" JSONB NOT NULL,
    "findingId" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "NetworkSensorEvent_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "NetworkSensorBatch" (
    "id" TEXT NOT NULL,
    "sensorId" TEXT NOT NULL,
    "batchId" TEXT NOT NULL,
    "contentSha256" TEXT NOT NULL,
    "result" JSONB NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "NetworkSensorBatch_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "NetworkSensorEventIdentity" (
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "sensorId" TEXT NOT NULL,
    "eventId" TEXT NOT NULL,
    "contentSha256" TEXT NOT NULL,

    CONSTRAINT "NetworkSensorEventIdentity_pkey" PRIMARY KEY ("sensorId","eventId")
);

-- CreateIndex
CREATE INDEX "NetworkSensor_assetId_createdAt_idx" ON "NetworkSensor"("assetId", "createdAt");

-- CreateIndex
CREATE INDEX "NetworkSensorEvent_sensorId_occurredAt_idx" ON "NetworkSensorEvent"("sensorId", "occurredAt");

-- CreateIndex
CREATE INDEX "NetworkSensorEvent_sensorId_flowId_occurredAt_idx" ON "NetworkSensorEvent"("sensorId", "flowId", "occurredAt");

-- CreateIndex
CREATE INDEX "NetworkSensorEvent_assetId_occurredAt_idx" ON "NetworkSensorEvent"("assetId", "occurredAt");

-- CreateIndex
CREATE UNIQUE INDEX "NetworkSensorEvent_sensorId_eventId_key" ON "NetworkSensorEvent"("sensorId", "eventId");

-- CreateIndex
CREATE INDEX "NetworkSensorBatch_createdAt_idx" ON "NetworkSensorBatch"("createdAt");

-- CreateIndex
CREATE UNIQUE INDEX "NetworkSensorBatch_sensorId_batchId_key" ON "NetworkSensorBatch"("sensorId", "batchId");

-- CreateIndex
CREATE INDEX "NetworkSensorEventIdentity_sensorId_createdAt_idx" ON "NetworkSensorEventIdentity"("sensorId", "createdAt");

-- AddForeignKey
ALTER TABLE "NetworkSensor" ADD CONSTRAINT "NetworkSensor_assetId_fkey" FOREIGN KEY ("assetId") REFERENCES "Asset"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "NetworkSensorEvent" ADD CONSTRAINT "NetworkSensorEvent_sensorId_fkey" FOREIGN KEY ("sensorId") REFERENCES "NetworkSensor"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "NetworkSensorEvent" ADD CONSTRAINT "NetworkSensorEvent_assetId_fkey" FOREIGN KEY ("assetId") REFERENCES "Asset"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "NetworkSensorEvent" ADD CONSTRAINT "NetworkSensorEvent_findingId_fkey" FOREIGN KEY ("findingId") REFERENCES "Finding"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "NetworkSensorBatch" ADD CONSTRAINT "NetworkSensorBatch_sensorId_fkey" FOREIGN KEY ("sensorId") REFERENCES "NetworkSensor"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "NetworkSensorEventIdentity" ADD CONSTRAINT "NetworkSensorEventIdentity_sensorId_fkey" FOREIGN KEY ("sensorId") REFERENCES "NetworkSensor"("id") ON DELETE CASCADE ON UPDATE CASCADE;

