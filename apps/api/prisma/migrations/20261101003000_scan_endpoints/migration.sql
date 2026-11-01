CREATE TABLE "ScanEndpoint" (
 "id" TEXT NOT NULL,
 "assetId" TEXT NOT NULL,
 "name" TEXT NOT NULL,
 "hostname" TEXT NOT NULL,
 "port" INTEGER NOT NULL,
 "protocol" TEXT NOT NULL,
 "allowedPaths" TEXT[],
 "excludedPaths" TEXT[],
 "approvedAddresses" TEXT[] DEFAULT ARRAY[]::TEXT[],
 "status" TEXT NOT NULL DEFAULT 'DRAFT',
 "version" INTEGER NOT NULL DEFAULT 1,
 "configHash" TEXT NOT NULL,
 "approvalHash" TEXT,
 "approvedAt" TIMESTAMP(3),
 "approvedBy" TEXT,
 "creatorId" TEXT NOT NULL,
 "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
 "updatedAt" TIMESTAMP(3) NOT NULL,
 CONSTRAINT "ScanEndpoint_pkey" PRIMARY KEY ("id")
);
CREATE UNIQUE INDEX "ScanEndpoint_assetId_hostname_port_protocol_key" ON "ScanEndpoint"("assetId","hostname","port","protocol");
CREATE INDEX "ScanEndpoint_status_assetId_idx" ON "ScanEndpoint"("status","assetId");
