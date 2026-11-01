CREATE TABLE "AssetRemoteAccess" (
 "assetId" TEXT PRIMARY KEY REFERENCES "Asset"("id") ON DELETE CASCADE,
 "address" TEXT NOT NULL, "username" TEXT NOT NULL, "port" INTEGER NOT NULL,
 "hostKey" TEXT NOT NULL, "credential" TEXT NOT NULL, "updatedAt" TIMESTAMP(3) NOT NULL
);
CREATE TABLE "AssetRemoteJob" (
 "id" TEXT PRIMARY KEY, "assetId" TEXT NOT NULL REFERENCES "Asset"("id") ON DELETE CASCADE,
 "ownerId" TEXT NOT NULL, "address" TEXT NOT NULL, "accessUpdatedAt" TIMESTAMP(3) NOT NULL,
 "config" JSONB NOT NULL, "status" TEXT NOT NULL DEFAULT 'QUEUED', "detail" TEXT NOT NULL DEFAULT '等待执行',
 "result" JSONB, "leaseUntil" TIMESTAMP(3), "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
 "updatedAt" TIMESTAMP(3) NOT NULL
);
CREATE INDEX "AssetRemoteJob_status_createdAt_idx" ON "AssetRemoteJob"("status","createdAt");
CREATE INDEX "AssetRemoteJob_assetId_createdAt_idx" ON "AssetRemoteJob"("assetId","createdAt");
CREATE UNIQUE INDEX "AssetRemoteJob_one_active_per_asset" ON "AssetRemoteJob"("assetId") WHERE "status" IN ('QUEUED','RUNNING');
