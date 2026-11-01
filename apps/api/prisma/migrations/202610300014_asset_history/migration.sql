CREATE TABLE "AssetChange" ("id" TEXT PRIMARY KEY,"assetId" TEXT NOT NULL,"actor" TEXT NOT NULL,"changes" JSONB NOT NULL,"createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP);
CREATE INDEX "AssetChange_assetId_createdAt_idx" ON "AssetChange"("assetId","createdAt");
