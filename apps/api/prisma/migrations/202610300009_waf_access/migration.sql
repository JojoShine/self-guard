CREATE TABLE "WafAccess" ("id" TEXT PRIMARY KEY,"nodeId" TEXT NOT NULL,"siteId" TEXT NOT NULL,"method" TEXT NOT NULL,"path" TEXT NOT NULL,"status" INTEGER NOT NULL,"timestamp" TIMESTAMP(3) NOT NULL,"durationMicros" INTEGER NOT NULL);
CREATE INDEX "WafAccess_nodeId_timestamp_idx" ON "WafAccess"("nodeId","timestamp");
