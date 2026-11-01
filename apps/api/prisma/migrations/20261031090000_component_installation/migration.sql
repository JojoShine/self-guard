CREATE TABLE "BusinessGroup" ("id" TEXT NOT NULL,"name" TEXT NOT NULL,"createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,CONSTRAINT "BusinessGroup_pkey" PRIMARY KEY ("id"));
CREATE UNIQUE INDEX "BusinessGroup_name_key" ON "BusinessGroup"("name");
INSERT INTO "BusinessGroup" (id,name) SELECT md5('selfguard-business:' || business)::uuid::text,business FROM "Asset" WHERE business IS NOT NULL AND business<>'' GROUP BY business ON CONFLICT DO NOTHING;
CREATE TABLE "AgentRelease" (
 "id" TEXT NOT NULL,"version" TEXT NOT NULL,"sequence" INTEGER NOT NULL,"architecture" TEXT NOT NULL,"manifestBytes" TEXT NOT NULL,"signature" TEXT NOT NULL,"sha256" TEXT NOT NULL,"size" INTEGER NOT NULL,"expiresAt" TIMESTAMP(3) NOT NULL,"sourceDigest" TEXT NOT NULL,"license" TEXT NOT NULL,"sbom" JSONB NOT NULL,"channel" TEXT NOT NULL DEFAULT 'stable',"status" TEXT NOT NULL DEFAULT 'DRAFT',"author" TEXT NOT NULL,"createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,"publishedAt" TIMESTAMP(3),"revokedAt" TIMESTAMP(3),CONSTRAINT "AgentRelease_pkey" PRIMARY KEY ("id")
);
CREATE UNIQUE INDEX "AgentRelease_sequence_architecture_key" ON "AgentRelease"("sequence","architecture");
CREATE UNIQUE INDEX "AgentRelease_version_architecture_key" ON "AgentRelease"("version","architecture");
CREATE INDEX "AgentRelease_status_channel_createdAt_idx" ON "AgentRelease"("status","channel","createdAt");
CREATE TABLE "AgentInstallation" (
 "id" TEXT NOT NULL,"releaseId" TEXT NOT NULL,"ownerId" TEXT NOT NULL,"profile" JSONB NOT NULL,"ticketHash" TEXT NOT NULL,"expiresAt" TIMESTAMP(3) NOT NULL,"claimedIdentity" TEXT,"credentialHash" TEXT,"leaseUntil" TIMESTAMP(3),"assetId" TEXT,"challenge" TEXT NOT NULL,"status" TEXT NOT NULL DEFAULT 'WAITING',"detail" TEXT NOT NULL DEFAULT '',"revokedAt" TIMESTAMP(3),"createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,"updatedAt" TIMESTAMP(3) NOT NULL,CONSTRAINT "AgentInstallation_pkey" PRIMARY KEY ("id"),CONSTRAINT "AgentInstallation_releaseId_fkey" FOREIGN KEY ("releaseId") REFERENCES "AgentRelease"("id") ON DELETE RESTRICT ON UPDATE CASCADE
);
CREATE UNIQUE INDEX "AgentInstallation_ticketHash_key" ON "AgentInstallation"("ticketHash");
CREATE INDEX "AgentInstallation_ownerId_createdAt_idx" ON "AgentInstallation"("ownerId","createdAt");
CREATE INDEX "AgentInstallation_assetId_idx" ON "AgentInstallation"("assetId");
