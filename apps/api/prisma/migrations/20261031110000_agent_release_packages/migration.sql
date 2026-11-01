CREATE TABLE "AgentReleasePackage" (
 "id" TEXT NOT NULL,
 "releaseId" TEXT NOT NULL,
 "format" TEXT NOT NULL,
 "sha256" TEXT NOT NULL,
 "size" INTEGER NOT NULL,
 "manifestBytes" TEXT NOT NULL,
 "signature" TEXT NOT NULL,
 "expiresAt" TIMESTAMP(3) NOT NULL,
 "status" TEXT NOT NULL DEFAULT 'DRAFT',
 "author" TEXT NOT NULL,
 "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
 "publishedAt" TIMESTAMP(3),
 CONSTRAINT "AgentReleasePackage_pkey" PRIMARY KEY ("id"),
 CONSTRAINT "AgentReleasePackage_releaseId_fkey" FOREIGN KEY ("releaseId") REFERENCES "AgentRelease"("id") ON DELETE RESTRICT ON UPDATE CASCADE
);
CREATE UNIQUE INDEX "AgentReleasePackage_releaseId_format_key" ON "AgentReleasePackage"("releaseId","format");
CREATE INDEX "AgentReleasePackage_releaseId_status_idx" ON "AgentReleasePackage"("releaseId","status");
