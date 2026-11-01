CREATE TABLE "Revision" (
 "id" TEXT NOT NULL, "resource" TEXT NOT NULL, "resourceId" TEXT NOT NULL, "version" INTEGER NOT NULL,
 "snapshot" JSONB NOT NULL, "actor" TEXT NOT NULL, "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
 CONSTRAINT "Revision_pkey" PRIMARY KEY ("id")
);
CREATE UNIQUE INDEX "Revision_resource_resourceId_version_key" ON "Revision"("resource","resourceId","version");
