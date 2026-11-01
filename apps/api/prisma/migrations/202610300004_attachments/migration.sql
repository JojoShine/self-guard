CREATE TABLE "Attachment" (
 "id" TEXT NOT NULL, "resource" TEXT NOT NULL, "resourceId" TEXT NOT NULL, "name" TEXT NOT NULL,
 "contentType" TEXT NOT NULL, "size" INTEGER NOT NULL, "data" BYTEA NOT NULL, "author" TEXT NOT NULL,
 "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP, CONSTRAINT "Attachment_pkey" PRIMARY KEY ("id")
);
CREATE INDEX "Attachment_resource_resourceId_idx" ON "Attachment"("resource","resourceId");
