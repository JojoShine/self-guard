CREATE TABLE "IntelligenceArtifact" (
    "sha256" TEXT NOT NULL,
    "size" INTEGER NOT NULL,
    "encoding" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT "IntelligenceArtifact_pkey" PRIMARY KEY ("sha256")
);

ALTER TABLE "VulnerabilitySnapshot"
    ADD COLUMN "normalizerVersion" TEXT NOT NULL DEFAULT 'selfguard-intelligence-v1',
    ADD COLUMN "artifactSha256" TEXT,
    ADD COLUMN "reservedArtifactBytes" INTEGER NOT NULL DEFAULT 0,
    ADD COLUMN "sourceManifest" JSONB NOT NULL DEFAULT '{}';

CREATE INDEX "VulnerabilitySnapshot_artifactSha256_idx" ON "VulnerabilitySnapshot"("artifactSha256");

ALTER TABLE "VulnerabilitySnapshot" ADD CONSTRAINT "VulnerabilitySnapshot_artifactSha256_fkey"
    FOREIGN KEY ("artifactSha256") REFERENCES "IntelligenceArtifact"("sha256") ON DELETE RESTRICT ON UPDATE CASCADE;
