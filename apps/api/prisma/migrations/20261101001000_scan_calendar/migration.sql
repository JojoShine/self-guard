-- Additive only: retain all existing fixed-interval plans and run history.
ALTER TABLE "ScanPlan" ADD COLUMN "timing" JSONB;
ALTER TABLE "ScanRun" ADD COLUMN "timing" JSONB;
