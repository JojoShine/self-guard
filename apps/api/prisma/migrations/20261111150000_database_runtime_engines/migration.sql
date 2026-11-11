ALTER TABLE "OperationalMonitor" DROP CONSTRAINT "OperationalMonitor_target";
ALTER TABLE "OperationalMonitor" ADD CONSTRAINT "OperationalMonitor_target"
 CHECK (("kind" = 'HOST' AND "assetId" IS NOT NULL AND "instanceId" IS NULL)
 OR ("kind" IN ('POSTGRESQL', 'DATABASE') AND "instanceId" IS NOT NULL AND "assetId" IS NULL));
