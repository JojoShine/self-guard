-- Historical rows have unknown provenance; do not infer live capture from timestamps.
ALTER TABLE "NetworkSensorEvent" ADD COLUMN "mode" TEXT NOT NULL DEFAULT 'UNKNOWN';
