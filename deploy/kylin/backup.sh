#!/bin/bash
set -euo pipefail
umask 077
base=/opt/self-guard
exec 9>"$base/state/complete-backup.lock"
flock -n 9 || exit 0
# The database dump, original sources and public packages are readable only by the backup service UID.
postgres_image=$(python3 -c 'import json;print(json.load(open("/opt/self-guard/current/manifest.json"))["images"]["postgres"])')
/opt/self-guard/bin/podman run --rm --net bridge --user 1000:1000 --read-only --cap-drop ALL --security-opt no-new-privileges \
  --memory 256m --cpus 0.5 --tmpfs /tmp:rw,nosuid,nodev,size=32m,mode=1777 \
  -e PGHOST=10.88.0.10 -e PGUSER=selfguard_runtime -e PGDATABASE=selfguard -e PGPASSFILE=/run/secrets/pgpass \
  -v "$base/secrets/pgpass:/run/secrets/pgpass:ro" -v "$base/backups/database:/backups" \
  -v "$base/data/intelligence:/intelligence-artifacts:ro" \
  -v "$base/current/scripts/scheduled-backup.sh:/scripts/backup.sh:ro" \
  "$postgres_image" sh /scripts/backup.sh --once
stamp=$(date -u +%Y%m%dT%H%M%SZ)
# Keys stay root-only and outside the database backup container.
tar -C "$base" -czf "$base/backups/private/identity-$stamp.tar.gz.partial" secrets acme current/manifest.json
mv "$base/backups/private/identity-$stamp.tar.gz.partial" "$base/backups/private/identity-$stamp.tar.gz"
# Agent objects are immutable; never overwrite an existing object with different bytes.
python3 "$base/current/scripts/backup-agent-artifacts.py" "$base/data/agent-artifacts" "$base/backups/agent-artifacts"
find "$base/backups/private" -name 'identity-*.tar.gz' -type f -mtime +30 -delete
