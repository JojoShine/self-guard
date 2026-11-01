#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
file=${1:?Pass the path to a database dump}
test -s "$file"
compose=${COMPOSE_FILE:-compose.dev.yaml}
db="selfguard_restore_check_$(date +%s)"
registry=".artifacts/backups/.restore-$db.artifacts"
cleanup(){ rm -f "$registry"; docker compose -f "$compose" exec -T postgres dropdb -U selfguard --if-exists "$db" >/dev/null; }
trap cleanup EXIT
docker compose -f "$compose" exec -T postgres createdb -U selfguard "$db"
cat "$file" | docker compose -f "$compose" exec -T postgres pg_restore -U selfguard -d "$db" --no-owner --exit-on-error
docker compose -f "$compose" exec -T postgres psql -U selfguard -d "$db" -v ON_ERROR_STOP=1 -c 'SELECT count(*) AS restored_assets FROM "Asset";'
if [ -f "$file.artifacts" ]; then
 umask 077
 docker compose -f "$compose" exec -T postgres psql -U selfguard -d "$db" -At -v ON_ERROR_STOP=1 > "$registry" <<'SQL'
SELECT sha256 || '|' || size || '|' || encoding FROM "IntelligenceArtifact" ORDER BY sha256;
SQL
 docker compose -f "$compose" exec -T backup sh /scripts/verify-intelligence-backup.sh "/backups/$(basename "$file").artifacts" "/backups/$(basename "$registry")"
else
 printf 'Historical dump has no original-file manifest; original sources are not verified.\n'
fi
printf 'Isolated database restore verification passed.\n' 
