#!/bin/sh
set -eu
umask 077
folder=${BACKUP_DIR:-/backups}
mkdir -p "$folder"
backup_artifacts(){
 manifest=$1
 source_objects="${INTELLIGENCE_BACKUP_SOURCE_DIR:-/intelligence-artifacts}/objects"
 artifact_count=0
 exists=$(psql -At -v ON_ERROR_STOP=1 -c "SELECT to_regclass('\"IntelligenceArtifact\"') IS NOT NULL") || return 1
 if [ "$exists" = 't' ]; then
  psql -At -v ON_ERROR_STOP=1 -c "SELECT sha256 || '|' || size || '|' || encoding FROM \"IntelligenceArtifact\" ORDER BY sha256" > "$manifest" || return 1
 else
  : > "$manifest" || return 1
 fi
 mkdir -p "$folder/intelligence-objects" || return 1
 while IFS='|' read -r artifact_sha artifact_size artifact_encoding; do
  [ -n "$artifact_sha" ] || continue
  case "$artifact_sha" in *[!0-9a-f]*) return 1;; esac
  [ "${#artifact_sha}" -eq 64 ] || return 1
  case "$artifact_size" in ''|*[!0-9]*) return 1;; esac
  case "$artifact_encoding" in ZIP|GZIP_JSON) :;; *) return 1;; esac
  destination="$folder/intelligence-objects/$artifact_sha.blob"
  if [ ! -f "$destination" ]; then
   cp "$source_objects/$artifact_sha.blob" "$destination.partial" || return 1
   chmod 600 "$destination.partial" || return 1
   actual=$(sha256sum "$destination.partial" | cut -d ' ' -f 1)
   [ "$actual" = "$artifact_sha" ] || { rm -f "$destination.partial"; return 1; }
   mv "$destination.partial" "$destination" || return 1
  fi
  actual=$(sha256sum "$destination" | cut -d ' ' -f 1)
  [ "$actual" = "$artifact_sha" ] || return 1
  actual_size=$(wc -c < "$destination")
  [ "$actual_size" -eq "$artifact_size" ] || return 1
  artifact_count=$((artifact_count+1))
 done < "$manifest"
}
backup_once(){
 stamp=$(date -u +%Y%m%dT%H%M%SZ)
 target="$folder/selfguard-$stamp.dump"
 if pg_dump -Fc --file="$target.partial" && backup_artifacts "$target.artifacts.partial"; then
  mv "$target.partial" "$target"
  mv "$target.artifacts.partial" "$target.artifacts"
  psql -v ON_ERROR_STOP=1 -c "INSERT INTO \"Setting\"(key,value,\"updatedAt\") VALUES('backup:last',jsonb_build_object('status','SUCCEEDED','completedAt',CURRENT_TIMESTAMP,'file','selfguard-$stamp.dump','sourceArtifactsIncluded',true,'sourceArtifactCount',$artifact_count),CURRENT_TIMESTAMP) ON CONFLICT(key) DO UPDATE SET value=EXCLUDED.value,\"updatedAt\"=CURRENT_TIMESTAMP" >/dev/null
  keep=$(psql -At -c "SELECT COALESCE((value->>'keepCount')::int,7) FROM \"Setting\" WHERE key='backup:policy'")
  case "$keep" in ''|*[!0-9]*) keep=7;; esac
  [ "$keep" -ge 1 ] && [ "$keep" -le 30 ] || keep=7
  ls -1t "$folder"/selfguard-*.dump | tail -n +$((keep+1)) | while IFS= read -r old; do rm -f "$old" "$old.artifacts"; done
  echo "Backup completed: selfguard-$stamp.dump"
 else
  rm -f "$target.partial" "$target.artifacts.partial"
  psql -c "INSERT INTO \"Setting\"(key,value,\"updatedAt\") VALUES('backup:last',jsonb_build_object('status','FAILED','completedAt',CURRENT_TIMESTAMP),CURRENT_TIMESTAMP) ON CONFLICT(key) DO UPDATE SET value=EXCLUDED.value,\"updatedAt\"=CURRENT_TIMESTAMP" >/dev/null 2>&1 || true
  return 1
 fi
}
if [ "${1:-}" = '--locked' ]; then backup_once; exit; fi
if [ "${1:-}" = '--once' ]; then exec flock -n "$folder/.selfguard-backup.lock" sh "$0" --locked; fi
tick=${BACKUP_TICK_SECONDS:-60}
case "$tick" in ''|*[!0-9]*) tick=60;; esac
[ "$tick" -ge 1 ] && [ "$tick" -le 3600 ] || tick=60
while :; do
 due=$(psql -At -c "SELECT COALESCE((p.value->>'enabled')::boolean,false) AND (b.value IS NULL OR (b.value->>'completedAt')::timestamptz < NOW()-make_interval(hours=>COALESCE((p.value->>'intervalHours')::int,24))) FROM \"Setting\" p LEFT JOIN \"Setting\" b ON b.key='backup:last' WHERE p.key='backup:policy'" 2>/dev/null || true)
 if [ "$due" = 't' ]; then flock -n "$folder/.selfguard-backup.lock" sh "$0" --locked || true; fi
 sleep "$tick" & wait $!
done
