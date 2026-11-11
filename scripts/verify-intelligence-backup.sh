#!/bin/sh
set -eu
manifest=${1:?Pass the backup original-file manifest}
registry=${2:?Pass the registry exported from the isolated restored database}
folder=$(dirname "$manifest")
test -f "$manifest"
test -f "$registry"
count=0
while IFS='|' read -r artifact_sha artifact_size artifact_encoding; do
 [ -n "$artifact_sha" ] || continue
 case "$artifact_sha" in *[!0-9a-f]*) exit 1;; esac
 [ "${#artifact_sha}" -eq 64 ]
 case "$artifact_size" in ''|*[!0-9]*) exit 1;; esac
 case "$artifact_encoding" in ZIP|GZIP_JSON|GZIP_XML) :;; *) exit 1;; esac
 grep -Fx -- "$artifact_sha|$artifact_size|$artifact_encoding" "$manifest" >/dev/null
 file="$folder/intelligence-objects/$artifact_sha.blob"
 test -f "$file"
 actual=$(sha256sum "$file" | cut -d ' ' -f 1)
 [ "$actual" = "$artifact_sha" ]
 actual_size=$(wc -c < "$file")
 [ "$actual_size" -eq "$artifact_size" ]
 count=$((count+1))
done < "$registry"
printf 'Verified original files referenced by restored database: %s\n' "$count"
