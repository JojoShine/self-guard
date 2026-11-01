#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
# The same locked path as scheduled backups includes verified source originals.
docker compose -f "${COMPOSE_FILE:-compose.dev.yaml}" exec -T backup sh /scripts/scheduled-backup.sh --once
