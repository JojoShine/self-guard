#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
if [ -f .env ]; then echo '.env already exists; left unchanged'; exit 0; fi
umask 077
python3 - <<'PY'
import secrets
with open('.env','x') as f:
 f.write('POSTGRES_PASSWORD='+secrets.token_hex(24)+'\nADMIN_EMAIL=admin@selfguard.local\nADMIN_PASSWORD='+secrets.token_urlsafe(24)+'\nENROLLMENT_TOKEN='+secrets.token_urlsafe(32)+'\nWAF_TOKEN='+secrets.token_urlsafe(32)+'\n')
PY
echo 'Created private .env with random credentials.'
