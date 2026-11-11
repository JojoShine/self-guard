#!/usr/bin/env python3
"""Compare the restored database and immutable files with the source snapshot."""
import hashlib
import json
from pathlib import Path
import subprocess
import sys

bundle = Path(sys.argv[1]).resolve()
expected = json.loads((bundle / 'snapshot/registry.json').read_text())
base = Path('/opt/self-guard')
def query(sql):
    return subprocess.check_output(['podman', 'exec', 'selfguard-postgres', 'psql', '-U', 'selfguard_bootstrap', '-d', 'selfguard', '-At', '-v', 'ON_ERROR_STOP=1', '-c', sql], universal_newlines=True).strip()
for table, count in expected['counts'].items():
    if not table.replace('_', '').isalnum():
        raise SystemExit('Unexpected table name')
    actual = int(query('SELECT count(*) FROM public."' + table + '"'))
    if actual != count:
        raise SystemExit('Restored table count mismatch: ' + table)
for kind, rows in [('intelligence', expected['intelligence']), ('agent-artifacts', expected['agents'])]:
    for item in rows:
        digest = item['sha256']
        if len(digest) != 64 or any(c not in '0123456789abcdef' for c in digest):
            raise SystemExit('Invalid object digest')
        source = base / 'data' / kind / ('objects/' + digest + '.blob' if kind == 'intelligence' else digest)
        if not source.exists() and item.get('status') == 'DRAFT':
            continue
        if source.is_symlink() or not source.is_file() or source.stat().st_size != item['size']:
            raise SystemExit('Restored object missing or wrong size')
        h = hashlib.sha256()
        with source.open('rb') as stream:
            for chunk in iter(lambda: stream.read(1048576), b''):
                h.update(chunk)
        if h.hexdigest() != digest:
            raise SystemExit('Restored object checksum mismatch')
roles = json.loads(query("SELECT json_agg(json_build_object('name',rolname,'super',rolsuper,'createDb',rolcreatedb,'createRole',rolcreaterole)) FROM pg_roles WHERE rolname IN ('selfguard_runtime','selfguard_migrator')"))
if len(roles) != 2 or any(row['super'] or row['createDb'] or row['createRole'] for row in roles):
    raise SystemExit('Runtime/migrator database roles have excessive privileges')
if query("SELECT has_table_privilege('selfguard_runtime','public._prisma_migrations','UPDATE')") != 'f':
    raise SystemExit('Runtime role can modify the migration ledger')
print('Restored table counts, file checksums and database role boundaries verified')
