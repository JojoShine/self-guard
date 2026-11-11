#!/usr/bin/env python3
"""Validate an offline bundle before preparing its dedicated deployment tree."""
import base64
import hashlib
import json
import os
from pathlib import Path
import shutil
import sys

bundle = Path(sys.argv[1]).resolve()
base = Path('/opt/self-guard')
manifest = json.loads((bundle / 'manifest.json').read_text())
for item in manifest['files']:
    relative = Path(item['path'])
    if relative.is_absolute() or '..' in relative.parts:
        raise SystemExit('Unsafe bundle path')
    source = bundle / relative
    if source.is_symlink() or not source.is_file() or source.stat().st_size != item['size']:
        raise SystemExit('Bundle file missing, linked or wrong size: ' + str(relative))
    digest = hashlib.sha256()
    with source.open('rb') as stream:
        for chunk in iter(lambda: stream.read(1048576), b''):
            digest.update(chunk)
    if digest.hexdigest() != item['sha256']:
        raise SystemExit('Bundle checksum mismatch: ' + str(relative))
if len(sys.argv) > 2 and sys.argv[2] == '--verify-only':
    print('All offline payload checksums verified')
    raise SystemExit(0)

def copy_tree(source, target):
    # Kylin V10 includes Python 3.7, before copytree(dirs_exist_ok) was introduced.
    for root, dirs, files in os.walk(str(source)):
        destination = target / Path(root).relative_to(source)
        destination.mkdir(parents=True, exist_ok=True)
        for filename in files:
            shutil.copy2(os.path.join(root, filename), str(destination / filename))

marker = base / 'installed.json'
if marker.exists() and json.loads(marker.read_text())['snapshotSha256'] != manifest['snapshotSha256']:
    raise SystemExit('A different deployment already exists; migration must be reviewed first')
base.mkdir(mode=0o700, exist_ok=True)
if base.is_symlink() or base.stat().st_uid != 0:
    raise SystemExit('Deployment path must be root-owned and not a symbolic link')
for name in ['secrets', 'backups', 'data', 'state', 'releases', 'acme', 'acme-staging', 'public/acme/.well-known/acme-challenge']:
    (base / name).mkdir(parents=True, mode=0o700, exist_ok=True)
release = base / 'releases' / manifest['release']
release.mkdir(mode=0o700, exist_ok=True)
for name in ['scripts', 'reports']:
    copy_tree(bundle / name, release / name)
for script in (release / 'scripts').iterdir():
    if script.is_file():
        os.chmod(str(script), 0o644)
shutil.copy2(bundle / 'manifest.json', release / 'manifest.json')
packet = json.loads((bundle / 'private/configuration.json').read_text())
for name, value in packet['files'].items():
    relative = Path(name)
    if relative.parts[0] != 'secrets' or len(relative.parts) != 2:
        raise SystemExit('Invalid secret destination')
    target = base / relative
    data = base64.b64decode(value, validate=True) if name in packet.get('binaryFiles', []) else value.encode()
    if target.is_symlink():
        raise SystemExit('Secret destination is a link')
    if marker.exists() and (not target.exists() or target.read_bytes() != data):
        raise SystemExit('Existing deployment credentials differ; not replacing them')
    temporary = target.with_suffix(target.suffix + '.pending')
    with os.fdopen(os.open(str(temporary), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), 'wb') as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(str(temporary), str(target))
for name in ['db-admin-password', 'db-runtime-password', 'db-migrator-password']:
    os.chown(str(base / 'secrets' / name), 70, 70)
    os.chmod(str(base / 'secrets' / name), 0o400)
os.chown(str(base / 'secrets/waf-runtime.pk8.b64'), 1000, 1000)
os.chmod(str(base / 'secrets/waf-runtime.pk8.b64'), 0o400)
os.chmod(str(base / 'secrets/waf-public.key'), 0o444)
os.chown(str(base / 'secrets/pgpass'), 1000, 1000)
os.chmod(str(base / 'secrets/pgpass'), 0o600)
if not (base / 'state/snapshot-restored').exists():
    for name in ['intelligence', 'agent-artifacts']:
        target = base / 'data' / name
        origin = bundle / 'artifacts' / name
        if target.is_symlink():
            raise SystemExit('Artifact destination is a link')
        for existing in target.rglob('*') if target.exists() else []:
            corresponding = origin / existing.relative_to(target)
            if existing.is_symlink() or not corresponding.exists():
                raise SystemExit('Unexpected existing artifact; not replacing it')
            if existing.is_file() and existing.read_bytes() != corresponding.read_bytes():
                raise SystemExit('Existing artifact differs; not replacing it')
        copy_tree(origin, target)
        for root, dirs, files in os.walk(str(target)):
            os.chown(root, 1000, 1000)
            os.chmod(root, 0o700)
            for filename in files:
                os.chown(os.path.join(root, filename), 1000, 1000)
                os.chmod(os.path.join(root, filename), 0o600)
copy_tree(bundle / 'delivery', release / 'delivery')
for root, dirs, files in os.walk(str(release / 'delivery')):
    os.chmod(root, 0o755)
    for filename in files:
        os.chmod(os.path.join(root, filename), 0o644)
for name in ['postgres', 'waf']:
    target = base / 'data' / name
    target.mkdir(mode=0o700, exist_ok=True)
    os.chown(str(target), 70 if name == 'postgres' else 10001, 70 if name == 'postgres' else 10001)
current = base / 'current'
if current.is_symlink():
    if current.resolve() != release:
        raise SystemExit('A different release is active; not changing the pointer')
elif current.exists():
    raise SystemExit('Current release pointer is not a symbolic link')
else:
    current.symlink_to(release)
print('Offline bundle checksums verified; private configuration prepared')

# Effective access bodies have their own rolling seven-day lifecycle; do not copy them into snapshot backups.
evidence = base / "data/access-evidence"
if evidence.is_symlink():
    raise SystemExit("Access evidence destination is a link")
evidence.mkdir(mode=0o700, parents=True, exist_ok=True)
os.chown(str(evidence), 1000, 1000)
os.chmod(str(evidence), 0o700)
