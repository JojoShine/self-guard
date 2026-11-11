import hashlib
import os
from pathlib import Path
import shutil
import sys
source, target = map(Path, sys.argv[1:])
target.mkdir(mode=0o700, exist_ok=True)
for item in source.iterdir():
    if len(item.name) != 64 or any(c not in '0123456789abcdef' for c in item.name):
        continue
    if item.is_symlink() or not item.is_file():
        raise SystemExit('Invalid Agent object type')
    data = item.read_bytes()
    if hashlib.sha256(data).hexdigest() != item.name:
        raise SystemExit('Agent source object checksum failed')
    destination = target / item.name
    if destination.exists():
        if destination.is_symlink() or destination.read_bytes() != data:
            raise SystemExit('Previous Agent backup differs; retained unchanged')
    else:
        with os.fdopen(os.open(str(destination), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), 'wb') as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
print('Immutable Agent object backup verified')
