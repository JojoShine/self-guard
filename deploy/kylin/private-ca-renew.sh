#!/bin/bash
set -euo pipefail
umask 077
base=/opt/self-guard
cert="$base/acme/current-selfguard"
if [ -f "$cert/fullchain.pem" ] && [ -f "$cert/privkey.pem" ] && openssl x509 -checkend 2592000 -noout -in "$cert/fullchain.pem" >/dev/null && openssl verify -CAfile "$base/secrets/platform-ca.crt" -verify_ip 20.88.127.75 "$cert/fullchain.pem" >/dev/null 2>&1; then
 certificate_key=$(openssl x509 -in "$cert/fullchain.pem" -pubkey -noout | openssl pkey -pubin -outform DER | openssl dgst -sha256)
 private_key=$(openssl pkey -in "$cert/privkey.pem" -pubout -outform DER | openssl dgst -sha256)
 [ "$certificate_key" != "$private_key" ] || exit 0
fi
install -d -m 700 "$base/acme/archive"
work=$(mktemp -d "$base/acme/archive/management.XXXXXXXX")
# Preserve a committed version even if interrupted immediately after switching the link.
trap 'if [ "$(readlink "$cert" 2>/dev/null || true)" != "archive/$(basename "$work")" ]; then rm -rf "$work"; fi' EXIT
openssl ecparam -name prime256v1 -genkey -noout -out "$work/privkey.pem"
openssl req -new -key "$work/privkey.pem" -subj '/CN=20.88.127.75' -out "$work/request.csr"
cat > "$work/extensions" <<'EXT'
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=serverAuth
subjectAltName=IP:20.88.127.75
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer
EXT
openssl x509 -req -days 90 -sha256 -in "$work/request.csr" -CA "$base/secrets/platform-ca.crt" -CAkey "$base/secrets/platform-ca.key" -set_serial "0x$(openssl rand -hex 16)" -extfile "$work/extensions" -out "$work/cert.pem"
openssl verify -CAfile "$base/secrets/platform-ca.crt" -verify_ip 20.88.127.75 "$work/cert.pem"
cp "$base/secrets/platform-ca.crt" "$work/chain.pem"
cat "$work/cert.pem" "$work/chain.pem" > "$work/fullchain.pem"
python3 - "$base/acme" "$work" <<'PY'
import os,pathlib,sys
root,version=map(pathlib.Path,sys.argv[1:])
for item in version.iterdir():
 with item.open('rb') as f:os.fsync(f.fileno())
fd=os.open(str(version),os.O_RDONLY)
try:os.fsync(fd)
finally:os.close(fd)
link=root/('current-selfguard.'+version.name)
os.symlink(str(version.relative_to(root)),str(link))
os.replace(str(link),str(root/'current-selfguard'))
fd=os.open(str(root),os.O_RDONLY)
try:os.fsync(fd)
finally:os.close(fd)
PY
