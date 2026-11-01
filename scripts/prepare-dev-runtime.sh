#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
mkdir -p .artifacts/runtime .artifacts/postgres
# Use only public libraries from the selected PostgreSQL image; no existing containers are read.
docker run --rm --entrypoint sh -v "$PWD/.artifacts/runtime:/out" postgres:17-bookworm -c 'for dir in /usr/lib/aarch64-linux-gnu /usr/lib/x86_64-linux-gnu; do if [ -f "$dir/libssl.so.3" ]; then cp "$dir/libssl.so.3" "$dir/libcrypto.so.3" /out/; fi; done; cp /usr/bin/openssl /out/'
docker run --rm -v "$PWD/apps/api:/app" -w /app node:22-bookworm-slim npm ci --no-audit --no-fund
docker run --rm -v "$PWD/apps/web:/app" -w /app node:22-bookworm-slim npm ci --no-audit --no-fund
