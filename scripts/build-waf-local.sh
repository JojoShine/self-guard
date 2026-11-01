#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
mkdir -p .artifacts/waf-runtime .artifacts/go-cache .artifacts/results/expansion
if ! docker image inspect selfguard-waf-toolchain:1.27.3-pcre2 >/dev/null 2>&1; then
 docker build -t selfguard-waf-toolchain:1.27.3-pcre2 -f services/waf/Dockerfile.toolchain .
fi
# Compilation/cache stays on the project volume; avoid duplicating Go's cache in
# a Docker build layer when Docker storage is tight. Never prune other projects.
docker run --rm -v "$PWD:/workspace" -w /workspace/services/waf -e GOCACHE=/workspace/.artifacts/go-cache -e CGO_ENABLED=1 selfguard-waf-toolchain:1.27.3-pcre2 sh -c 'go test -tags pcre2 ./... && go build -trimpath -tags pcre2 -o /workspace/.artifacts/waf-runtime/waf .'
docker build -t selfguard-waf:crs-foundation -f services/waf/Dockerfile.prebuilt .artifacts/waf-runtime
