#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
mkdir -p .artifacts/bin .artifacts/go-cache
docker run --rm -v "$PWD:/workspace" -w /workspace/services/intelligence -e GOCACHE=/workspace/.artifacts/go-cache -e CGO_ENABLED=0 golang:1.27.3-alpine sh -c 'go test ./... && go build -trimpath -o /workspace/.artifacts/bin/intelligence-unzip .'
