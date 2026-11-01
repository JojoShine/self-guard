#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
mkdir -p .artifacts/results .artifacts/go-cache .artifacts/bin
docker compose -f compose.dev.yaml restart api
# Wait for an actual HTTP response; startup includes migration and compilation.
docker compose -f compose.dev.yaml exec -T api node -e 'async function wait(){for(let i=0;i<90;i++){try{const r=await fetch("http://127.0.0.1:4000/api/assets");if(r.status===401)return;}catch{}await new Promise(r=>setTimeout(r,1000));}throw Error("API startup timeout")}wait().catch(e=>{console.error(e.message);process.exit(1)})'
docker compose -f compose.dev.yaml exec -T api npm run build
docker compose -f compose.dev.yaml exec -T -e TEST_API_URL=http://127.0.0.1:4000/api api npm test
docker compose -f compose.dev.yaml exec -T web npm test
docker compose -f compose.dev.yaml exec -T web npm run build
docker run --rm -v "$PWD:/workspace" -w /workspace/services/agent -e GOCACHE=/workspace/.artifacts/go-cache golang:1.27.3-alpine sh -c 'go test ./... && CGO_ENABLED=0 go build -o /workspace/.artifacts/bin/agent.next . && mv /workspace/.artifacts/bin/agent.next /workspace/.artifacts/bin/agent'
# CRS requires the pinned native PCRE2 dependency; a CGO-disabled build cannot
# be used to validate or deploy the rule interpreter.
sh scripts/build-waf-local.sh
docker compose -f compose.dev.yaml up -d --no-deps --no-build waf
# Reload compiled modules. Auth regression uses a dedicated test source and cleans its shared counter.
docker compose -f compose.dev.yaml restart api
