# SelfGuard Suricata bridge

Independent Linux read-only EVE-to-platform bridge. Go 1.25.5 standard library only; no capture privileges, packet capture libraries or Suricata subprocesses.

See [passive deployment and rules guidance](../../deploy/suricata/README.md). CLI: `selfguard-suricata-bridge --config /etc/selfguard-suricata/config.json [--once]`; `--version` prints build identity. HTTPS is mandatory except explicit isolated `--allow-local-http` numeric-loopback tests.

Wire contract: `apps/api/src/network-sensor-contract.ts`. Allowed EVE types are alert/http/dns/tls/flow/anomaly/stats. Raw lines are hashed in memory and discarded; only bounded allowlisted metadata is persisted/sent. Flow IDs and large counters preserve decimal uint64 strings. HTTP uploads contain path without userinfo, query or fragment. No raw headers, Cookie, packet, payload, certificate or file body is queued.

Build and verify using cached Go 1.25.5 in Docker, without host Go:

```sh
docker run --rm --network none -v "$PWD/services/suricata-bridge:/src" -w /src golang:1.25.5 go test -race ./...
docker run --rm --network none -v "$PWD/services/suricata-bridge:/src" -w /src golang:1.25.5 go vet ./...
node scripts/build-suricata-bridge-package.cjs
```

The packaging command is independent of existing release scripts. It produces Linux amd64/arm64 binaries and checksums under `.artifacts/releases/suricata-bridge`; no deployment is performed.
