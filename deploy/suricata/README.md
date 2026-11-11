# Independent passive Suricata source

This integration runs three separate components: the existing asset Agent, a separately installed Suricata IDS, and the unprivileged metadata bridge. It does not modify business traffic or start Suricata. Bind the source to the local Agent's `assetId`; only the `assetId` property is decoded from `/var/lib/selfguard-agent/identity.json`. The bridge uses its own revocable source token. Do not copy an Agent credential into bridge configuration.

## Compatibility and prerequisites

The supplied configuration targets Suricata 8 EVE JSON. Check the installed vendor version, EVE output and `suricata -T` results before rollout. Old Kylin/CentOS kernels, vendor Suricata packages, systemd resource controls and capture drivers are **not certified** by these samples. The bridge is a Go standard-library static Linux binary for amd64/arm64, not a Suricata package. Obtain Suricata and `suricata-update` from your approved OS/vendor channel. Choose a mirror/TAP interface with the network owner; never enable NFQUEUE, inline `copy-mode: ips`, automatic firewall changes or packet forwarding for this integration.

## Install bridge without capture privileges

1. Create a source under the correct asset and download the one-time private JSON configuration. Confirm its HTTPS platform URL, optional CA path, EVE path, source ID and expected rule fingerprint. The server may include an existing platform subpath; the bridge appends `/api/sensor-ingest/<sensorId>`.
2. Install the architecture-matching binary at `/opt/selfguard-suricata/selfguard-suricata-bridge` (root owned, 0755). Put configuration in `/etc/selfguard-suricata/config.json`, owner `selfguard-agent`, mode 0600; the containing directory should be root owned and traversable only by that service user/group. Create `/var/lib/selfguard-suricata/<sensorId>` owner `selfguard-agent`, 0700. Keep bridge state separate from base Agent state. Back up state only with equally private permissions; do not restore stale state over a running writer.
3. Install the supplied systemd unit after adapting resource limits and paths. The unit has no capture capabilities. Create the dedicated supplementary group `selfguard-suricata-read`; grant it read access to `eve.json` and traverse access to `/var/log/suricata`, **not** write access or access to all Suricata logs. Use file ACLs and rotation hooks to preserve those permissions. Apply default ACLs only to a dedicated EVE directory if EVE is isolated there. Do not add privileges to the base Agent unit. Confirm the service user can read the existing Agent identity without exposing its credentials to another account.
4. Merge `eve-passive.fragment.yaml` into a complete vendor configuration, keeping the existing unrelated outputs/settings. Avoid HTTP custom/extended headers, packet/payload output, bodies and credentials. The bridge independently strips every field outside its metadata allowlist; raw local EVE remains subject to local access and retention policy.
5. Validate the complete Suricata configuration using `suricata -T -c /etc/suricata/suricata.yaml`. Start Suricata separately in passive IDS mode under your OS policy. Start the bridge via `systemctl enable --now selfguard-suricata-bridge`. No production host is changed by this repository.

Example private configuration (replace IDs/token; never commit a real token):

```json
{
  "schema": "selfguard-suricata-config-v1",
  "server": "https://selfguard.example/platform",
  "sensorId": "11111111-1111-4111-8111-111111111111",
  "assetId": "22222222-2222-4222-8222-222222222222",
  "token": "REPLACE_WITH_SOURCE_TOKEN",
  "evePath": "/var/log/suricata/eve.json",
  "identityPath": "/var/lib/selfguard-agent/identity.json",
  "stateDir": "/var/lib/selfguard-suricata/11111111-1111-4111-8111-111111111111",
  "readFromStart": false
}
```

Optional keys: `ruleFile`, `expectedRuleSha256`, `caCertificate` (PEM file). TLS certificate/hostname verification is always enabled; redirects are refused. `--allow-local-http` permits only numeric loopback HTTP inside isolated tests and is not a production setting. `--version` reports the bridge build; `--once` deliberately replays complete lines to EOF as `REPLAY`; missing/unreadable input or a trailing incomplete line returns a nonzero result, not successful EOF. Use a separate lab source/state directory for replay. Never delete production state to force a replay.

## Rule update recipe

Use the official [suricata-update workflow](https://docs.suricata.io/en/suricata-8.0.6/rule-management/suricata-update.html). Review enabled sources, licensing and disable/enable policies first. Perform each stage under an operator account; the bridge does not download rules, run shell commands or send reload signals.

1. Create a private staging directory and retain a backup of the active rules plus the source/version/disable configuration. Run `suricata-update --help` for the installed version, then `suricata-update --suricata /usr/bin/suricata --suricata-conf /etc/suricata/suricata.yaml --output /var/lib/suricata/staging`. Do not point this stage at active rules. Retain the updater's output, enabled-source manifest and resulting SHA256 as provenance.
2. Validate the candidate with `suricata -T -c /etc/suricata/suricata.yaml -S /var/lib/suricata/staging/suricata.rules`. If the production configuration uses multiple rule files, datasets or auxiliary files, validate a complete staged configuration with their real paths as well. A test of one merged file does not certify those other inputs.
3. After validation, install the candidate to the configured active rule path using an atomic replacement on the same filesystem and preserve the former version for rollback. Trigger an operator-authorized [blocking reload](https://docs.suricata.io/en/suricata-8.0.6/rule-management/rule-reload.html) with `suricatasc -c reload-rules` if the control socket is enabled. Otherwise use the OS service's documented reload/restart method. Do not give the bridge control-socket or signal privileges.
4. Confirm reload success in engine logs/control output and subsequent EVE `stats.detect.engines[].rules_loaded`, `rules_failed`, `rules_skipped` when available. A failed validation/reload means retain/restore the previous tested rules and verify the rollback reload. Set the registered expected hash to the actual approved file after success. Do not claim zero rule failures when a vendor version omits those counters.

A registered engine/version is operator inventory. A file SHA256/mtime proves which bytes the bridge can read (maximum 32 MiB), **not** which rules the running engine has loaded. EVE stats/reload results provide distinct runtime evidence; replay and old stats do not establish live engine health. Inspect packet/drop counters and latest stats independently from bridge heartbeats. Missing EVE, malformed lines, missing rule files and rotation gaps are visible health conditions.

## Delivery and file operations

The reader starts at the existing file's end by default; appended complete lines only. Partial lines wait for newline. Max line 256 KiB; oversized lines are discarded and counted without persisting their text. Unknown EVE types are skipped and counted. Each pass is bounded to 4 MiB/50 events. Rotation uses the old open handle until drained and can find its inode among directory siblings after restart. The remembered old generation can be recovered, but arbitrary sibling names/mtimes cannot prove intermediate rotation order. Every old-to-current handoff therefore conservatively reports `ROTATION_GAP`; multiple intervening generations may be skipped and must not be interpreted as complete coverage. Keep rotated uncompressed siblings until drained; deletion/compression before recovery and truncation produce explicit gaps. Prefer rename/create rotation over copytruncate. Inode reuse plus identical content/offset is inherently indistinguishable from an unchanged file; avoid aggressive rotation/deletion while the bridge is offline.

One 0600 atomic/fsynced pending batch stores sanitized metadata and its next cursor. Only a matching persisted acknowledgement advances the cursor. Retries preserve batch/event IDs; a single writer lock prevents competing readers. Offline/protocol errors retain the bounded batch and stop further reads. Disabled or revoked sources are checked before reads; 401/403 stops the bridge. Health heartbeats occur every 10 seconds when idle, subject to network latency/backoff; last EVE/stats event time is separate. API event retention/quota policy applies independently of existing alerts.

## Isolated lab

`lab.rules` recognizes only a synthetic local path. It is not production protection. Use a disconnected container/network namespace, synthetic PCAP, the vendor's full default config and `-S /lab/lab.rules`; write EVE into a temporary directory. Validate with `-T` first, then process the PCAP using `suricata -r /lab/synthetic.pcap -c /etc/suricata/suricata.yaml -S /lab/lab.rules -l /lab/output`. Replay using a dedicated source and the bridge `--once`. Mount a test identity file at the required identity path inside the isolated bridge container; do not replace a host's real identity. No external target, live interface or production rule set is needed.

Reference: [official EVE JSON format](https://docs.suricata.io/en/suricata-8.0.6/output/eve/eve-json-format.html).
