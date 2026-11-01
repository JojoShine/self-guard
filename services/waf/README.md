# Self Guard WAF

Run `go test -race ./...`, then `go build .`. Copy config.example.json to config.json and run the executable. HTTP listens on :8081 by default. WAF_LISTEN and WAF_CONFIG override these settings. WAF_TLS_CERT and WAF_TLS_KEY enable HTTPS termination. Set WAF_API_URL to the management origin and WAF_TOKEN to its component credential to poll /api/waf/config every 10 seconds and submit /api/waf/events. Otherwise the local file reloads every 10 seconds. A rejected update retains the previous configuration. Empty configuration rejects all hosts.

The example documents the JSON schema. Additional sites use exact hostnames. Upstreams must be fixed HTTP(S) URLs without credentials. Only trusted administrators should change upstream addresses. Config is replaced atomically. Rate windows are one minute per site and client IP, with at most 10,000 entries; exhausted capacity blocks new identities. Limits remain enforced for body size in observe mode. Bodies are limited to 1 MiB by default (maximum 8 MiB); URI and network header limits are 16 KiB and 32 KiB. Upstream connect and response-header timeouts are 5 and 15 seconds.

Rules: SQLI, XSS, TRAVERSAL, COMMAND, IP, METHOD, PATH, RATE. OBSERVE records a match and forwards; BLOCK refuses it. Exceptions have exact `ruleId`, exact `path`, and optional exact `param`; omitted param exempts the matching rule for that path. Query and form parameter names are supported; headers use `header:Canonical-Name`; other bodies use `body`. JSON string values are decoded and scanned by their field names. Denied paths match exactly. Forwarded IP addresses are ignored unless the immediate sender is in trustedProxyCidrs; the chain is walked from the trusted side. Forwarded identity headers are stripped before proxying.

Events contain no body, query, header, or raw path (path is redacted). Queue capacity is 1,024 events. Detected events are persisted synchronously to a private atomic JSON outbox before the request returns. Network failures retain events for retry; only 2xx acknowledges delivery. Stable IDs make replay safe at the management API. Overflow or disk-write failure increments droppedEvents; request processing continues. Pattern matching is a starter ruleset, not a comprehensive SQL/HTML parser, and does not inspect compressed bodies or multipart file contents semantically. The legacy WAF_TLS_CERT/WAF_TLS_KEY pair is loaded at process start; the SNI manifest described below supports hot rotation. Deploy behind network controls and validate application security independently.

Management connections require HTTPS, except loopback addresses or explicit `WAF_DEVELOPMENT=true`; redirects are refused. Set `WAF_NODE_ID` to a stable unique identifier (defaults to hostname). Every 10 seconds the node reports its start time, software version, active site configuration versions, and cumulative dropped-event count to `/api/waf/heartbeat`, after attempting config refresh. Dropped events count queue overflow and persistence failures since process start; failed network deliveries remain queued. Valid remote snapshots are atomically persisted before activation to `WAF_CONFIG`; its parent directory must be writable. Restart loads that snapshot when the management service is offline. Invalid or non-persistable snapshots retain the active configuration. Content encodings other than identity generate `ENCODING` matches: block mode refuses them, observe mode records and forwards them.


Set `WAF_STATE_DIR` to a writable private persistent directory (default `waf-state`), owned by one WAF process only. Startup refuses a corrupt/unreadable outbox rather than silently discarding it. A background worker delivers at most four events per second and backs off on failure; network I/O never runs in the request handler. Snapshot rewrites, file fsync, and directory fsync run under a mutex during event append/ack. This favors durability for a bounded initial deployment but adds disk latency to matched requests; high attack volume can fill the queue. No throughput guarantee is claimed. A crash before the append completes can lose that in-flight event; a crash after server acknowledgment but before local removal replays its stable ID. Outbox capacity is fixed and disk failure does not fail closed for otherwise observed traffic. There is no automatic deletion of permanent API-rejected events: repair the cause to resume delivery. Mount the state directory when running the non-root image.

## Path limits and upstream checks

`config.pathRateLimits` accepts at most 100 `{ "path": "/login", "ratePerMinute": 10 }` entries per site. Each exact decoded path gets its own one-minute counter per site and client IP in addition to the site-wide rate limit. The shared rate map remains bounded at 10,000 entries. Paths must be absolute, unescaped, and free of query strings/fragments; duplicates and non-positive limits reject the entire snapshot. Both BLOCK and OBSERVE retain their normal match behavior.

`config.healthCheckPath` defaults to `/`. Every health round sends a real GET to this path on each enabled upstream, with eight workers, a three-second timeout per probe, no environment proxy, and no redirect following. A new round begins ten seconds after the previous round completes. HTTP 200–399 is healthy; other responses and connection/TLS failures are unhealthy. Probes do not enter WAF request totals. These checks report status and do not change routing or claim failover. The heartbeat includes `upstreamHealth: [{siteId, healthy, statusCode, checkedAt}]`; statusCode 0 denotes connection/timeout failure. Check checkedAt when assessing freshness.

## Redacted access history and request counters

Every request handled by the engine, including unknown hosts, malformed payloads, blocked requests and upstream failures, produces an access entry in `WAF_STATE_DIR/access.json`. Each entry contains only site ID, an allowlisted HTTP method (OTHER for custom methods), literal `[redacted]` path, status, UTC timestamp and duration in microseconds. It never records a URI, query, body, header or client IP. The private atomic JSON ring retains the most recent 1,024 entries and survives normal restarts. Requests rejected by the HTTP server before reaching the handler are outside these counts.

Heartbeat counters `totalRequests`, `blockedRequests`, `observedRequests`, `upstreamErrors`, and `accessLogDropped` are cumulative since the reported `startedAt`. Blocked/observed counters describe security matches; upstreamErrors counts failed proxy exchanges. The counters reset on process restart. Access persistence failures increment accessLogDropped and allow traffic processing to continue. Normal ring eviction is retention, not a persistence failure. The ring is intentionally bounded; it is not an indefinite audit archive. Access writes synchronously rewrite/fsync the ring, adding disk latency to all requests. Capacity and concurrent throughput still need deployment-specific measurement.

## Local SNI certificates and rotation

Set `WAF_TLS_CONFIG` to an absolute path to a local JSON manifest:

```json
[
  {"hostname":"app.example.com","certFile":"/etc/waf/tls/app.fullchain.pem","keyFile":"/etc/waf/tls/app.key"},
  {"hostname":"admin.example.com","certFile":"/etc/waf/tls/admin.fullchain.pem","keyFile":"/etc/waf/tls/admin.key"}
]
```

The operator provisions these files on the WAF node and restricts private key permissions. Neither certificate paths nor key contents are accepted from API site configuration. Exact SNI hostnames select their certificate; unknown/missing SNI names fail the handshake. TLS 1.2 is the minimum. Each pair must parse, match its hostname and be within its validity period. Invalid initial manifests prevent startup. The node re-reads the manifest and certificate files every ten seconds and atomically swaps the entire valid set; any invalid pair retains the previous set. Existing TLS connections are unaffected. Replace files atomically to avoid transient partial reads. This does not implement ACME issuance, renewal automation, revocation checking or multi-node distribution.

`runtime_test.go`, `tls_test.go` and `process_test.go` cover independent path limits, invalid configuration retaining live routing, all four attack classes across query/header/form/JSON/path, narrow exceptions, trusted proxy chains, redacted bounded access history, disk-write failure accounting, real multi-domain TLS handshakes and rotation, active upstream health probes, plus a real subprocess offline restart with stable pending event delivery and heartbeat confirmation. Run `go test ./...` and `go vet ./...`. This evidence does not establish HA, concurrency capacity or comprehensive attack prevention.

## Central access history synchronization

Each ten-second management heartbeat includes `accessHistory`, a snapshot of all currently retained entries (at most 1,024). Each entry has `{id, siteId, method, path, status, timestamp, durationMicros}`. The ID combines node ID, process start time and a monotonic sequence; it is written with the record and remains unchanged when the node restarts. Old-format retained entries receive stable IDs during loading. Management storage should upsert by ID to deduplicate overlapping snapshots. The snapshot is copied while holding the log lock; JSON encoding and network transmission occur after release.

`accessHistoryCapacity`, `accessHistoryCount`, and `accessHistoryEvictedSinceStart` explicitly describe the bounded retention window and its evictions in this process. Disk failures are separately reported as `accessLogDropped`. This mechanism synchronizes retained history without delivery acknowledgements or an additional access outbox. If more than 1,024 requests arrive between successful heartbeats, records can be evicted before management sees them; totalRequests still counts those requests. Central history must not be labeled a complete archive. Metadata resets follow the heartbeat's startedAt; retained entries may originate from earlier process starts. Heartbeat receivers must allow payloads containing the bounded 1,024-entry array.

Full request telemetry uses a separate durable `access-pending` directory under
`WAF_STATE_DIR`. Each request stores only method, redacted path, site, status,
time and duration. Records retain stable IDs over retries and restarts; the WAF
posts batches of at most 100 to authenticated `/api/telemetry/access` and removes
records only after a 2xx response. The API stores redacted structured telemetry
for 30 days, indexed by asset/site and event time; administrators can purge expired
records with `POST /api/telemetry/retention/purge`. No request headers or body are
persisted. The queue holds 100000 pending records. If full or unwritable, new
records are rejected explicitly, counted in `accessLogDropped`, and reported to
stderr; pending records are preserved. The 1024-entry heartbeat history remains a
local preview and is not the full delivery channel. Size the queue/disk and monitor
rejections for the deployment's actual request volume.

Optional online policy testing: set `WAF_TEST_LISTEN` to a private management
listener and provide a `WAF_TOKEN` of at least 32 characters. Keep this listener
on the management network. Set the API's `WAF_TEST_URL` to that listener and use
`POST /api/waf-policy-tests` as an authenticated unrestricted administrator or
analyst. The test takes `siteId`, `method`, `path`, optional `headers`, `body`,
`remoteIp`, and `repeat` (1–100). It reports active policy version, decision,
matched rule and status for each simulated request. It runs the live inspection
pipeline with isolated counters and a proxy transport that cannot contact any
upstream. Test bodies/headers are neither persisted nor included in audit data.
The live public proxy never exposes this test handler.

Central certificate lifecycle is opt-in with `WAF_REMOTE_CERTIFICATES=true`.
An administrator uploads a DNS-SAN certificate chain and matching private key at
`/api/certificates`; the API encrypts private keys with `DATA_ENCRYPTION_KEY` and
exposes only certificate metadata to signed-in administrators. WAF nodes fetch
`GET /api/waf/certificates` with their component token, validate every certificate,
and replace the SNI snapshot atomically every 10 seconds. A rejected update leaves
the prior snapshot active. Every new TLS handshake checks validity, including
when the node is offline; expired certificates fail the handshake.

`WAF_TLS_CONFIG` local manifests take priority over remote management. If no
manifest is configured, a static `WAF_TLS_CERT`/`WAF_TLS_KEY` pair also takes priority.
Otherwise remote mode starts an HTTPS listener, initially from the encrypted
`WAF_STATE_DIR/certificates.enc` cache if available. The cache uses AES-256-GCM with
a domain-separated key derived from `WAF_TOKEN` and is written with mode 0600.
Keep this directory on persistent storage. Rotating the component token makes an
old cache unreadable until the next successful management fetch. If neither a
valid cache nor management is available, TLS handshakes fail closed until refresh
succeeds. Certificate disablement becomes effective when the node next receives
the management snapshot. A disconnected node cannot learn revocations; remove its
route or local cache when immediate revocation is required. Managed snapshots are
limited to 200 DNS hostnames and 24 MiB. Remote management uses the existing HTTPS
management URL checks; loopback/development HTTP is intended only for local tests.

## Candidate rule execution and bounded warm workers

The private `/seclang/test` endpoint uses up to three reusable isolated processes,
with immutable loaded rule plans. They share a four-process ceiling with basic
compatibility checks; one slot remains available to management. At most four HTTP
test inputs are admitted at once, and the pool limits accepted active/pending
calls to24. Each call has a two-second wall deadline; each process retains the
existing two-second cumulative CPU limit and is recycled after at most64 calls.
Failed, timed-out, malformed or incomplete inspection is returned explicitly,
never converted into a clean result. Each load receipt identifies its exact input
bytes and engine, and every result is sequence-correlated. This test endpoint
still does not activate a candidate on public sites.

PCRE2 compilation is cached under both a 1024-entry and32 MiB budget, including
pattern text. Borrowed code cannot be evicted; match contexts and captures remain
per invocation. Static target updates and compatibility checks are prepared once
per immutable plan. Match/depth/heap limits are unchanged. Explicit `deny` takes
its root rule's `status` (final codes200–599); informational, duplicate or invalid
status actions are rejected. The default blocking status is403.

For controlled local regression only, `--test-seclang-diagnostics` adds a bounded
native audit transcript from actual matches and expanded message/logdata actions.
It respects `nolog`, escapes fields, and marks omissions/truncation. Ordinary CLI,
HTTP and reusable-worker results do not enable this transcript. Diagnostic data
may contain matched fixture text: use synthetic or public regression inputs.
CRS log regex checks require explicit complete diagnostics; missing or truncated
transcripts are not counted as passing negative assertions. This mechanism is
not a claim of Apache/ModSecurity transport equivalence or production acceptance.

PCRE2 reference: https://www.pcre.org/current/doc/html/pcre2api.html


Rule execution retains a per-transaction long-value transform cache (128 entries,
2 MiB) keyed by exact bytes, ordered transformations and multiMatch. PCRE2 JIT
code counts toward the32 MiB compiled-pattern cache. Each exclusively borrowed
native execution context has a32..256 KiB JIT stack; at most4 are retained per
process. Stack exhaustion retries with the bounded interpreter (match100000,
depth1000, heap8192 KiB); the isolated CPU and wall deadlines remain enforced.
JIT has its own stack controls and does not use interpreter depth/heap limits.
See the [PCRE2 JIT documentation](https://www.pcre.org/current/doc/html/pcre2jit.html).
These optimizations have not completed the fixed30-minute runtime acceptance.

## Same-host Nginx ingress

The optional signed policy flag nginxIngress supports the managed Nginx onboarding path. Nginx overwrites X-Selfguard-Original-Host with the original proxy Host (including the original default proxy_host) while routing to the WAF using the public site Host. The WAF honors this metadata only from a loopback socket peer that is also in trustedProxyCidrs. The internal header is removed before every upstream forwarding, including requests from untrusted peers. External clients cannot use it to select an upstream virtual host. TLS remains on the existing Nginx entry; the local WAF binds loopback.

Host-scoped management credentials cannot read other sites, report another node, fetch global certificate material, or authenticate as the Agent. Site configuration moves out of the central-node distribution only after the host reports successful real ingress validation. Signed rule acknowledgement is checked against the site's actual hosting node(s).

### Explicit HTTP management transport

`WAF_ALLOW_HTTP=true` permits a declared HTTP management API without enabling development mode. The default still requires HTTPS outside loopback. This controls the management connection only, independently of protected-site HTTP/HTTPS ingress. HTTPS certificate checks and signed policy verification remain enabled. Agent 0.4.10 sets this flag for a host WAF only when its installation explicitly selected HTTP.
