package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestRequestTracePrivacyAndImmutableDecision(t *testing.T) {
	r := httptest.NewRequest("GET", "http://site.test/api/token/private-value?password=private-query&name=a", nil)
	r.RemoteAddr = "192.0.2.5:1234"
	trace := newRequestTrace("request-1", r)
	blocked := trace.event("SQLI", "BLOCK")
	trace.value.ClientIP = "192.0.2.6"
	if blocked.ClientIP != "192.0.2.5" || blocked.Outcome != "BLOCKED_BY_WAF" || blocked.Forwarded {
		t.Fatal("mutable or inaccurate decision snapshot")
	}
	if retainedRequestPath(r) != "/api/token/[redacted]" {
		t.Fatal(retainedRequestPath(r))
	}
	raw, _ := json.Marshal(blocked)
	if strings.Contains(string(raw), "private-") {
		t.Fatal("request secret retained")
	}
	if blocked.RequestID != "request-1" || blocked.PeerIP != "192.0.2.5" || len(blocked.QueryKeys) != 2 {
		t.Fatalf("%+v", blocked)
	}
}

func TestRequestTraceActualUpstreamAndBlockedLink(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(201) }))
	defer upstream.Close()
	e := newEngine()
	var err error
	e.access, err = openAccessLog(t.TempDir(), 10)
	if err != nil {
		t.Fatal(err)
	}
	if err = e.update(Config{Sites: []Site{{ID: "site", Hostname: "site.test", Upstream: upstream.URL, Mode: "BLOCK", Enabled: true}}}); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/api/items?name=public", "/api/items?q=union%20select"} {
		r := httptest.NewRequest("GET", path, nil)
		r.Host = "site.test"
		r.RemoteAddr = "192.0.2.5:1234"
		w := httptest.NewRecorder()
		e.ServeHTTP(w, r)
	}
	rows, _, _ := e.access.snapshot()
	if len(rows) != 2 {
		t.Fatal(rows)
	}
	success, blocked := rows[0].Context, rows[1].Context
	if !success.Forwarded || success.UpstreamAddress == "" || success.UpstreamTLS == nil || *success.UpstreamTLS || success.Outcome != "UPSTREAM_RESPONSE" {
		t.Fatalf("%+v", success)
	}
	ev := <-e.events
	if blocked.Forwarded || blocked.Outcome != "BLOCKED_BY_WAF" || ev.Context.RequestID != rows[1].ID {
		t.Fatalf("%+v %+v", blocked, ev)
	}
}

func TestRequestTraceOnlyUsesValidTrustedForwardedAddress(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) }))
	defer upstream.Close()
	e := newEngine()
	e.access, _ = openAccessLog(t.TempDir(), 10)
	if err := e.update(Config{Sites: []Site{{ID: "site", Hostname: "site.test", Upstream: upstream.URL, Mode: "BLOCK", Enabled: true, Config: Policy{TrustedProxyCidrs: []string{"192.0.2.0/24"}}}}}); err != nil {
		t.Fatal(err)
	}
	for _, value := range []string{"invalid", "198.51.100.8"} {
		r := httptest.NewRequest("GET", "/api/items", nil)
		r.Host = "site.test"
		r.RemoteAddr = "192.0.2.5:1234"
		r.Header.Set("X-Forwarded-For", value)
		e.ServeHTTP(httptest.NewRecorder(), r)
	}
	rows, _, _ := e.access.snapshot()
	if rows[0].Context.SourceBasis != "SOCKET_PEER" || rows[0].Context.ClientIP != "192.0.2.5" {
		t.Fatal("invalid forwarded source trusted")
	}
	if rows[1].Context.SourceBasis != "TRUSTED_PROXY_CHAIN" || rows[1].Context.ClientIP != "198.51.100.8" {
		t.Fatal("valid forwarded source lost")
	}
}
