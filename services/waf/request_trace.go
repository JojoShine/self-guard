package main

import (
	"crypto/sha256"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"strings"
	"sync"
)

type requestTrace struct {
	RequestID           string   `json:"requestId"`
	PeerIP              string   `json:"peerIp"`
	PeerPort            string   `json:"peerPort,omitempty"`
	ClientIP            string   `json:"clientIp"`
	SourceBasis         string   `json:"sourceBasis"`
	IncomingTLS         bool     `json:"incomingTls"`
	RequestTargetSHA256 string   `json:"requestTargetSha256"`
	PathRetention       string   `json:"pathRetention"`
	QueryKeys           []string `json:"queryKeys"`
	QueryKeysOmitted    int      `json:"queryKeysOmitted"`
	ConfiguredUpstream  string   `json:"configuredUpstream,omitempty"`
	UpstreamAddress     string   `json:"upstreamAddress,omitempty"`
	UpstreamTLS         *bool    `json:"upstreamTls,omitempty"`
	Forwarded           bool     `json:"forwarded"`
	Action              string   `json:"action"`
	RuleID              string   `json:"ruleId,omitempty"`
	Outcome             string   `json:"outcome"`
	BanState            string   `json:"banState"`
}
type requestTraceState struct {
	mu    sync.Mutex
	value requestTrace
}
type requestTraceKey struct{}

func newRequestTrace(id string, r *http.Request) *requestTraceState {
	ip, port, _ := net.SplitHostPort(r.RemoteAddr)
	keys := []string{}
	omitted := 0
	for _, part := range strings.Split(r.URL.RawQuery, "&") {
		if part == "" {
			continue
		}
		key, _, _ := strings.Cut(part, "=")
		decoded, err := url.QueryUnescape(key)
		if err != nil {
			decoded = "[invalid-key]"
		}
		if len(decoded) > 80 {
			decoded = "[oversize-key]"
		}
		if len(keys) < 30 {
			keys = append(keys, decoded)
		} else {
			omitted++
		}
	}
	return &requestTraceState{value: requestTrace{RequestID: id, PeerIP: ip, PeerPort: port, ClientIP: ip, SourceBasis: "SOCKET_PEER", IncomingTLS: r.TLS != nil, RequestTargetSHA256: fmt.Sprintf("%x", sha256.Sum256([]byte(r.RequestURI))), PathRetention: "SANITIZED_PATH_QUERY_VALUES_NOT_RETAINED", QueryKeys: keys, QueryKeysOmitted: omitted, Action: "ALLOW", Outcome: "NOT_FORWARDED", BanState: "NO_PERSISTENT_BAN"}}
}
func retainedRequestPath(r *http.Request) string {
	parts := strings.Split(r.URL.EscapedPath(), "/")
	sensitive := false
	for i, part := range parts {
		if sensitive {
			parts[i] = "[redacted]"
			sensitive = false
			continue
		}
		decoded, _ := url.PathUnescape(part)
		switch strings.ToLower(decoded) {
		case "password", "token", "secret", "api-key", "apikey", "access_token":
			sensitive = true
		}
		if len(part) > 128 {
			parts[i] = "[redacted-segment]"
		}
	}
	path := strings.Join(parts, "/")
	if path == "" {
		path = "/"
	}
	if len(path) > 1024 {
		return "[oversize-path]"
	}
	return path
}
func (t *requestTraceState) snapshot() *requestTrace {
	t.mu.Lock()
	defer t.mu.Unlock()
	v := t.value
	v.QueryKeys = append([]string{}, v.QueryKeys...)
	return &v
}
func (t *requestTraceState) event(rule, action string) *requestTrace {
	t.mu.Lock()
	t.value.RuleID = rule
	t.value.Action = action
	if action == "BLOCK" {
		t.value.Outcome = "BLOCKED_BY_WAF"
	}
	t.mu.Unlock()
	return t.snapshot()
}
func (t *requestTraceState) forward(r *http.Request) *http.Request {
	t.mu.Lock()
	t.value.Forwarded = true
	t.value.Outcome = "UPSTREAM_RESPONSE"
	t.mu.Unlock()
	return r.WithContext(httptrace.WithClientTrace(r.Context(), &httptrace.ClientTrace{GotConn: func(info httptrace.GotConnInfo) {
		secured := false
		if conn, ok := info.Conn.(*tls.Conn); ok {
			secured = conn.ConnectionState().HandshakeComplete
		}
		t.mu.Lock()
		t.value.UpstreamAddress = info.Conn.RemoteAddr().String()
		t.value.UpstreamTLS = &secured
		t.mu.Unlock()
	}}))
}
