package scanner

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type fixtureDial struct {
	endpoint string
	calls    atomic.Int32
}

func (d *fixtureDial) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if address != "10.20.0.8:8080" {
		return nil, errors.New("unexpected pinned destination")
	}
	d.calls.Add(1)
	return (&net.Dialer{}).DialContext(ctx, network, d.endpoint)
}

type fixtureBudget struct {
	calls atomic.Int32
	deny  bool
}

func (b *fixtureBudget) Acquire(ctx context.Context, keys []string) error {
	if len(keys) != 1 || keys[0] != "10.20.0.8:8080" {
		return errors.New("endpoint budget key mismatch")
	}
	b.calls.Add(1)
	if b.deny {
		return errors.New("shared budget unavailable")
	}
	return ctx.Err()
}
func httpFixture(t *testing.T, handler http.HandlerFunc) (*Engine, *fixtureDial, *fixtureBudget) {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	target := Target{Hostname: "app.example.test", Port: 8080, Protocol: "http", Addresses: []string{"10.20.0.8"}, AllowedPaths: []string{"/public"}, ExcludedPaths: []string{"/public/admin"}}
	policy, err := NewPolicy(target, nil)
	if err != nil {
		t.Fatal(err)
	}
	policy.resolver = fixedResolver{[]netip.Addr{netip.MustParseAddr("10.20.0.8")}}
	dial := &fixtureDial{endpoint: server.Listener.Addr().String()}
	policy.dialer = dial
	budget := &fixtureBudget{}
	engine, err := NewEngine(policy, budget)
	if err != nil {
		t.Fatal(err)
	}
	return engine, dial, budget
}
func matchingRule() HTTPRule {
	return HTTPRule{ID: "fixture-exposure", Description: "Explicit read-only response condition", Operator: "ALL", Conditions: []Condition{{Kind: "STATUS", Status: 200}, {Kind: "HEADER_CONTAINS", Header: "Content-Type", Value: "text/plain"}, {Kind: "BODY_REGEX", Value: "exposed-[0-9]+"}}}
}
func TestHTTPUsesActualBoundedResponseAndSharedBudget(t *testing.T) {
	engine, dial, budget := httpFixture(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" || r.Host != "app.example.test:8080" {
			t.Error("request identity changed")
		}
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprint(w, "exposed-123")
	})
	result := engine.HTTP(context.Background(), "GET", "/public/status", matchingRule())
	if result.Outcome != "CONFIRMED" || result.Evidence.Status != 200 || result.Evidence.BodyBytes != 11 || len(result.Evidence.ResponseSHA256) != 64 || len(result.Evidence.Conditions) != 3 || dial.calls.Load() != 1 || budget.calls.Load() != 1 {
		t.Fatalf("unexpected actual response evidence: %+v", result)
	}
	if len(result.Evidence.Connections) != 1 || result.Evidence.Connections[0].Source == "" || result.Evidence.Connections[0].Destination != dial.endpoint || result.Evidence.Connections[0].Transport != "TCP" {
		t.Fatal("missing actual socket endpoints", result.Evidence.Connections)
	}
	if result.Evidence.Conditions[0].Observed != "200" || result.Evidence.Conditions[2].Observed != "exposed-123" {
		t.Fatal("must retain actual status and regex match, not only the authored pattern", result.Evidence.Conditions)
	}
	rule := matchingRule()
	rule.Conditions[2].Value = "absent"
	if result = engine.HTTP(context.Background(), "GET", "/public/status", rule); result.Outcome != "NOT_FOUND" {
		t.Fatal(result)
	}
}
func TestHTTPRefusesOutOfScopeRedirectBeforeConnection(t *testing.T) {
	for _, destination := range []string{"http://127.0.0.1/private", "http://app.example.test:8080/public/admin", "http://app.example.test:8080/private", "http://other.example.test:8080/public/status"} {
		t.Run(destination, func(t *testing.T) {
			engine, dial, budget := httpFixture(t, func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, destination, 302) })
			result := engine.HTTP(context.Background(), "GET", "/public/start", matchingRule())
			if result.Outcome != "INCONCLUSIVE" || dial.calls.Load() != 1 || budget.calls.Load() != 1 {
				t.Fatal(result, dial.calls.Load(), budget.calls.Load())
			}
		})
	}
}
func TestHTTPRejectsRebindingBudgetFailureAndUnsafeMethodsWithoutTraffic(t *testing.T) {
	engine, dial, budget := httpFixture(t, func(w http.ResponseWriter, r *http.Request) { t.Error("unexpected traffic") })
	for _, method := range []string{"POST", "PUT", "DELETE", "OPTIONS"} {
		if result := engine.HTTP(context.Background(), method, "/public/status", matchingRule()); result.Outcome != "INCONCLUSIVE" {
			t.Fatal(result)
		}
	}
	budget.deny = true
	if result := engine.HTTP(context.Background(), "GET", "/public/status", matchingRule()); result.Outcome != "INCONCLUSIVE" {
		t.Fatal(result)
	}
	budget.deny = false
	engine.policy.resolver = fixedResolver{[]netip.Addr{netip.MustParseAddr("10.20.0.9")}}
	if result := engine.HTTP(context.Background(), "GET", "/public/status", matchingRule()); result.Outcome != "INCONCLUSIVE" || dial.calls.Load() != 0 {
		t.Fatal(result, dial.calls.Load())
	}
}
func TestHTTPIncompleteOrOversizedResponseNeverMeansNotFound(t *testing.T) {
	engine, _, _ := httpFixture(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/public/large" {
			fmt.Fprint(w, strings.Repeat("a", (1<<20)+1))
			return
		}
		w.Header().Set("Content-Length", "10000")
		fmt.Fprint(w, "short")
	})
	for _, path := range []string{"/public/large", "/public/truncated"} {
		result := engine.HTTP(context.Background(), "GET", path, matchingRule())
		if result.Outcome != "INCONCLUSIVE" {
			t.Fatal(result)
		}
	}
}
func TestHTTPCancelAndRequestBudget(t *testing.T) {
	engine, dial, _ := httpFixture(t, func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "normal") })
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if result := engine.HTTP(ctx, "GET", "/public/status", matchingRule()); result.Outcome != "INCONCLUSIVE" || dial.calls.Load() != 0 {
		t.Fatal(result)
	}
	engine.requests.Store(300)
	ctx, cancel = context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if result := engine.HTTP(ctx, "GET", "/public/status", matchingRule()); result.Outcome != "INCONCLUSIVE" || dial.calls.Load() != 0 {
		t.Fatal(result)
	}
}
func TestHTTPFollowsBoundedSameOriginRedirectsAndRejectsInvalidRules(t *testing.T) {
	engine, dial, budget := httpFixture(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/public/start" {
			http.Redirect(w, r, "/public/end", 302)
			return
		}
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprint(w, "exposed-123")
	})
	result := engine.HTTP(context.Background(), "GET", "/public/start", matchingRule())
	if result.Outcome != "CONFIRMED" || dial.calls.Load() != 2 || budget.calls.Load() != 2 {
		t.Fatal(result, dial.calls.Load(), budget.calls.Load())
	}
	before := dial.calls.Load()
	for _, rule := range []HTTPRule{{ID: "empty"}, {ID: "regex", Description: "bad regex", Operator: "ALL", Conditions: []Condition{{Kind: "BODY_REGEX", Value: "(?=invalid)"}}}} {
		if result := engine.HTTP(context.Background(), "GET", "/public/start", rule); result.Outcome != "INCONCLUSIVE" || dial.calls.Load() != before {
			t.Fatal(result)
		}
	}
}

func TestHTTPGzipIsBoundedAndHEADDoesNotRequireAResponseBody(t *testing.T) {
	engine, _, _ := httpFixture(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("Content-Encoding", "gzip")
		if r.Method == "HEAD" {
			return
		}
		var out bytes.Buffer
		writer := gzip.NewWriter(&out)
		body := "exposed-123"
		if r.URL.Path == "/public/bomb" {
			body = strings.Repeat("a", (1<<20)+1)
		}
		writer.Write([]byte(body))
		writer.Close()
		data := out.Bytes()
		if r.URL.Path == "/public/corrupt" {
			data[len(data)-1] ^= 1
		}
		w.Write(data)
	})
	result := engine.HTTP(context.Background(), "GET", "/public/normal", matchingRule())
	if result.Outcome != "CONFIRMED" || result.Evidence.WireSHA256 == result.Evidence.ResponseSHA256 {
		t.Fatal(result)
	}
	for _, path := range []string{"/public/bomb", "/public/corrupt"} {
		if result = engine.HTTP(context.Background(), "GET", path, matchingRule()); result.Outcome != "INCONCLUSIVE" {
			t.Fatal(result)
		}
	}
	head := matchingRule()
	head.Conditions = head.Conditions[:2]
	if result = engine.HTTP(context.Background(), "HEAD", "/public/status", head); result.Outcome != "CONFIRMED" || result.Evidence.BodyBytes != 0 {
		t.Fatal(result)
	}
}

type rebindingResolver struct{ calls atomic.Int32 }

func (r *rebindingResolver) LookupNetIP(context.Context, string, string) ([]netip.Addr, error) {
	if r.calls.Add(1) == 1 {
		return []netip.Addr{netip.MustParseAddr("10.20.0.8")}, nil
	}
	return []netip.Addr{netip.MustParseAddr("10.20.0.9")}, nil
}
func TestHTTPRedirectRechecksDNSAndHasABoundedHopCount(t *testing.T) {
	engine, dial, budget := httpFixture(t, func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, "/public/next", 302) })
	engine.policy.resolver = &rebindingResolver{}
	result := engine.HTTP(context.Background(), "GET", "/public/start", matchingRule())
	if result.Outcome != "INCONCLUSIVE" || result.Reason != "DNS_SCOPE_UNVERIFIED" || dial.calls.Load() != 1 || budget.calls.Load() != 2 {
		t.Fatal(result, dial.calls.Load(), budget.calls.Load())
	}
	engine.policy.resolver = fixedResolver{[]netip.Addr{netip.MustParseAddr("10.20.0.8")}}
	result = engine.HTTP(context.Background(), "GET", "/public/start", matchingRule())
	if result.Outcome != "INCONCLUSIVE" || result.Reason != "REDIRECT_LIMIT" || len(result.Evidence.Requests) != 4 {
		t.Fatal(result)
	}
}
func TestHTTPSVerifiesCertificateAndTargetHostname(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprint(w, "exposed-123")
	}))
	defer server.Close()
	cert := server.Certificate()
	if len(cert.DNSNames) == 0 {
		t.Fatal("fixture requires a real certificate DNS identity")
	}
	target := targetFixture()
	target.Hostname = cert.DNSNames[0]
	target.Port = 8080
	target.AllowedPaths = []string{"/public"}
	policy, err := NewPolicy(target, nil)
	if err != nil {
		t.Fatal(err)
	}
	policy.resolver = fixedResolver{[]netip.Addr{netip.MustParseAddr("10.20.0.8")}}
	policy.dialer = &fixtureDial{endpoint: server.Listener.Addr().String()}
	engine, err := NewEngine(policy, &fixtureBudget{})
	if err != nil {
		t.Fatal(err)
	}
	if result := engine.HTTP(context.Background(), "GET", "/public/status", matchingRule()); result.Outcome != "INCONCLUSIVE" || result.Reason != "TLS_CERTIFICATE_UNTRUSTED" {
		t.Fatal("untrusted fixture certificate accepted or unexplained", result)
	}
	roots := x509.NewCertPool()
	roots.AddCert(cert)
	engine.rootCAs = roots
	if result := engine.HTTP(context.Background(), "GET", "/public/status", matchingRule()); result.Outcome != "CONFIRMED" || result.Evidence.TLS == nil || !result.Evidence.TLS.Verified || len(result.Evidence.TLS.CertificateSHA256) != 64 {
		t.Fatal(result)
	}
	engine.policy.hostname = "wrong.example.test"
	if result := engine.HTTP(context.Background(), "GET", "/public/status", matchingRule()); result.Outcome != "INCONCLUSIVE" || result.Reason != "TLS_HOSTNAME_MISMATCH" {
		t.Fatal("hostname mismatch accepted or unexplained", result)
	}
}
