package scanner

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"math/big"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"
)

func networkFixture(t *testing.T, protocol string, handler func(net.Conn)) (*Engine, *fixtureDial, *fixtureBudget) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	go func() {
		for {
			connection, err := listener.Accept()
			if err != nil {
				return
			}
			go func() { defer connection.Close(); handler(connection) }()
		}
	}()
	policy, err := NewPolicy(Target{Hostname: "app.example.test", Port: 8080, Protocol: protocol, Addresses: []string{"10.20.0.8"}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	policy.resolver = fixedResolver{[]netip.Addr{netip.MustParseAddr("10.20.0.8")}}
	dial := &fixtureDial{endpoint: listener.Addr().String()}
	policy.dialer = dial
	budget := &fixtureBudget{}
	engine, err := NewEngine(policy, budget)
	if err != nil {
		t.Fatal(err)
	}
	return engine, dial, budget
}
func networkRule(kind string) NetworkRule {
	return NetworkRule{ID: "owned-network", Description: "Explicit owned service observation", Kind: kind}
}
func TestNetworkConnectIsObservationAndHasActualSocketEvidence(t *testing.T) {
	var writes atomic.Int32
	engine, dial, budget := networkFixture(t, "tcp", func(connection net.Conn) {
		connection.SetReadDeadline(time.Now().Add(time.Second))
		buffer := make([]byte, 1)
		n, _ := connection.Read(buffer)
		writes.Add(int32(n))
	})
	result := engine.Network(context.Background(), networkRule("TCP_CONNECT"))
	if result.Outcome != "OBSERVED" || budget.calls.Load() != 1 || dial.calls.Load() != 1 || len(result.Evidence.Connections) != 1 || result.Evidence.Connections[0].Destination != dial.endpoint || result.Evidence.Connections[0].Source == "" || result.Evidence.StartedAt.IsZero() {
		t.Fatalf("missing actual connection observation: %+v", result)
	}
	if writes.Load() != 0 {
		t.Fatal("connect observation sent application commands")
	}
}
func TestNetworkBannerMatchesActualBoundedReadWithoutSendingCommands(t *testing.T) {
	engine, _, budget := networkFixture(t, "tcp", func(connection net.Conn) { connection.Write([]byte("owned-legacy-service 1.0\r\n")) })
	rule := networkRule("TCP_BANNER")
	rule.Value = "legacy-service 1.0"
	result := engine.Network(context.Background(), rule)
	sum := sha256.Sum256([]byte("owned-legacy-service 1.0\r\n"))
	if result.Outcome != "CONFIRMED" || result.Evidence.BannerSHA256 != hex.EncodeToString(sum[:]) || result.Evidence.BannerPreview != "owned-legacy-service 1.0\r\n" || budget.calls.Load() != 1 {
		t.Fatalf("banner evidence differs from socket bytes: %+v", result)
	}
	rule.Value = "absent"
	if result = engine.Network(context.Background(), rule); result.Outcome != "NOT_FOUND" {
		t.Fatal(result)
	}
}
func TestNetworkCannotBypassBudgetDNSCancellationOrProtocol(t *testing.T) {
	engine, dial, budget := networkFixture(t, "tcp", func(connection net.Conn) {})
	budget.deny = true
	if result := engine.Network(context.Background(), networkRule("TCP_CONNECT")); result.Outcome != "INCONCLUSIVE" || dial.calls.Load() != 0 {
		t.Fatal(result)
	}
	budget.deny = false
	engine.policy.resolver = fixedResolver{[]netip.Addr{netip.MustParseAddr("127.0.0.1")}}
	if result := engine.Network(context.Background(), networkRule("TCP_CONNECT")); result.Outcome != "INCONCLUSIVE" || dial.calls.Load() != 0 {
		t.Fatal(result)
	}
	engine.policy.resolver = fixedResolver{[]netip.Addr{netip.MustParseAddr("10.20.0.8")}}
	before := budget.calls.Load()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if result := engine.Network(ctx, networkRule("TCP_CONNECT")); result.Outcome != "INCONCLUSIVE" || dial.calls.Load() != 0 || budget.calls.Load() != before {
		t.Fatal(result)
	}
	if result := engine.Network(context.Background(), networkRule("TLS_CERT_EXPIRED")); result.Outcome != "INCONCLUSIVE" || budget.calls.Load() != before {
		t.Fatal(result)
	}
}
func TestNetworkScopeCannotSilentlyIgnoreWebPaths(t *testing.T) {
	for _, protocol := range []string{"tcp", "tls"} {
		for _, target := range []Target{{Hostname: "app.example.test", Port: 8080, Protocol: protocol, Addresses: []string{"10.20.0.8"}, AllowedPaths: []string{"/public"}}, {Hostname: "app.example.test", Port: 8080, Protocol: protocol, Addresses: []string{"10.20.0.8"}, ExcludedPaths: []string{"/private"}}} {
			if _, err := NewPolicy(target, nil); err == nil {
				t.Fatal("network scope silently discarded HTTP paths")
			}
		}
	}
}
func TestNetworkTLSRetainsActualLeafAndTrustResultWithoutWeakeningHTTPS(t *testing.T) {
	for _, expired := range []bool{false, true} {
		t.Run(map[bool]string{false: "valid", true: "expired"}[expired], func(t *testing.T) {
			key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			now := time.Now()
			end := now.Add(24 * time.Hour)
			if expired {
				end = now.Add(-time.Hour)
			}
			template := &x509.Certificate{SerialNumber: big.NewInt(41), Subject: pkix.Name{CommonName: "app.example.test"}, DNSNames: []string{"app.example.test"}, NotBefore: now.Add(-48 * time.Hour), NotAfter: end, KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, BasicConstraintsValid: true, IsCA: true}
			raw, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
			if err != nil {
				t.Fatal(err)
			}
			certificate, err := x509.ParseCertificate(raw)
			if err != nil {
				t.Fatal(err)
			}
			engine, _, budget := networkFixture(t, "tls", func(connection net.Conn) {
				session := tls.Server(connection, &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{raw}, PrivateKey: key}}, MinVersion: tls.VersionTLS12})
				session.Handshake()
			})
			engine.rootCAs = x509.NewCertPool()
			engine.rootCAs.AddCert(certificate)
			result := engine.Network(context.Background(), networkRule("TLS_CERT_EXPIRED"))
			want := "NOT_FOUND"
			if expired {
				want = "CONFIRMED"
			}
			if result.Outcome != want || result.Evidence.TLS == nil || result.Evidence.TLS.CertificateSHA256 != hashBytes(raw) || result.Evidence.TLS.Verified == expired || budget.calls.Load() != 1 {
				t.Fatalf("TLS observation lost actual certificate or validation: %+v", result)
			}
			if expired && result.Evidence.ValidationReason != "TLS_CERTIFICATE_EXPIRED" {
				t.Fatal(result)
			}
		})
	}
}

func TestNetworkOfflineSamplesAreExplicitAndCannotOpenConnections(t *testing.T) {
	now := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	for _, sample := range []struct {
		rule        NetworkRule
		observation NetworkSample
		matched     bool
		observe     bool
	}{
		{networkRule("TCP_CONNECT"), NetworkSample{Connected: true}, true, true},
		{networkRule("TCP_CONNECT"), NetworkSample{}, false, true},
		{NetworkRule{ID: "banner", Description: "Owned marker", Kind: "TCP_BANNER", Value: "legacy"}, NetworkSample{Connected: true, Banner: "owned legacy\r\n"}, true, false},
		{networkRule("TLS_CERT_EXPIRED"), NetworkSample{Connected: true, ObservedAt: now, NotBefore: now.Add(-48 * time.Hour), NotAfter: now.Add(-time.Hour), TLSVersion: "TLS1.3"}, true, false},
		{networkRule("TLS_CERT_EXPIRED"), NetworkSample{Connected: true, ObservedAt: now, NotBefore: now.Add(-48 * time.Hour), NotAfter: now.Add(time.Hour), TLSVersion: "TLS1.3"}, false, false},
	} {
		result, err := CheckNetworkRule(sample.rule, sample.observation)
		if err != nil || result.Matched != sample.matched || result.Observation != sample.observe {
			t.Fatal(result, err)
		}
	}
	for _, sample := range []NetworkSample{{Connected: true}, {Connected: true, ObservedAt: now, NotBefore: now, NotAfter: now.Add(-time.Hour), TLSVersion: "TLS1.3"}} {
		if _, err := CheckNetworkRule(networkRule("TLS_CERT_EXPIRED"), sample); err == nil {
			t.Fatal("incomplete certificate sample accepted")
		}
	}
}

func TestNetworkCancellationStopsPassiveReadWithoutAFalseCleanResult(t *testing.T) {
	accepted := make(chan struct{})
	engine, _, _ := networkFixture(t, "tcp", func(connection net.Conn) {
		close(accepted)
		connection.SetReadDeadline(time.Now().Add(3 * time.Second))
		buffer := make([]byte, 1)
		connection.Read(buffer)
	})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan NetworkResult, 1)
	rule := networkRule("TCP_BANNER")
	rule.Value = "not-observed"
	go func() { done <- engine.Network(ctx, rule) }()
	<-accepted
	cancel()
	select {
	case result := <-done:
		if result.Outcome != "INCONCLUSIVE" || result.Reason != "CANCELLED" {
			t.Fatal(result)
		}
	case <-time.After(time.Second):
		t.Fatal("cancellation did not stop the service read")
	}
}

type networkChangingBudget struct {
	policy *Policy
	calls  int
}

func (b *networkChangingBudget) Acquire(ctx context.Context, keys []string) error {
	b.calls++
	b.policy.resolver = fixedResolver{[]netip.Addr{netip.MustParseAddr("127.0.0.1")}}
	return nil
}
func TestNetworkRechecksDNSAfterSharedAllowanceWait(t *testing.T) {
	engine, dial, _ := networkFixture(t, "tcp", func(connection net.Conn) { t.Error("unapproved network traffic") })
	budget := &networkChangingBudget{policy: engine.policy}
	engine.budget = budget
	result := engine.Network(context.Background(), networkRule("TCP_CONNECT"))
	if result.Outcome != "INCONCLUSIVE" || result.Reason != "DNS_SCOPE_UNVERIFIED" || budget.calls != 1 || dial.calls.Load() != 0 {
		t.Fatal(result)
	}
}
func TestNetworkOversizedBannerNeverBecomesCleanOrConfirmed(t *testing.T) {
	engine, _, _ := networkFixture(t, "tcp", func(connection net.Conn) { connection.Write(bytes.Repeat([]byte("x"), 4097)) })
	rule := networkRule("TCP_BANNER")
	rule.Value = "x"
	result := engine.Network(context.Background(), rule)
	if result.Outcome != "INCONCLUSIVE" || result.Reason != "BANNER_LIMIT" || result.Evidence.BannerBytes > 4096 || len(result.Evidence.BannerPreview) > 1024 {
		t.Fatal(result)
	}
}
