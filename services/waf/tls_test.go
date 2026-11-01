package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func writeTestCertificate(t *testing.T, dir, host string, serial int64) (string, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: host}, DNSNames: []string{host}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	secret, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certFile := filepath.Join(dir, host+".pem")
	keyFile := filepath.Join(dir, host+".key")
	if err = os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: secret}), 0600); err != nil {
		t.Fatal(err)
	}
	return certFile, keyFile
}
func TestSNIHandshakeReloadAndInvalidRetention(t *testing.T) {
	dir := t.TempDir()
	a, ak := writeTestCertificate(t, dir, "a.test", 1)
	b, bk := writeTestCertificate(t, dir, "b.test", 2)
	path := filepath.Join(dir, "tls.json")
	data, _ := json.Marshal([]map[string]string{{"hostname": "a.test", "certFile": a, "keyFile": ak}, {"hostname": "b.test", "certFile": b, "keyFile": bk}})
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	store := &certificateStore{}
	if err := store.reload(path); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	srv.TLS = store.tlsConfig()
	srv.StartTLS()
	defer srv.Close()
	check := func(host string, want int64) {
		t.Helper()
		conn, err := tls.Dial("tcp", srv.Listener.Addr().String(), &tls.Config{ServerName: host, InsecureSkipVerify: true})
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		cert := conn.ConnectionState().PeerCertificates[0]
		if cert.SerialNumber.Int64() != want || cert.VerifyHostname(host) != nil {
			t.Fatal("wrong SNI certificate")
		}
	}
	check("a.test", 1)
	check("b.test", 2)
	writeTestCertificate(t, dir, "a.test", 3)
	if err := store.reload(path); err != nil {
		t.Fatal(err)
	}
	check("a.test", 3)
	if err := os.WriteFile(a, []byte("broken"), 0600); err != nil {
		t.Fatal(err)
	}
	if store.reload(path) == nil {
		t.Fatal("invalid reload accepted")
	}
	check("a.test", 3)
	check("b.test", 2)
	conn, err := tls.Dial("tcp", srv.Listener.Addr().String(), &tls.Config{ServerName: "unknown.test", InsecureSkipVerify: true})
	if err == nil {
		conn.Close()
		t.Fatal("unknown SNI accepted")
	}
}
func TestHealthChecksRealStatusAndNoRedirect(t *testing.T) {
	var path string
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { path = r.URL.Path; w.WriteHeader(503) }))
	defer up.Close()
	e := newEngine()
	if err := e.update(Config{Sites: []Site{{ID: "a", Hostname: "a", Upstream: up.URL, Mode: "BLOCK", Enabled: true, Config: Policy{HealthCheckPath: "/ready"}}}}); err != nil {
		t.Fatal(err)
	}
	e.checkUpstreams()
	h := e.health.Load().([]UpstreamHealth)
	if len(h) != 1 || h[0].Healthy || h[0].StatusCode != 503 || path != "/ready" {
		t.Fatal(h, path)
	}
	up.Close()
	e.checkUpstreams()
	h = e.health.Load().([]UpstreamHealth)
	if h[0].Healthy || h[0].StatusCode != 0 {
		t.Fatal(h)
	}
}
