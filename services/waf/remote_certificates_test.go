package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestRemoteCertificatesEncryptedOfflineCacheAndAtomicRenewal(t *testing.T) {
	dir := t.TempDir()
	cert, key := writeTestCertificate(t, dir, "remote.test", 31)
	pem, _ := os.ReadFile(cert)
	secret, _ := os.ReadFile(key)
	token := strings.Repeat("t", 32)
	payload := []remoteCertificate{{Hostname: "remote.test", Certificate: string(pem), PrivateKey: string(secret), Version: 1}}
	status := 200
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/waf/certificates" || r.Header.Get("Authorization") != "Bearer "+token {
			t.Error("unauthorized certificate request")
		}
		w.WriteHeader(status)
		json.NewEncoder(w).Encode(map[string]any{"items": payload, "generatedAt": time.Now().UTC().Format(time.RFC3339)})
	}))
	defer api.Close()
	store := &certificateStore{}
	if err := store.syncRemote(api.Client(), api.URL, token, dir); err != nil {
		t.Fatal(err)
	}
	cache := filepath.Join(dir, "certificates.enc")
	data, err := os.ReadFile(cache)
	if err != nil || strings.Contains(string(data), "PRIVATE KEY") || strings.Contains(string(data), "CERTIFICATE") {
		t.Fatal("unencrypted cache", err)
	}
	info, _ := os.Stat(cache)
	if info.Mode().Perm() != 0600 {
		t.Fatal("unsafe cache mode")
	}
	offline := &certificateStore{}
	if err = offline.loadRemoteCache(dir, token); err != nil {
		t.Fatal(err)
	}
	check := func(s *certificateStore, want int64) {
		t.Helper()
		srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
		srv.TLS = s.tlsConfig()
		srv.StartTLS()
		defer srv.Close()
		conn, err := tls.Dial("tcp", srv.Listener.Addr().String(), &tls.Config{ServerName: "remote.test", InsecureSkipVerify: true})
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		if conn.ConnectionState().PeerCertificates[0].SerialNumber.Int64() != want {
			t.Fatal("wrong remote SNI certificate")
		}
	}
	check(offline, 31)
	if (&certificateStore{}).loadRemoteCache(dir, "wrong-token") == nil {
		t.Fatal("cache authentication missing")
	}
	cert, key = writeTestCertificate(t, dir, "remote.test", 32)
	pem, _ = os.ReadFile(cert)
	secret, _ = os.ReadFile(key)
	payload[0] = remoteCertificate{Hostname: "remote.test", Certificate: string(pem), PrivateKey: string(secret), Version: 2}
	if err = store.syncRemote(api.Client(), api.URL, token, dir); err != nil {
		t.Fatal(err)
	}
	check(store, 32)
	payload = append(payload, remoteCertificate{Hostname: "bad.test", Certificate: "bad", PrivateKey: "raw-secret"})
	if store.syncRemote(api.Client(), api.URL, token, dir) == nil {
		t.Fatal("bad rotation accepted")
	}
	check(store, 32)
	restored := &certificateStore{}
	if err = restored.loadRemoteCache(dir, token); err != nil {
		t.Fatal(err)
	}
	check(restored, 32)
	expired := store.certificates.Load().(map[string]*tls.Certificate)["remote.test"]
	expired.Leaf.NotAfter = time.Now().Add(-time.Minute)
	if _, err = store.tlsConfig().GetCertificate(&tls.ClientHelloInfo{ServerName: "remote.test"}); err == nil {
		t.Fatal("expired certificate accepted")
	}
}

func TestRemoteCertificateSubprocessOfflineBoot(t *testing.T) {
	if testing.Short() {
		t.Skip("process lifecycle test")
	}
	dir := t.TempDir()
	cert, key := writeTestCertificate(t, dir, "remote.test", 87)
	certPEM, _ := os.ReadFile(cert)
	keyPEM, _ := os.ReadFile(key)
	token := strings.Repeat("r", 32)
	config := filepath.Join(dir, "config.json")
	if err := persistConfig(config, []byte(`{"sites":[]}`)); err != nil {
		t.Fatal(err)
	}
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/waf/certificates" {
			http.NotFound(w, r)
			return
		}
		if r.Header.Get("Authorization") != "Bearer "+token {
			http.Error(w, "identity", 401)
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"items": []remoteCertificate{{Hostname: "remote.test", Certificate: string(certPEM), PrivateKey: string(keyPEM), Version: 1}}, "generatedAt": time.Now().UTC().Format(time.RFC3339)})
	}))
	defer api.Close()
	start := func() func() {
		t.Helper()
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		addr := listener.Addr().String()
		listener.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestWAFSubprocess$")
		cmd.Env = append(os.Environ(), "WAF_SUBPROCESS=true", "WAF_LISTEN="+addr, "WAF_STATE_DIR="+dir, "WAF_CONFIG="+config, "WAF_API_URL="+api.URL, "WAF_TOKEN="+token, "WAF_REMOTE_CERTIFICATES=true", "WAF_TLS_CONFIG=", "WAF_TLS_CERT=", "WAF_TLS_KEY=", "WAF_TEST_LISTEN=")
		if err = cmd.Start(); err != nil {
			cancel()
			t.Fatal(err)
		}
		stop := func() { cancel(); _ = cmd.Wait() }
		t.Cleanup(stop)
		deadline := time.Now().Add(7 * time.Second)
		for time.Now().Before(deadline) {
			conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 500 * time.Millisecond}, "tcp", addr, &tls.Config{ServerName: "remote.test", InsecureSkipVerify: true})
			if err == nil {
				serial := conn.ConnectionState().PeerCertificates[0].SerialNumber.Int64()
				conn.Close()
				if serial != 87 {
					stop()
					t.Fatal("wrong remote certificate")
				}
				return stop
			}
			time.Sleep(20 * time.Millisecond)
		}
		stop()
		t.Fatal("remote certificate TLS process unavailable")
		return func() {}
	}
	stop := start()
	stop()
	api.Close()
	offlineStop := start()
	offlineStop()
}
