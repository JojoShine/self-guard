package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestNginxIngressPreservesOriginalUpstreamHost(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Selfguard-Original-Host") != "" {
			t.Error("internal ingress header forwarded")
		}
		w.Write([]byte(r.Host))
	}))
	defer upstream.Close()
	e := newEngine()
	if err := e.update(Config{Sites: []Site{{ID: "owned", Hostname: "public.example", Upstream: upstream.URL, Enabled: true, Mode: "OBSERVE", Version: 1, Config: Policy{NginxIngress: true, TrustedProxyCidrs: []string{"127.0.0.1/32"}}}}}); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ peer, expected string }{{"127.0.0.1:1234", "original.internal:3000"}, {"192.0.2.10:1234", "public.example"}} {
		r := httptest.NewRequest("GET", "http://public.example/", nil)
		r.RemoteAddr = tc.peer
		r.Header.Set("X-Selfguard-Original-Host", "original.internal:3000")
		w := httptest.NewRecorder()
		e.ServeHTTP(w, r)
		if w.Code != 200 || w.Body.String() != tc.expected {
			t.Fatal(w.Code, w.Body.String(), tc.expected)
		}
	}
}
