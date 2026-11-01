package main

import (
	"strings"
	"testing"
)

func TestNginxOnboardingPreservesTLSAndChangesOnlyProxy(t *testing.T) {
	source := `server {
 listen 443 ssl;
 server_name app.example.com;
 ssl_certificate /etc/ssl/fullchain.pem;
 ssl_certificate_key /etc/ssl/private.pem;
 location / {
 proxy_pass http://127.0.0.1:3000;
 proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
 }
}`
	plan, err := planNginxOnboarding([]byte(source), "app.example.com", "http://127.0.0.1:3000", "127.0.0.1:18081")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(plan), "ssl_certificate_key /etc/ssl/private.pem;") || !strings.Contains(string(plan), "proxy_pass http://127.0.0.1:18081;") || !strings.Contains(string(plan), "proxy_set_header X-Forwarded-For $remote_addr;") || strings.Contains(string(plan), "$proxy_add_x_forwarded_for") {
		t.Fatal(string(plan))
	}
}
func TestNginxOnboardingRejectsAmbiguousConfigurations(t *testing.T) {
	for _, s := range []string{
		`server { server_name app.example.com; location / { proxy_pass http://other:3000; } }`,
		`server { server_name app.example.com; include custom.conf; location / { proxy_pass http://127.0.0.1:3000; } }`,
		`server { server_name app.example.com; location / { proxy_pass http://127.0.0.1:3000; } location /admin { proxy_pass http://127.0.0.1:3001; } }`,
		`server { server_name app.example.com alias.example.com; location / { proxy_pass http://127.0.0.1:3000; } }`,
		`server { server_name app.example.com; location / { proxy_pass http://127.0.0.1:3000; rewrite x y; } }`,
		`server { server_name app.example.com; location / { proxy_pass http://127.0.0.1:3000; } } server {server_name other;}`,
	} {
		if _, err := planNginxOnboarding([]byte(s), "app.example.com", "http://127.0.0.1:3000", "127.0.0.1:18081"); err == nil {
			t.Fatal("unsafe configuration accepted", s)
		}
	}
}

func TestHostWafPlanRefusesFloatingOrExternalEntrypoints(t *testing.T) {
	p := HostWafPlan{Schema: "selfguard-nginx-v1", AssetID: "asset-owned", SiteID: "site-owned", Hostname: "app.example.com", Upstream: "http://127.0.0.1:3000", Image: "sha256:" + strings.Repeat("a", 64), NginxConfig: "/etc/nginx/conf.d/app.conf", WafPort: 18081, EntryURL: "http://127.0.0.1/", HealthPath: "/health", Mode: "OBSERVE"}
	if err := p.validate(); err != nil {
		t.Fatal(err)
	}
	p.Image = "selfguard-waf:latest"
	if p.validate() == nil {
		t.Fatal("mutable image accepted")
	}
	p.Image = "sha256:" + strings.Repeat("a", 64)
	p.EntryURL = "http://outside.example/"
	if p.validate() == nil {
		t.Fatal("external ingress probe accepted")
	}
}

func TestNginxOnboardingRetainsOriginalBackendHost(t *testing.T) {
	for _, header := range []string{"", "proxy_set_header Host $proxy_host;", "proxy_set_header Host original.internal:3000;", "proxy_set_header Host $http_host;"} {
		source := []byte("server {server_name public.example;location / {proxy_pass http://127.0.0.1:3000;" + header + "}}")
		out, err := planNginxOnboarding(source, "public.example", "http://127.0.0.1:3000", "127.0.0.1:18081")
		if err != nil {
			t.Fatal(err)
		}
		expected := "127.0.0.1:3000"
		if strings.Contains(header, "original.internal") {
			expected = "original.internal:3000"
		}
		if strings.Contains(header, "$http_host") {
			expected = "$http_host"
		}
		if !strings.Contains(string(out), "X-Selfguard-Original-Host "+expected+";") {
			t.Fatal(string(out))
		}
	}
}
