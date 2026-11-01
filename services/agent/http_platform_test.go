package main

import (
	"strings"
	"testing"
)

func TestHTTPPlatformRequiresExplicitConfigAndPreservesUpgradeOrigin(t *testing.T) {
	c := installationCollectorConfig("http://platform.example:8080", "root", "")
	c.ReadOnly = true
	c.StateDir = t.TempDir()
	if !c.AllowHTTP {
		t.Fatal("HTTP installation must persist its explicit transport choice")
	}
	if _, err := New(c); err != nil {
		t.Fatal(err)
	}
	c.AllowHTTP = false
	if _, err := New(c); err == nil {
		t.Fatal("HTTP must remain explicit outside installed configuration")
	}
	c.AllowHTTP = true
	if err := trustedArtifact(c, "http://platform.example:8080/api/agent-releases/owned/download"); err != nil {
		t.Fatal(err)
	}
	for _, url := range []string{"https://platform.example:8080/a", "http://other.example:8080/a"} {
		if trustedArtifact(c, url) == nil {
			t.Fatal("origin/protocol substitution allowed")
		}
	}
	if _, err := offlineInstallationState(installationProfile{Server: "http://platform.example:8080"}, "0.4.10"); err != nil {
		t.Fatal(err)
	}
}
func TestHTTPTransportDoesNotDowngradeHTTPS(t *testing.T) {
	c := installationCollectorConfig("https://platform.example", "root", "")
	if c.AllowHTTP {
		t.Fatal("HTTPS must not opt in to HTTP")
	}
	if err := trustedArtifact(c, "http://platform.example/a"); err == nil {
		t.Fatal("HTTPS transport downgraded")
	}
	if !strings.HasPrefix(c.UpgradeOrigins[0], "https:") {
		t.Fatal("configured origin changed")
	}
}
