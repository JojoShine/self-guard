package main

import (
	"net/url"
	"testing"
)

func TestPlatformBasePath(t *testing.T) {
	for _, path := range []string{"", "/", "/self-guard", "/self-guard/"} {
		u, _ := url.Parse("https://platform.example" + path)
		if !validPlatformPath(u) {
			t.Fatal("valid path refused", path)
		}
	}
	for _, path := range []string{"/a/../b", "/a//b", "/%2fadmin", "/api", "/a?b", "/a#b"} {
		u, _ := url.Parse("https://platform.example" + path)
		if validPlatformPath(u) {
			t.Fatal("unsafe path accepted", path)
		}
	}
	c := installationCollectorConfig("https://platform.example/self-guard", "root", "")
	c.ReadOnly = true
	c.StateDir = t.TempDir()
	if _, err := New(c); err != nil {
		t.Fatal(err)
	}
	if err := trustedArtifact(c, "https://platform.example/self-guard/api/agent-releases/owned/download"); err != nil {
		t.Fatal(err)
	}
	if err := trustedArtifact(c, "https://platform.example/other/api/agent-releases/owned/download"); err == nil {
		t.Fatal("escaped platform scope")
	}
	if _, err := offlineInstallationState(installationProfile{Server: c.Server}, "0.4.11"); err != nil {
		t.Fatal(err)
	}
}
