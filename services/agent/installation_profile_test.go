package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestInstallationProfileScopesResourcesAndState(t *testing.T) {
	profile := installationProfile{StateDir: "/var/lib/selfguard-agent-production", ProxyURL: "http://proxy.example:3128", CollectionRoot: "/srv/data", FIMPaths: []string{"/srv/data/config"}, LogPaths: []string{"/srv/data/access.log"}, MaxCPUs: 2, MaxMemoryBytes: 256 << 20, MaxQueueBytes: 16 << 20, BytesPerSecond: 65536, CPUQuotaPercent: 30}
	c, err := applyInstallationProfile(installationCollectorConfig("https://guard.example", "root", ""), profile)
	if err != nil {
		t.Fatal(err)
	}
	if !c.ReadOnly || c.StateDir != profile.StateDir || c.AllowedRoot != "/srv/data" || c.ProxyURL != profile.ProxyURL || c.MaxCPUs != 2 || len(c.FIMPaths) != 1 {
		t.Fatal("profile was not applied", c)
	}
	unit := installationCollectorUnit(false, c)
	for _, want := range []string{"StateDirectory=selfguard-agent-production", "ReadWritePaths=/var/lib/selfguard-agent-production", "MemoryMax=268435456", "CPUQuota=30%"} {
		if !strings.Contains(unit, want) {
			t.Fatal("unit omitted profile", want)
		}
	}
	for _, change := range []func(*installationProfile){func(p *installationProfile) { p.StateDir = "/etc/agent" }, func(p *installationProfile) { p.ProxyURL = "http://user:secret@proxy.example" }, func(p *installationProfile) { p.FIMPaths = []string{"/srv/data/../secret"} }, func(p *installationProfile) { p.LogPaths = []string{"/srv/database/log"} }, func(p *installationProfile) { p.CollectionRoot = "/" }, func(p *installationProfile) { p.MaxMemoryBytes = 1024 }} {
		bad := profile
		change(&bad)
		if _, e := applyInstallationProfile(Config{}, bad); e == nil {
			t.Fatal("unsafe profile accepted", bad)
		}
	}
}
func TestReadOnlyCollectorCannotMutateEvenWithReadableRoot(t *testing.T) {
	root := t.TempDir()
	file := filepath.Join(root, "data")
	os.WriteFile(file, []byte("fixture"), 0644)
	a := &Agent{Config: Config{ReadOnly: true, AllowedRoot: root, StateDir: root}, Done: map[string]Result{}}
	r := a.execute(Task{ID: "read-only", Template: "FILE_PERMISSION", Parameters: Check{Path: file, Mode: "0600"}})
	if r.Success {
		t.Fatal("collector changed file")
	}
	st, _ := os.Stat(file)
	if st.Mode().Perm() != 0644 {
		t.Fatal("collector wrote without executor")
	}
}
