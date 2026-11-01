package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestFIMLifecycle(t *testing.T) {
	d, _ := filepath.EvalSymlinks(t.TempDir())
	p := filepath.Join(d, "watch")
	a := &Agent{Config: Config{StateDir: d, AllowedRoot: d}}
	a.applyPolicy([]PolicyRule{{Kind: "FIM", Config: PolicyConfig{Path: p}}})
	if len(a.RemoteFIM) != 1 {
		t.Fatal("absent watch rejected")
	}
	if len(a.collectFiles()) != 0 {
		t.Fatal("first missing baseline")
	}
	a.commitCollectors()
	os.WriteFile(p, []byte("x"), 0600)
	f := a.collectFiles()
	if len(f) != 1 || f[0]["evidence"].(map[string]string)["change"] != "created" {
		t.Fatal(f)
	}
	replay := a.collectFiles()
	if len(replay) != 1 || replay[0]["externalId"] != f[0]["externalId"] {
		t.Fatal("unstable replay ID", replay, f)
	}
	a.commitCollectors()
	os.Remove(p)
	f = a.collectFiles()
	if len(f) != 1 || f[0]["evidence"].(map[string]string)["change"] != "deleted" {
		t.Fatal(f)
	}
	a.commitCollectors()
	os.Mkdir(p, 0700)
	f = a.collectFiles()
	if len(f) != 1 || f[0]["evidence"].(map[string]string)["change"] != "unreadable" {
		t.Fatal(f)
	}
	a.commitCollectors()
	if len(a.collectFiles()) != 0 {
		t.Fatal("repeated unreadable")
	}
}
func ruleEvents(f []map[string]any) int {
	n := 0
	for _, v := range f {
		if v["title"] == "Log rule matched" {
			n++
		}
	}
	return n
}
func TestLogPartialWindowAndRestart(t *testing.T) {
	d := t.TempDir()
	p := filepath.Join(d, "log")
	os.WriteFile(p, []byte("ba"), 0600)
	a := &Agent{Config: Config{StateDir: d, LogPaths: []string{p}}, LogRules: []PolicyRule{{ID: "r", Config: PolicyConfig{Contains: "bad", Field: "message", Threshold: 2, WindowSeconds: 10}}}}
	now := time.Now()
	if ruleEvents(a.collectFilesAt(now)) != 0 {
		t.Fatal("partial matched")
	}
	a.commitCollectors()
	appendFile := func(s string) { f, _ := os.OpenFile(p, os.O_APPEND|os.O_WRONLY, 0600); f.WriteString(s); f.Close() }
	appendFile("d\n")
	if ruleEvents(a.collectFilesAt(now.Add(time.Second))) != 0 {
		t.Fatal("below threshold")
	}
	a.commitCollectors()
	b := &Agent{Config: a.Config, LogRules: a.LogRules}
	appendFile("bad\n")
	if ruleEvents(b.collectFilesAt(now.Add(2*time.Second))) != 1 {
		t.Fatal("restart lost rolling count")
	}
	b.commitCollectors()
	appendFile("bad\n")
	if ruleEvents(b.collectFilesAt(now.Add(13*time.Second))) != 0 {
		t.Fatal("expired lines counted")
	}
}
func TestLogRotationWithIdenticalPrefix(t *testing.T) {
	d := t.TempDir()
	p := filepath.Join(d, "log")
	body := strings.Repeat("x", 64) + "\nbad\n"
	os.WriteFile(p, []byte(body), 0600)
	a := &Agent{Config: Config{StateDir: d, LogPaths: []string{p}}}
	a.collectFiles()
	a.commitCollectors()
	if a.CollectorState["log:"+p].Identity == "" {
		t.Skip("inode detection Linux only")
	}
	os.Rename(p, p+".1")
	os.WriteFile(p, []byte(body), 0600)
	if len(a.collectFiles()) != 1 {
		t.Fatal("same-prefix replacement skipped")
	}
}
func TestConfigBaseline(t *testing.T) {
	d, _ := filepath.EvalSymlinks(t.TempDir())
	p := filepath.Join(d, "config")
	os.WriteFile(p, []byte("SECRET=old\n"), 0600)
	a := &Agent{Config: Config{AllowedRoot: d, Checks: []Check{{Type: "CONFIG_VALUE", Path: p, Key: "SECRET", Value: "new"}}}}
	f := a.collectBaselines()
	if len(f) != 1 {
		t.Fatal(f)
	}
	ev := f[0]["evidence"].(map[string]string)
	if ev["actual"] != "" || ev["expected"] != "" {
		t.Fatal("secret leaked")
	}
	a.Config.Checks[0].Value = "old"
	if len(a.collectBaselines()) != 0 {
		t.Fatal("correct config failed")
	}
	os.WriteFile(p, []byte("SECRET=old\nSECRET=old\n"), 0600)
	if len(a.collectBaselines()) != 1 {
		t.Fatal("duplicate key passed")
	}
}
func TestPortAndServiceParsing(t *testing.T) {
	for _, tt := range []struct {
		raw, want string
		port      int
	}{{"0100007F:1F90", "127.0.0.1", 8080}, {"00000000000000000000000001000000:01BB", "::1", 443}} {
		a, p, e := procAddress(tt.raw)
		if e != nil || a != tt.want || p != tt.port {
			t.Fatal(a, p, e)
		}
	}
	d := t.TempDir()
	for _, p := range []string{"tcp", "tcp6", "udp", "udp6"} {
		os.WriteFile(filepath.Join(d, p), []byte("header\n"), 0600)
	}
	os.WriteFile(filepath.Join(d, "tcp"), []byte("header\n0: 0100007F:1F90 00000000:0000 0A\n1: 0100007F:1F91 00000000:0000 01\n"), 0600)
	ports, status := portInventory(d)
	if len(ports) != 1 || ports[0].Port != 8080 || !status.Complete {
		t.Fatal(ports, status)
	}
	services, status := serviceLines(&cappedOutput{b: []byte("sshd.service loaded active running SSH\n")})
	if !status.Complete || len(services) != 1 || services[0].State != "active" {
		t.Fatal(services, status)
	}
	if validService("--help") || validService("a;id") {
		t.Fatal("unsafe service accepted")
	}
}

func TestSystemdEscapedServiceNamesDoNotInvalidateInventory(t *testing.T) {
	name := `systemd-fsck@dev-disk-by\x2dlabel-BOOT.service`
	services, status := serviceLines(&cappedOutput{b: []byte(name + " loaded active exited File System Check\n")})
	if !status.Complete || len(services) != 1 || services[0].Name != name {
		t.Fatalf("%+v %+v", services, status)
	}
	for _, name := range []string{`sshd\evil.service`, `sshd\xZZ.service`, "--help", "a;id"} {
		if validService(name) {
			t.Fatalf("unsafe service accepted: %s", name)
		}
	}
}

func TestServiceBaseline(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux service fixture")
	}
	d := t.TempDir()
	os.WriteFile(filepath.Join(d, "systemctl"), []byte("#!/bin/sh\nprintf 'active\\n'\n"), 0700)
	t.Setenv("PATH", d)
	a := &Agent{Config: Config{Checks: []Check{{Type: "SERVICE_STATE", Service: "sshd.service", State: "active"}}}}
	if f := a.collectBaselines(); len(f) != 0 {
		t.Fatal(f)
	}
	a.Config.Checks[0].State = "inactive"
	if f := a.collectBaselines(); len(f) != 1 {
		t.Fatal(f)
	}
	t.Setenv("PATH", t.TempDir())
	if f := a.collectBaselines(); len(f) != 1 || f[0]["evidence"].(map[string]string)["status"] != "unreadable" {
		t.Fatal(f)
	}
}

func TestOfflineCollectionSurvivesRestart(t *testing.T) {
	d, _ := filepath.EvalSymlinks(t.TempDir())
	p := filepath.Join(d, "log")
	os.WriteFile(p, []byte("first\n"), 0600)
	online := false
	received := 0
	telemetryReceived := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !online {
			w.WriteHeader(503)
			return
		}
		switch r.URL.Path {
		case "/api/agent/policy":
			w.Write([]byte(`{"rules":[]}`))
		case "/api/agent/tasks":
			w.Write([]byte(`{"items":[]}`))
		case "/api/telemetry/events":
			telemetryReceived++
			w.Write([]byte(`{}`))
		case "/api/agent/heartbeat":
			received++
			w.Write([]byte(`{}`))
		default:
			w.WriteHeader(404)
		}
	}))
	defer server.Close()
	c := Config{Server: server.URL, StateDir: d, AllowedRoot: d, LogPaths: []string{p}}
	a, e := New(c)
	if e != nil {
		t.Fatal(e)
	}
	a.Identity = Identity{Token: "fixture", AssetID: "fixture"}
	writePrivate(filepath.Join(d, "identity.json"), a.Identity)
	if a.cycle() == nil || len(a.Queue) != 2 {
		t.Fatal("offline report not buffered", len(a.Queue))
	}
	os.WriteFile(p, []byte("first\nsecond\n"), 0600)
	if a.cycle() == nil || len(a.Queue) != 4 {
		t.Fatal("offline collection stopped", len(a.Queue))
	}
	online = true
	b, e := New(c)
	if e != nil {
		t.Fatal(e)
	}
	if e = b.cycle(); e != nil {
		t.Fatal(e)
	}
	if received != 3 || telemetryReceived != 2 || len(b.Queue) != 0 {
		t.Fatal(received, len(b.Queue))
	}
}
