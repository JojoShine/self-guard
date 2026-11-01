package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestPolicyBoundaryAndCache(t *testing.T) {
	root, _ := filepath.EvalSymlinks(t.TempDir())
	p := filepath.Join(root, "file")
	os.WriteFile(p, []byte("x"), 0600)
	a := &Agent{Config: Config{StateDir: root, AllowedRoot: root}}
	a.applyPolicy([]PolicyRule{{Kind: "FIM", Config: PolicyConfig{Path: p}}, {Kind: "FIM", Config: PolicyConfig{Path: "/etc/passwd"}}})
	if len(a.RemoteFIM) != 1 {
		t.Fatal(a.RemoteFIM)
	}
	a.applyPolicy(nil)
	if len(a.RemoteFIM) != 0 {
		t.Fatal("stale snapshot")
	}
	if matches("bad\nok\nbad\n", "bad", 2) != 2 {
		t.Fatal("threshold")
	}
	if matches("bad\n", "bad", 2) != 0 {
		t.Fatal("below threshold")
	}
}

func TestPolicyReloadAndOfflineCache(t *testing.T) {
	root, _ := filepath.EvalSymlinks(t.TempDir())
	p := filepath.Join(root, "file")
	os.WriteFile(p, []byte("x"), 0600)
	enabled := true
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if enabled {
			json.NewEncoder(w).Encode(map[string]any{"rules": []PolicyRule{{Kind: "FIM", Config: PolicyConfig{Path: p}}}})
		} else {
			w.Write([]byte(`{"rules":[]}`))
		}
	}))
	a, e := New(Config{Server: server.URL, StateDir: root, AllowedRoot: root})
	if e != nil {
		t.Fatal(e)
	}
	a.policy()
	if len(a.RemoteFIM) != 1 {
		t.Fatal("load")
	}
	server.Close()
	b, _ := New(a.Config)
	b.policy()
	if len(b.RemoteFIM) != 1 {
		t.Fatal("offline cache")
	}
	enabled = false
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(`{"rules":[]}`)) }))
	defer server.Close()
	b.Config.Server = server.URL
	b.policy()
	if len(b.RemoteFIM) != 0 {
		t.Fatal("disable snapshot")
	}
}
