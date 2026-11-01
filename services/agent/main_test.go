package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func TestRemediationBoundary(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("secure remediation Linux only")
	}
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(root, "file")
	os.WriteFile(p, []byte("test"), 0644)
	a := &Agent{Config: Config{AllowedRoot: root}}
	task := Task{ID: "t", Template: "FILE_PERMISSION", Parameters: Check{Path: p, Mode: "0600"}, ExpiresAt: time.Now().Add(time.Hour)}
	if r := a.execute(task); !r.Success {
		t.Fatal(r)
	}
	s, _ := os.Stat(p)
	if s.Mode().Perm() != 0600 {
		t.Fatal(s.Mode())
	}
	link := filepath.Join(root, "link")
	os.Symlink(p, link)
	task.Parameters.Path = link
	if a.execute(task).Success {
		t.Fatal("followed symlink")
	}
	task.Parameters.Path = filepath.Join(t.TempDir(), "other")
	if a.execute(task).Success {
		t.Fatal("escaped root")
	}
	a.Config.AllowedRoot = ""
	task.Parameters.Path = p
	if a.execute(task).Success {
		t.Fatal("default enabled")
	}
}
func TestTLSAndQueue(t *testing.T) {
	if _, e := New(Config{Server: "http://example.com", StateDir: t.TempDir()}); e == nil {
		t.Fatal("accepted insecure URL")
	}
	calls := 0
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.Header.Get("Authorization") != "Bearer secret" {
			t.Error("token missing")
		}
		w.Write([]byte(`{"ok":true}`))
	}))
	defer s.Close()
	dir := t.TempDir()
	a, e := New(Config{Server: s.URL, StateDir: dir})
	if e != nil {
		t.Fatal(e)
	}
	a.Identity.Token = "secret"
	if e = a.enqueue("/agent/heartbeat", map[string]any{"inventory": map[string]string{}}); e != nil {
		t.Fatal(e)
	}
	b, e := New(a.Config)
	if e != nil || len(b.Queue) != 1 {
		t.Fatal("queue not durable", e)
	}
	if e = a.flush(); e != nil || calls != 1 || len(a.Queue) != 0 {
		t.Fatal(e)
	}
	info, _ := os.Stat(filepath.Join(dir, "queue.json"))
	if info.Mode().Perm() != 0600 {
		t.Fatal("unsafe permissions")
	}
}
