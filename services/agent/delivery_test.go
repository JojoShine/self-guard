package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func TestHeartbeatBatchEvidence(t *testing.T) {
	a := &Agent{Config: Config{StateDir: t.TempDir()}}
	f := []map[string]any{}
	for i := 0; i < 221; i++ {
		f = append(f, map[string]any{"evidence": map[string]string{"path": "x"}})
	}
	if e := a.heartbeat(map[string]any{}, f); e != nil {
		t.Fatal(e)
	}
	if len(a.Queue) != 3 {
		t.Fatal(len(a.Queue))
	}
	for _, p := range a.Queue {
		var body struct {
			Findings []struct {
				Evidence string `json:"evidence"`
			} `json:"findings"`
		}
		if e := json.Unmarshal(p.Body, &body); e != nil {
			t.Fatal(e)
		}
		if len(body.Findings) > 100 {
			t.Fatal("oversized")
		}
	}
}
func TestResultCrashRecovery(t *testing.T) {
	calls := 0
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls++; w.Write([]byte(`{"ok":true}`)) }))
	defer s.Close()
	c := Config{Server: s.URL, StateDir: t.TempDir()}
	writePrivate(filepath.Join(c.StateDir, "done.json"), map[string]Result{"id": {Success: true, Evidence: "verified"}})
	a, _ := New(c)
	if e := a.sendResults(); e != nil {
		t.Fatal(e)
	}
	b, _ := New(c)
	if e := b.sendResults(); e != nil {
		t.Fatal(e)
	}
	if calls != 1 {
		t.Fatal(calls)
	}
}
func TestRejectUnsafeModesAndParentSymlink(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux")
	}
	root, _ := filepath.EvalSymlinks(t.TempDir())
	p := filepath.Join(root, "file")
	os.WriteFile(p, []byte("x"), 0600)
	a := &Agent{Config: Config{AllowedRoot: root}}
	task := Task{Template: "FILE_PERMISSION", Parameters: Check{Path: p, Mode: "0777"}, ExpiresAt: time.Now().Add(time.Hour)}
	if a.execute(task).Success {
		t.Fatal("unsafe mode")
	}
	link := filepath.Join(root, "link")
	os.Symlink(root, link)
	if f, e := openTarget(filepath.Join(link, "file")); e == nil {
		f.Close()
		t.Fatal("parent symlink followed")
	}
}
