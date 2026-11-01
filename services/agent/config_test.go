package main

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func TestConfigValue(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux")
	}
	root, _ := filepath.EvalSymlinks(t.TempDir())
	p := filepath.Join(root, "app.conf")
	a := &Agent{Config: Config{AllowedRoot: root, StateDir: root}}
	task := Task{ID: "config", Template: "CONFIG_VALUE", ExpiresAt: time.Now().Add(time.Hour), Parameters: Check{Path: p, Key: "DEBUG", ExpectedValue: "true", Value: "false"}}
	for _, body := range []string{"DEBUG=other\n", "DEBUG=true\nDEBUG=true\n"} {
		os.WriteFile(p, []byte(body), 0600)
		if a.execute(task).Success {
			t.Fatal("accepted conflict")
		}
	}
	os.WriteFile(p, []byte("# comment\nDEBUG=true\n"), 0600)
	if r := a.execute(task); !r.Success {
		t.Fatal(r)
	}
	b, _ := os.ReadFile(p)
	if string(b) != "# comment\nDEBUG=false\n" {
		t.Fatal(string(b))
	}
	task.Parameters.Value = "false\nBAD=yes"
	if a.execute(task).Success {
		t.Fatal("accepted injection")
	}
}

func TestHardlinkMutationRefused(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux")
	}
	base, _ := filepath.EvalSymlinks(t.TempDir())
	root := filepath.Join(base, "allowed")
	os.Mkdir(root, 0700)
	outside := filepath.Join(base, "outside")
	os.WriteFile(outside, []byte("DEBUG=true\n"), 0644)
	inside := filepath.Join(root, "linked")
	if e := os.Link(outside, inside); e != nil {
		t.Fatal(e)
	}
	a := &Agent{Config: Config{AllowedRoot: root, StateDir: base}}
	for _, template := range []string{"FILE_PERMISSION", "CONFIG_VALUE"} {
		task := Task{ID: template, Template: template, ExpiresAt: time.Now().Add(time.Hour), Parameters: Check{Path: inside, Mode: "0600", Key: "DEBUG", ExpectedValue: "true", Value: "false"}}
		if a.execute(task).Success {
			t.Fatal("hardlink mutated", template)
		}
	}
	b, _ := os.ReadFile(outside)
	s, _ := os.Stat(outside)
	if string(b) != "DEBUG=true\n" || s.Mode().Perm() != 0644 {
		t.Fatal("outside changed")
	}
}
func TestRecoveryMarkerStopsAgent(t *testing.T) {
	d := t.TempDir()
	writePrivate(filepath.Join(d, "config-recovery.json"), map[string]string{"status": "pending"})
	a := &Agent{Config: Config{StateDir: d}}
	if e := a.cycle(); e == nil {
		t.Fatal("did not stop")
	}
}
