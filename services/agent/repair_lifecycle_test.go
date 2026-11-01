package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestRepairRollbackAndFreshVerification(t *testing.T) {
	root, _ := filepath.EvalSymlinks(t.TempDir())
	path := filepath.Join(root, "managed")
	os.WriteFile(path, []byte("DEBUG=true\n"), 0644)
	a := &Agent{Config: Config{StateDir: root, AllowedRoot: root}, Done: map[string]Result{}}
	task := Task{ID: "repair", Template: "FILE_PERMISSION", Parameters: Check{Path: path, Mode: "0600"}, ExpiresAt: time.Now().Add(time.Hour)}
	a.Done[task.ID] = a.execute(task)
	if !a.Done[task.ID].Success {
		t.Fatal(a.Done[task.ID])
	}
	verify := Task{ID: "verify", Template: "VERIFY_READ", Parameters: Check{OriginalTaskID: task.ID}, ExpiresAt: task.ExpiresAt}
	if r := a.execute(verify); !r.Success {
		t.Fatal(r)
	}
	os.Chmod(path, 0640)
	if r := a.execute(verify); r.Success {
		t.Fatal("verification reused stale successful result")
	}
	rollback := Task{ID: "rollback", Template: "ROLLBACK", Parameters: Check{OriginalTaskID: task.ID}, ExpiresAt: task.ExpiresAt}
	if r := a.execute(rollback); r.Success {
		t.Fatal("rollback overwrote changed target")
	}
	os.Chmod(path, 0600)
	if r := a.execute(rollback); !r.Success {
		t.Fatal(r)
	}
	info, _ := os.Stat(path)
	if info.Mode().Perm() != 0644 {
		t.Fatal("original mode not restored")
	}
	task = Task{ID: "config", Template: "CONFIG_VALUE", Parameters: Check{Path: path, Key: "DEBUG", ExpectedValue: "true", Value: "false"}, ExpiresAt: time.Now().Add(time.Hour)}
	a.Done[task.ID] = a.execute(task)
	if !a.Done[task.ID].Success {
		t.Fatal(a.Done[task.ID])
	}
	verify.Parameters.OriginalTaskID = task.ID
	if r := a.execute(verify); !r.Success {
		t.Fatal(r)
	}
	rollback.Parameters.OriginalTaskID = task.ID
	if r := a.execute(rollback); !r.Success {
		t.Fatal(r)
	}
	b, _ := os.ReadFile(path)
	if string(b) != "DEBUG=true\n" {
		t.Fatal("configuration not restored")
	}
}
