package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestRelatedServiceHealthAllowlistAndFreshRead(t *testing.T) {
	root, _ := filepath.EvalSymlinks(t.TempDir())
	file := filepath.Join(root, "file")
	os.WriteFile(file, []byte("DEBUG=true\n"), 0644)
	a := &Agent{Config: Config{StateDir: root, AllowedRoot: root}, Done: map[string]Result{}}
	task := Task{ID: "health-repair", Template: "FILE_PERMISSION", Parameters: Check{Path: file, Mode: "0600", HealthService: "app.service"}, ExpiresAt: time.Now().Add(time.Hour)}
	calls := 0
	state := "active"
	a.serviceRunner = func(ctx context.Context, args ...string) (string, error) {
		calls++
		if args[0] != "is-active" || args[1] != "--" || args[2] != "app.service" {
			t.Fatal("health probe mutated service", args)
		}
		return state, nil
	}
	if r := a.execute(task); r.Success {
		t.Fatal("unlisted health service allowed")
	}
	info, _ := os.Stat(file)
	if info.Mode().Perm() != 0644 || calls != 0 {
		t.Fatal("disallowed service mutated file/probed")
	}
	a.Config.AllowedServices = []string{"app.service"}
	a.Done[task.ID] = a.execute(task)
	if !a.Done[task.ID].Success {
		t.Fatal(a.Done[task.ID])
	}
	if calls != 0 {
		t.Fatal("mutation executed unsolicited health command")
	}
	verify := Task{ID: "verify-health", Template: "VERIFY_READ", Parameters: Check{OriginalTaskID: task.ID}, ExpiresAt: task.ExpiresAt}
	r := a.execute(verify)
	if !r.Success || r.Details["healthOutcome"] != "ACTIVE" {
		t.Fatal(r)
	}
	state = "inactive"
	r = a.execute(verify)
	if r.Success || r.Details["healthOutcome"] != "INACTIVE" || r.Details["fileVerified"] != "true" {
		t.Fatal(r)
	}
	rollback := Task{ID: "health-rollback", Template: "ROLLBACK", Parameters: Check{OriginalTaskID: task.ID}, ExpiresAt: task.ExpiresAt}
	a.Done[rollback.ID] = a.execute(rollback)
	if !a.Done[rollback.ID].Success {
		t.Fatal(a.Done[rollback.ID])
	}
	verify.Parameters.OriginalTaskID = rollback.ID
	r = a.execute(verify)
	if r.Success || r.Details["healthService"] != "app.service" {
		t.Fatal("rollback lost related health plan", r)
	}
}
func TestRelatedServiceHealthTimeoutIsUnknownAndReadOnly(t *testing.T) {
	root, _ := filepath.EvalSymlinks(t.TempDir())
	file := filepath.Join(root, "config")
	os.WriteFile(file, []byte("DEBUG=true\n"), 0600)
	a := &Agent{Config: Config{StateDir: root, AllowedRoot: root, AllowedServices: []string{"app.service"}}, Done: map[string]Result{}, serviceTimeout: time.Millisecond}
	task := Task{ID: "health-config", Template: "CONFIG_VALUE", Parameters: Check{Path: file, Key: "DEBUG", ExpectedValue: "true", Value: "false", HealthService: "app.service"}, ExpiresAt: time.Now().Add(time.Hour)}
	a.Done[task.ID] = a.execute(task)
	if !a.Done[task.ID].Success {
		t.Fatal(a.Done[task.ID])
	}
	a.serviceRunner = func(ctx context.Context, args ...string) (string, error) {
		if args[0] != "is-active" {
			t.Fatal("readonly health command mutated service")
		}
		<-ctx.Done()
		return "", ctx.Err()
	}
	r := a.execute(Task{ID: "probe", Template: "VERIFY_READ", Parameters: Check{OriginalTaskID: task.ID}, ExpiresAt: task.ExpiresAt})
	if r.Success || r.Details["resultUnknown"] != "true" || r.Details["healthOutcome"] != "UNKNOWN" {
		t.Fatal(r)
	}
	if _, err := os.Stat(filepath.Join(root, "service-recovery.json")); !os.IsNotExist(err) {
		t.Fatal("readonly probe created mutation recovery marker")
	}
}
