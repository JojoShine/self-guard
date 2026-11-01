package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"testing"
	"time"
)

func serviceFixture(t *testing.T) (*Agent, Task) {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skip("Linux service remediation")
	}
	a := &Agent{Config: Config{StateDir: t.TempDir(), AllowedServices: []string{"demo.service"}}}
	task := Task{ID: "service-fixture", Template: "SERVICE_STATE", ExpiresAt: time.Now().Add(time.Hour), Parameters: Check{Service: "demo.service", ExpectedState: "inactive", State: "active"}}
	return a, task
}
func TestServiceRepairAllowlistAndInput(t *testing.T) {
	a, task := serviceFixture(t)
	calls := 0
	a.serviceRunner = func(context.Context, ...string) (string, error) { calls++; return "inactive", nil }
	a.Config.AllowedServices = nil
	if a.execute(task).Success || calls != 0 {
		t.Fatal("default enable")
	}
	a.Config.AllowedServices = []string{"demo.service"}
	for _, name := range []string{"other.service", "demo;id.service", "../demo.service", "--help.service", "demo.socket", "demo.service\n", "demo.service --now"} {
		bad := task
		bad.Parameters.Service = name
		if a.execute(bad).Success || calls != 0 {
			t.Fatal("unsafe or unlisted unit", name)
		}
	}
	for _, state := range []string{"failed", "activating", "active;id", ""} {
		bad := task
		bad.Parameters.State = state
		if a.execute(bad).Success || calls != 0 {
			t.Fatal("unsafe target", state)
		}
	}
	task.ExpiresAt = time.Now().Add(-time.Second)
	if a.execute(task).Success || calls != 0 {
		t.Fatal("expired executed")
	}
}
func TestServiceRepairSuccessAndDurablePrestate(t *testing.T) {
	a, task := serviceFixture(t)
	state := "inactive"
	calls := [][]string{}
	a.serviceRunner = func(ctx context.Context, args ...string) (string, error) {
		calls = append(calls, append([]string{}, args...))
		if _, ok := ctx.Deadline(); !ok {
			t.Fatal("unbounded command")
		}
		switch args[0] {
		case "is-active":
			return state, nil
		case "start":
			var marker map[string]string
			if e := read(filepath.Join(a.Config.StateDir, "service-recovery.json"), &marker); e != nil || marker["previousState"] != "inactive" || marker["taskId"] != task.ID {
				t.Fatal("prestate not durable", marker, e)
			}
			state = "active"
			return "", nil
		default:
			t.Fatal("unexpected operation", args)
			return "", nil
		}
	}
	r := a.execute(task)
	if !r.Success || r.Details["previousState"] != "inactive" {
		t.Fatal(r)
	}
	want := [][]string{{"is-active", "--", "demo.service"}, {"start", "--", "demo.service"}, {"is-active", "--", "demo.service"}}
	if !reflect.DeepEqual(calls, want) {
		t.Fatal(calls)
	}
	if _, e := os.Stat(filepath.Join(a.Config.StateDir, "service-recovery.json")); !os.IsNotExist(e) {
		t.Fatal("marker remained", e)
	}
}
func TestServiceRepairPreconditionAndAlreadyDesired(t *testing.T) {
	a, task := serviceFixture(t)
	calls := 0
	a.serviceRunner = func(_ context.Context, args ...string) (string, error) {
		calls++
		if args[0] != "is-active" {
			t.Fatal("unexpected mutation")
		}
		return "active", nil
	}
	if r := a.execute(task); r.Success || r.Evidence != "service precondition conflict" || calls != 1 {
		t.Fatal(r, calls)
	}
	task.Parameters.ExpectedState = "active"
	if r := a.execute(task); !r.Success || calls != 2 {
		t.Fatal(r, calls)
	}
	a.serviceRunner = func(context.Context, ...string) (string, error) { return "failed", nil }
	if r := a.execute(task); r.Success {
		t.Fatal("nonrestorable state accepted", r)
	}
}
func TestServiceRepairVerificationFailureRestoresState(t *testing.T) {
	a, task := serviceFixture(t)
	ops := []string{}
	a.serviceRunner = func(_ context.Context, args ...string) (string, error) {
		ops = append(ops, args[0])
		return "inactive", nil
	}
	r := a.execute(task)
	if r.Success || r.Details["rollbackSucceeded"] != "true" || r.Details["recoveryRequired"] != "false" {
		t.Fatal(r)
	}
	if !reflect.DeepEqual(ops, []string{"is-active", "start", "is-active", "stop", "is-active"}) {
		t.Fatal(ops)
	}
	if _, e := os.Stat(filepath.Join(a.Config.StateDir, "service-recovery.json")); !os.IsNotExist(e) {
		t.Fatal("restored marker remained", e)
	}
}
func TestServiceRepairRollbackFailureRetainsRecovery(t *testing.T) {
	a, task := serviceFixture(t)
	probes := 0
	a.serviceRunner = func(_ context.Context, args ...string) (string, error) {
		if args[0] == "is-active" {
			probes++
			if probes == 1 {
				return "inactive", nil
			}
			return "activating", nil
		}
		if args[0] == "stop" {
			return "", errors.New("denied")
		}
		return "", nil
	}
	r := a.execute(task)
	if r.Success || r.Details["rollbackSucceeded"] != "false" || r.Details["recoveryRequired"] != "true" {
		t.Fatal(r)
	}
	if _, e := os.Stat(filepath.Join(a.Config.StateDir, "service-recovery.json")); e != nil {
		t.Fatal(e)
	}
	a.serviceRunner = func(context.Context, ...string) (string, error) { t.Fatal("recovery allowed command"); return "", nil }
	if a.execute(task).Success {
		t.Fatal("pending recovery accepted")
	}
	if a.cycle() == nil {
		t.Fatal("recovery did not pause cycle")
	}
	if r := a.execute(Task{Template: "FILE_PERMISSION"}); r.Success || r.Evidence != "service recovery pending or inaccessible; further task mutation refused" {
		t.Fatal("other mutation not blocked", r)
	}
}
func TestServiceRepairTimeoutRemainsUnknownEvenAfterRestore(t *testing.T) {
	a, task := serviceFixture(t)
	a.serviceTimeout = 5 * time.Millisecond
	a.serviceRunner = func(ctx context.Context, args ...string) (string, error) {
		if args[0] == "start" {
			<-ctx.Done()
			return "", ctx.Err()
		}
		return "inactive", nil
	}
	r := a.execute(task)
	if r.Success || r.Details["rollbackSucceeded"] != "true" || r.Details["resultUnknown"] != "true" || r.Details["recoveryRequired"] != "true" {
		t.Fatal(r)
	}
	if _, e := os.Stat(filepath.Join(a.Config.StateDir, "service-recovery.json")); e != nil {
		t.Fatal(e)
	}
	if a.cycle() == nil {
		t.Fatal("unknown timeout recovery did not pause")
	}
}
func TestServiceRepairMarkerPersistenceFailurePreventsMutation(t *testing.T) {
	a, task := serviceFixture(t)
	a.Config.StateDir = filepath.Join(a.Config.StateDir, "missing")
	calls := 0
	a.serviceRunner = func(_ context.Context, args ...string) (string, error) {
		calls++
		if args[0] != "is-active" {
			t.Fatal("mutation without marker")
		}
		return "inactive", nil
	}
	if r := a.execute(task); r.Success || calls != 1 {
		t.Fatal(r, calls)
	}
}
