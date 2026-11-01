package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"
)

var repairServiceName = regexp.MustCompile(`^[A-Za-z0-9_.@-]+\.service$`)

// Production remediation resolves neither a PATH command nor user-provided command text.
func fixedSystemctl(ctx context.Context, args ...string) (string, error) {
	c := exec.CommandContext(ctx, "/usr/bin/systemctl", args...)
	output := &cappedOutput{}
	c.Stdout = output
	err := c.Run()
	if ctx.Err() != nil {
		return "", ctx.Err()
	}
	if output.truncated {
		return "", errors.New("systemctl output limit exceeded")
	}
	state := strings.TrimSpace(string(output.b))
	// is-active intentionally uses exit 3 for a known nonactive state.
	var exit *exec.ExitError
	if len(args) > 0 && args[0] == "is-active" && errors.As(err, &exit) && exit.ExitCode() == 3 && (state == "inactive" || state == "failed") {
		err = nil
	}
	return state, err
}
func (a *Agent) serviceCommand(operation, name string) (string, error) {
	timeout := a.serviceTimeout
	if timeout <= 0 {
		timeout = 3 * time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	run := a.serviceRunner
	if run == nil {
		run = fixedSystemctl
	}
	output, err := run(ctx, operation, "--", name)
	if ctx.Err() != nil {
		return "", ctx.Err()
	}
	return strings.TrimSpace(output), err
}
func activeState(value string) bool { return value == "active" || value == "inactive" }
func stateOperation(state string) string {
	if state == "active" {
		return "start"
	}
	return "stop"
}

func (a *Agent) executeService(t Task) Result {
	fail := func(reason string) Result { return Result{Evidence: reason} }
	p := t.Parameters
	if runtime.GOOS != "linux" {
		return fail("service remediation requires Linux")
	}
	if t.ExpiresAt.IsZero() || !t.ExpiresAt.After(time.Now()) {
		return fail("task expired or missing expiry")
	}
	if len(p.Service) > 200 || !repairServiceName.MatchString(p.Service) || strings.HasPrefix(p.Service, "-") {
		return fail("invalid service unit")
	}
	allowed := false
	for _, name := range a.Config.AllowedServices {
		if p.Service == name {
			allowed = true
			break
		}
	}
	if !allowed {
		return fail("service remediation disabled or unit not explicitly allowed")
	}
	if !activeState(p.ExpectedState) || !activeState(p.State) {
		return fail("only active/inactive service states can be restored safely")
	}
	marker := filepath.Join(a.Config.StateDir, "service-recovery.json")
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		return fail("service recovery pending or inaccessible; manual verification required")
	}
	before, err := a.serviceCommand("is-active", p.Service)
	if err != nil || !activeState(before) {
		return fail("cannot establish a restorable service state")
	}
	details := map[string]string{"service": p.Service, "previousState": before, "expectedState": p.ExpectedState, "state": p.State}
	if before != p.ExpectedState {
		return Result{Evidence: "service precondition conflict", Details: details}
	}
	if err := writePrivate(a.planPath(t.ID), repairPlan{Task: t}); err != nil {
		return fail("cannot persist private repair plan")
	}
	if before == p.State {
		return Result{Success: true, Evidence: "service already in desired state; independent health verification required", Details: details}
	}
	if err = writePrivate(marker, map[string]string{"taskId": t.ID, "service": p.Service, "previousState": before, "targetState": p.State, "status": "manual state and application health verification required if interrupted"}); err != nil {
		return fail("cannot persist service recovery marker")
	}
	_, commandErr := a.serviceCommand(stateOperation(p.State), p.Service)
	after, verifyErr := a.serviceCommand("is-active", p.Service)
	details["observedState"] = after
	if commandErr == nil && verifyErr == nil && after == p.State {
		if err = removeDurable(marker); err != nil {
			return Result{Evidence: "service state verified but recovery marker removal failed; manual review required", Details: details}
		}
		return Result{Success: true, Evidence: "service state verified; independent application health verification required", Details: details}
	}
	// A failed command may have changed state; always attempt to restore the recorded pre-state.
	_, rollbackErr := a.serviceCommand(stateOperation(before), p.Service)
	restored, restoreCheckErr := a.serviceCommand("is-active", p.Service)
	rollbackOK := rollbackErr == nil && restoreCheckErr == nil && restored == before
	uncertain := !rollbackOK || errors.Is(commandErr, context.DeadlineExceeded) || errors.Is(verifyErr, context.DeadlineExceeded) || errors.Is(rollbackErr, context.DeadlineExceeded) || errors.Is(restoreCheckErr, context.DeadlineExceeded)
	details["rollbackSucceeded"] = fmt.Sprint(rollbackOK)
	details["rollbackObservedState"] = restored
	details["resultUnknown"] = fmt.Sprint(uncertain)
	if rollbackOK && !uncertain {
		if err = removeDurable(marker); err != nil {
			details["recoveryRequired"] = "true"
		} else {
			details["recoveryRequired"] = "false"
		}
	} else {
		details["recoveryRequired"] = "true"
	}
	return Result{Evidence: "service operation or verification failed; review rollback and independently verify service/application health", Details: details}
}
