package main

import (
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

type repairPlan struct {
	Task         Task
	PreviousMode string
}

func (a *Agent) planPath(id string) string {
	return filepath.Join(a.Config.StateDir, fmt.Sprintf("repair-plan-%x.json", sha256.Sum256([]byte(id))))
}
func (a *Agent) execute(t Task) Result {
	if a.Config.ExecutorSocket != "" {
		return a.executeViaExecutor(t)
	}
	if a.Config.ReadOnly && t.Template != "VERIFY_READ" {
		return Result{Evidence: "managed collector is read-only; explicitly enabled executor required"}
	}
	if err := a.validateRelatedHealth(t); err != nil {
		return Result{Evidence: err.Error()}
	}
	if t.Template != "VERIFY_READ" {
		if _, err := os.Stat(filepath.Join(a.Config.StateDir, "service-recovery.json")); !os.IsNotExist(err) {
			return Result{Evidence: "service recovery pending or inaccessible; further task mutation refused"}
		}
	}
	if t.Template == "VERIFY_READ" || t.Template == "ROLLBACK" {
		return a.executeLifecycle(t)
	}
	if t.Template != "FILE_PERMISSION" && t.Template != "CONFIG_VALUE" && t.Template != "SERVICE_STATE" {
		return a.executeMutation(t)
	}
	if t.Template == "SERVICE_STATE" {
		return a.executeMutation(t)
	}
	// Record original local intent before any mutation; the server cannot supply backup paths or original modes.
	plan := repairPlan{Task: t}
	if t.Template == "FILE_PERMISSION" {
		if err := safePath(a.Config.AllowedRoot, t.Parameters.Path); err != nil {
			return Result{Evidence: err.Error()}
		}
		f, err := openTarget(t.Parameters.Path)
		if err != nil {
			return Result{Evidence: "cannot open backup target"}
		}
		defer f.Close()
		s, err := f.Stat()
		if err != nil || !s.Mode().IsRegular() || multipleLinks(s) {
			return Result{Evidence: "backup requires regular single-link file"}
		}
		plan.PreviousMode = fmt.Sprintf("%04o", s.Mode().Perm())
	}
	if err := writePrivate(a.planPath(t.ID), plan); err != nil {
		return Result{Evidence: "cannot persist private repair plan"}
	}
	return a.executeMutation(t)
}
func (a *Agent) executeLifecycle(t Task) Result {
	fail := func(s string) Result { return Result{Evidence: s} }
	id := t.Parameters.OriginalTaskID
	if id == "" || len(id) > 200 || t.ExpiresAt.IsZero() || !t.ExpiresAt.After(time.Now()) {
		return fail("invalid original task or expiry")
	}
	var plan repairPlan
	if err := read(a.planPath(id), &plan); err != nil || plan.Task.ID != id {
		return fail("original local repair plan unavailable")
	}
	original, ok := a.Done[id]
	if !ok || !original.Success {
		return fail("original successful task unavailable")
	}
	p := plan.Task.Parameters
	if t.Template == "VERIFY_READ" {
		matched := a.verifyRepair(plan.Task)
		details := map[string]string{"verifiedTaskId": id, "fileVerified": strconv.FormatBool(matched)}
		if p.HealthService != "" {
			healthy, healthDetails := a.relatedHealth(p.HealthService)
			for key, value := range healthDetails {
				details[key] = value
			}
			matched = matched && healthy
		}
		details["verificationPassed"] = strconv.FormatBool(matched)
		return Result{Success: matched, Evidence: "fresh target read and configured related-service health probe completed", Details: details}
	}
	for _, marker := range []string{"service-recovery.json", "config-recovery.json"} {
		if _, err := os.Stat(filepath.Join(a.Config.StateDir, marker)); !os.IsNotExist(err) {
			return fail("pending recovery requires operator reconciliation before rollback")
		}
	}
	if !a.verifyRepair(plan.Task) {
		return fail("rollback precondition failed: target changed since repair")
	}
	reverse := Task{ID: t.ID, Template: plan.Task.Template, Parameters: p, ExpiresAt: t.ExpiresAt}
	if err := a.validateRelatedHealth(reverse); err != nil {
		return fail(err.Error())
	}
	switch reverse.Template {
	case "FILE_PERMISSION":
		// Original permission can include values outside the mutation allowlist; restore only the locally saved mode.
		mode, e := strconv.ParseUint(plan.PreviousMode, 8, 12)
		if e != nil {
			return fail("invalid local permission backup")
		}
		if e = safePath(a.Config.AllowedRoot, p.Path); e != nil {
			return fail("unsafe rollback path")
		}
		f, e := openTarget(p.Path)
		if e != nil {
			return fail("rollback open failed")
		}
		defer f.Close()
		s, e := f.Stat()
		current, ce := os.Lstat(p.Path)
		if e != nil || ce != nil || !s.Mode().IsRegular() || multipleLinks(s) || !os.SameFile(s, current) {
			return fail("rollback target changed")
		}
		reverse.Parameters.Mode = plan.PreviousMode
		if e = writePrivate(a.planPath(t.ID), repairPlan{Task: reverse, PreviousMode: p.Mode}); e != nil {
			return fail("rollback plan persistence failed")
		}
		if e = f.Chmod(os.FileMode(mode)); e != nil {
			return fail("rollback chmod failed")
		}
		after, e := f.Stat()
		if e != nil || after.Mode().Perm() != os.FileMode(mode) {
			return fail("rollback readback failed")
		}
		return Result{Success: true, Evidence: "original local permission restored and read back", Details: map[string]string{"rollbackOf": id}}
	case "CONFIG_VALUE":
		reverse.Parameters.ExpectedValue = p.Value
		reverse.Parameters.Value = p.ExpectedValue
	case "SERVICE_STATE":
		reverse.Parameters.ExpectedState = p.State
		reverse.Parameters.State = p.ExpectedState
	default:
		return fail("original template cannot be rolled back")
	}
	result := a.execute(reverse)
	if result.Details == nil {
		result.Details = map[string]string{}
	}
	result.Details["rollbackOf"] = id
	return result
}
func (a *Agent) verifyRepair(t Task) bool {
	p := t.Parameters
	if t.Template == "SERVICE_STATE" {
		allowed := false
		for _, unit := range a.Config.AllowedServices {
			if unit == p.Service {
				allowed = true
			}
		}
		if !allowed || !repairServiceName.MatchString(p.Service) {
			return false
		}
		actual, err := a.serviceCommand("is-active", p.Service)
		return err == nil && actual == p.State
	}
	if err := safePath(a.Config.AllowedRoot, p.Path); err != nil {
		return false
	}
	f, err := openTarget(p.Path)
	if err != nil {
		return false
	}
	defer f.Close()
	s, err := f.Stat()
	if err != nil || !s.Mode().IsRegular() || multipleLinks(s) {
		return false
	}
	current, err := os.Lstat(p.Path)
	if err != nil || !os.SameFile(s, current) {
		return false
	}
	if t.Template == "FILE_PERMISSION" {
		mode, e := strconv.ParseUint(p.Mode, 8, 12)
		return e == nil && s.Mode().Perm() == os.FileMode(mode)
	}
	if t.Template != "CONFIG_VALUE" || s.Size() > 64<<10 {
		return false
	}
	b, err := io.ReadAll(io.LimitReader(f, (64<<10)+1))
	if err != nil || len(b) > 64<<10 {
		return false
	}
	matches := 0
	for _, line := range strings.Split(string(b), "\n") {
		key, value, ok := strings.Cut(line, "=")
		if ok && key == p.Key {
			if value != p.Value {
				return false
			}
			matches++
		}
	}
	return matches == 1
}
