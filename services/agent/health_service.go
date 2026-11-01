package main

import (
	"context"
	"errors"
	"runtime"
	"strings"
)

func (a *Agent) relatedServiceAllowed(name string) bool {
	if runtime.GOOS != "linux" || len(name) > 200 || !repairServiceName.MatchString(name) || strings.HasPrefix(name, "-") {
		return false
	}
	for _, allowed := range a.Config.AllowedServices {
		if name == allowed {
			return true
		}
	}
	return false
}
func (a *Agent) validateRelatedHealth(t Task) error {
	if t.Parameters.HealthService == "" {
		return nil
	}
	if (t.Template != "FILE_PERMISSION" && t.Template != "CONFIG_VALUE") || !a.relatedServiceAllowed(t.Parameters.HealthService) {
		return errors.New("related health service must be an explicitly allowed Linux .service unit on a file/config repair")
	}
	return nil
}
func (a *Agent) relatedHealth(name string) (bool, map[string]string) {
	details := map[string]string{"healthService": name, "healthVerified": "false"}
	if !a.relatedServiceAllowed(name) {
		details["healthOutcome"] = "DISALLOWED"
		return false, details
	}
	state, err := a.serviceCommand("is-active", name)
	if err != nil {
		details["healthOutcome"] = "UNKNOWN"
		details["resultUnknown"] = "true"
		if errors.Is(err, context.DeadlineExceeded) {
			details["healthReason"] = "probe timeout"
		} else {
			details["healthReason"] = "probe failed"
		}
		return false, details
	}
	switch state {
	case "active":
		details["healthOutcome"] = "ACTIVE"
		details["healthVerified"] = "true"
		return true, details
	case "inactive", "failed", "activating", "deactivating", "reloading", "maintenance":
		details["healthOutcome"] = strings.ToUpper(state)
	default:
		details["healthOutcome"] = "UNKNOWN"
		details["resultUnknown"] = "true"
	}
	return false, details
}
