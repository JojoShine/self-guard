//go:build !linux

package main

import "time"

func (a *Agent) collectResourceMetrics() resourceMetric {
	return resourceMetric{Schema: "selfguard-host-metrics-v1", CapturedAt: time.Now().UTC().Format(time.RFC3339Nano), Status: "UNSUPPORTED", Issues: []string{"LINUX_REQUIRED"}, CPU: map[string]any{}, Network: map[string]any{}, Filesystems: []resourceFilesystem{}}
}
