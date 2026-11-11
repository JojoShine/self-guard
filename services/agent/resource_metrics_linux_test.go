//go:build linux

package main

import (
	"encoding/json"
	"os"
	"testing"
	"time"
)

func TestResourceMetricsLiveLinux(t *testing.T) {
	a := &Agent{}
	first := a.collectResourceMetrics()
	if first.Memory == nil || len(first.Filesystems) == 0 || first.CPU["logicalCpus"] == nil {
		t.Fatal("live Linux baseline unavailable", first.Status, first.Issues)
	}
	if _, ok := first.CPU["usedPercent"]; ok {
		t.Fatal("first CPU sample fabricated a rate")
	}
	time.Sleep(100 * time.Millisecond)
	second := a.collectResourceMetrics()
	cpu, ok := second.CPU["usedPercent"].(float64)
	if !ok || cpu < 0 || cpu > 100 {
		t.Fatal("live CPU differential unavailable", second.Status, second.Issues)
	}
	if target := os.Getenv("SELFGUARD_METRICS_FIXTURE"); target != "" {
		body, err := json.Marshal(second)
		if err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(target, body, 0600); err != nil {
			t.Fatal(err)
		}
	}
}

func TestResourceFilesystemsSkipRemoteMount(t *testing.T) {
	rows, complete := resourceFilesystems("1 0 0:42 / / rw - nfs remote:/export rw\n")
	if len(rows) != 0 || complete {
		t.Fatalf("remote mounts must remain an explicit gap: rows=%v complete=%v", rows, complete)
	}
}
