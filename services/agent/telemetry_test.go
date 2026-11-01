package main

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
)

func TestCollectorTelemetryAtomicDurabilityAndRedaction(t *testing.T) {
	a := &Agent{Config: Config{StateDir: t.TempDir()}}
	f := []map[string]any{event("/secret/log:offset-1", "secret message", "agent-log", map[string]any{"path": "/secret/log", "message": "credential=secret", "ruleId": "rule-123"})}
	if err := a.heartbeat(map[string]any{}, f); err != nil {
		t.Fatal(err)
	}
	if len(a.Queue) != 2 || a.Queue[1].Path != "/telemetry/events" {
		t.Fatal("collector telemetry missing", a.Queue)
	}
	raw := string(a.Queue[1].Body)
	if strings.Contains(raw, "secret") || strings.Contains(raw, "message") || strings.Contains(raw, "path") {
		t.Fatal("sensitive telemetry", raw)
	}
	var batch struct {
		Events []struct {
			ID   string            `json:"id"`
			Type string            `json:"type"`
			Data map[string]string `json:"data"`
		} `json:"events"`
	}
	json.Unmarshal(a.Queue[1].Body, &batch)
	if len(batch.Events) != 1 || len(batch.Events[0].ID) != 64 || batch.Events[0].Type != "HOST_LOG" || batch.Events[0].Data["ruleId"] != "rule-123" {
		t.Fatal(raw)
	}
	var durable []Pending
	if err := read(filepath.Join(a.Config.StateDir, "queue.json"), &durable); err != nil || len(durable) != 2 {
		t.Fatal("queue not durable", err)
	}
	a.Queue = make([]Pending, 127)
	if err := a.heartbeat(map[string]any{}, f); err == nil {
		t.Fatal("partial collector batch accepted")
	}
	if len(a.Queue) != 127 {
		t.Fatal("partial batch queued")
	}
}
