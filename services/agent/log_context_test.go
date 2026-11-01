package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func contextMessages(t *testing.T, a *Agent, findings []map[string]any) ([]string, []string) {
	t.Helper()
	pending, err := a.collectorTelemetry(findings)
	if err != nil {
		t.Fatal(err)
	}
	messages, ids := []string{}, []string{}
	for _, p := range pending {
		var batch struct {
			Events []struct {
				ID   string            `json:"id"`
				Type string            `json:"type"`
				Data map[string]string `json:"data"`
			} `json:"events"`
		}
		if err = json.Unmarshal(p.Body, &batch); err != nil {
			t.Fatal(err)
		}
		for _, event := range batch.Events {
			if event.Type == "HOST_LOG_LINE" {
				if _, ok := event.Data["path"]; ok {
					t.Fatal("path leaked")
				}
				messages = append(messages, event.Data["message"])
				ids = append(ids, event.ID)
			}
		}
	}
	return messages, ids
}
func TestLogContextOptInRedactionPartialReplayAndRotation(t *testing.T) {
	dir := t.TempDir()
	log := filepath.Join(dir, "private.log")
	content := "login password=supersecret token:token-secret Authorization: Bearer bearer-secret customer=private-id\nsecond partial"
	os.WriteFile(log, []byte(content), 0600)
	a := &Agent{Identity: Identity{AssetID: "asset"}, Config: Config{StateDir: dir, LogPaths: []string{log}, LogRedactions: []string{`customer=[^ ]+`}}}
	findings := a.collectFiles()
	messages, _ := contextMessages(t, a, findings)
	if len(messages) != 0 {
		t.Fatal("defaultfalse included context")
	}
	a.Config.LogIncludeMessage = true
	findings = a.collectFiles()
	messages, ids := contextMessages(t, a, findings)
	if len(messages) != 1 {
		t.Fatal(messages)
	}
	for _, secret := range []string{"supersecret", "token-secret", "bearer-secret", "private-id"} {
		if strings.Contains(messages[0], secret) {
			t.Fatal("secret leaked", secret, messages)
		}
	}
	replay := a.collectFiles()
	_, replayIDs := contextMessages(t, a, replay)
	if len(replayIDs) != 1 || replayIDs[0] != ids[0] {
		t.Fatal("retry IDs changed")
	}
	if err := a.heartbeat(map[string]any{}, findings); err != nil {
		t.Fatal(err)
	}
	if err := a.commitCollectors(); err != nil {
		t.Fatal(err)
	}
	b := &Agent{Config: a.Config, Identity: a.Identity}
	next := b.collectFiles()
	messages, _ = contextMessages(t, b, next)
	if len(messages) != 0 {
		t.Fatal("unfinished line emitted")
	}
	f, _ := os.OpenFile(log, os.O_APPEND|os.O_WRONLY, 0600)
	f.WriteString(" completed token=next-secret\n")
	f.Close()
	next = b.collectFiles()
	messages, _ = contextMessages(t, b, next)
	if len(messages) != 1 || !strings.Contains(messages[0], "second partial completed") || strings.Contains(messages[0], "next-secret") {
		t.Fatal(messages)
	}
	b.commitCollectors()
	os.Rename(log, log+".1")
	os.WriteFile(log, []byte("rotated password=rotation-secret\n"), 0600)
	next = b.collectFiles()
	messages, _ = contextMessages(t, b, next)
	if len(messages) != 1 || strings.Contains(messages[0], "rotation-secret") {
		t.Fatal(messages)
	}
}
func TestLogContextBoundsAndInvalidRedactions(t *testing.T) {
	dir := t.TempDir()
	log := filepath.Join(dir, "log")
	os.WriteFile(log, []byte(strings.Repeat("é", 3000)+" token=secret\n"+strings.Repeat("line\n", 150)), 0600)
	a := &Agent{Config: Config{StateDir: dir, LogPaths: []string{log}, LogIncludeMessage: true}}
	first := a.collectFiles()
	messages, _ := contextMessages(t, a, first)
	if len(messages) != 100 || len(messages[0]) > 4096 || strings.Contains(messages[0], "secret") {
		t.Fatal("bounds failed", len(messages))
	}
	a.commitCollectors()
	second := a.collectFiles()
	messages, _ = contextMessages(t, a, second)
	if len(messages) != 51 {
		t.Fatal("bounded cursor lost remaining lines", len(messages))
	}
	bad := a.Config
	bad.Server = "http://127.0.0.1"
	bad.LogRedactions = []string{"["}
	if _, err := New(bad); err == nil {
		t.Fatal("invalid RE2 accepted")
	}
	a.Config = bad
	messages, _ = contextMessages(t, a, a.collectFiles())
	if len(messages) != 0 {
		t.Fatal("invalid redactions leaked context")
	}
}

func TestLogContextOfflineDurabilityAndFIMExclusion(t *testing.T) {
	dir := t.TempDir()
	log := filepath.Join(dir, "log")
	os.WriteFile(log, []byte("password=must-not-persist\n"), 0600)
	a := &Agent{Identity: Identity{AssetID: "fixture"}, Config: Config{Server: "http://127.0.0.1", StateDir: dir, LogPaths: []string{log}, LogIncludeMessage: true}}
	findings := a.collectFiles()
	_, ids := contextMessages(t, a, findings)
	if err := a.heartbeat(map[string]any{}, findings); err != nil {
		t.Fatal(err)
	}
	for _, pending := range a.Queue {
		if strings.Contains(string(pending.Body), "must-not-persist") {
			t.Fatal("unredacted line queued")
		}
	}
	restarted, err := New(a.Config)
	if err != nil {
		t.Fatal(err)
	}
	seen := false
	for _, pending := range restarted.Queue {
		if pending.Path == "/telemetry/events" && strings.Contains(string(pending.Body), ids[0]) {
			seen = true
		}
	}
	if !seen {
		t.Fatal("offline context missing after process restart")
	}
	// The failed queue capacity check must leave both the line and its stable ID available for retry.
	a.Queue = make([]Pending, 127)
	if err = a.heartbeat(map[string]any{}, findings); err == nil {
		t.Fatal("partial raw context batch accepted")
	}
	_, retry := contextMessages(t, a, a.collectFiles())
	if len(retry) != 1 || retry[0] != ids[0] {
		t.Fatal("retry lost context")
	}
	fim := &Agent{Config: Config{StateDir: dir, FIMPaths: []string{log}, LogIncludeMessage: true}}
	fim.collectFiles()
	fim.commitCollectors()
	os.WriteFile(log, []byte("secret=fim-content\n"), 0600)
	changes := fim.collectFiles()
	messages, _ := contextMessages(t, fim, changes)
	if len(messages) != 0 {
		t.Fatal("FIM contents emitted")
	}
}
