//go:build linux

package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestStatementCursorDoesNotPersistIncompleteRawText(t *testing.T) {
	for _, format := range []string{"audit-sql-json", "redis-command-json"} {
		t.Run(format, func(t *testing.T) {
			root := t.TempDir()
			source := filepath.Join(root, "commands.json")
			raw, _ := json.Marshal(map[string]any{"eventId": "command1", "timestamp": "2026-11-11T00:00:00Z", "service": "redis", "user": "[unknown]", "operation": "OTHER", "execution": map[string]any{"sql": "private-fragment", "protocol": "COMMAND"}})
			if err := os.WriteFile(source, raw[:len(raw)-2], 0600); err != nil {
				t.Fatal(err)
			}
			a := &Agent{Config: Config{StateDir: root, AllowedRoot: root, LogPaths: []string{source}}, LogRules: []PolicyRule{{Config: PolicyConfig{Type: "DATABASE_COLLECTION", Path: source, Service: format, InstanceID: "instance"}}}}
			a.collectFilesAt(time.Now())
			state := a.CollectorState["log:"+source]
			if state.Partial != "" || state.Offset != 0 {
				t.Fatal("raw partial persisted or advanced")
			}
			if err := a.commitCollectors(); err != nil {
				t.Fatal(err)
			}
			body, err := os.ReadFile(filepath.Join(root, "collectors.json"))
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(body), "private-fragment") {
				t.Fatal("cursor leaked raw command")
			}
			if err := os.WriteFile(source, append(raw, '\n'), 0600); err != nil {
				t.Fatal(err)
			}
			a.collectFilesAt(time.Now())
			if len(a.DatabaseEvents) != 1 {
				t.Fatal("complete raw event did not resume")
			}
		})
	}
}

func TestSQLCursorDoesNotPersistIncompleteRawSQL(t *testing.T) {
	root := t.TempDir()
	source := filepath.Join(root, "sql.csv")
	line := sqlCSV("SELECT", "LOG", "00000", "duration: 1.2 ms  statement: SELECT 'private-fragment'", "", "exec_simple_query, postgres.c:1277", "1")
	if err := os.WriteFile(source, []byte(line[:len(line)-2]), 0600); err != nil {
		t.Fatal(err)
	}
	a := &Agent{Config: Config{StateDir: root, AllowedRoot: root, LogPaths: []string{source}}, LogRules: []PolicyRule{{Config: PolicyConfig{Type: "DATABASE_COLLECTION", Path: source, Service: "postgresql-csv-sql", InstanceID: "instance"}}}}
	a.collectFilesAt(time.Now())
	state := a.CollectorState["log:"+source]
	if state.Partial != "" || state.Offset != 0 {
		t.Fatal("raw partial advanced or persisted", state.Offset)
	}
	if err := a.commitCollectors(); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(filepath.Join(root, "collectors.json"))
	if strings.Contains(string(b), "private-fragment") {
		t.Fatal("cursor leaked SQL")
	}
	if err := os.WriteFile(source, []byte(line), 0600); err != nil {
		t.Fatal(err)
	}
	a.collectFilesAt(time.Now())
	if len(a.DatabaseEvents) != 1 {
		t.Fatal("completed record did not resume", len(a.DatabaseEvents))
	}
}
