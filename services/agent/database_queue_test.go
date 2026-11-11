package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestDatabaseQueueEncryptedOnDisk(t *testing.T) {
	path := filepath.Join(t.TempDir(), "database-queue.json")
	want := []Pending{{Path: "/agent/database-audit", Body: json.RawMessage(`{"events":[{"sql":"private-value"}]}`)}}
	if err := writePrivate(path, want); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte("private-value")) {
		t.Fatal("SQL durable queue stored plaintext")
	}
	var got []Pending
	if err := read(path, &got); err != nil || len(got) != 1 || !bytes.Equal(got[0].Body, want[0].Body) {
		t.Fatal("encrypted queue did not recover", err)
	}
	if err := os.Remove(filepath.Join(filepath.Dir(path), "database-queue.key")); err != nil {
		t.Fatal(err)
	}
	if err := read(path, &got); err == nil {
		t.Fatal("missing queue key must fail closed")
	}
}

func TestExpiredSQLRemovedFromOfflineQueue(t *testing.T) {
	a := &Agent{Config: Config{StateDir: t.TempDir()}, DatabaseQueue: []Pending{{Path: "/agent/database-audit", Body: json.RawMessage(`{"events":[{"timestamp":"2020-01-01T00:00:00Z","execution":{"sql":"expired-private-value","protocol":"SIMPLE"},"eventId":"one"}]}`)}}}
	if err := a.expireDatabaseSQL(); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(a.DatabaseQueue[0].Body, []byte("expired-private-value")) || !bytes.Contains(a.DatabaseQueue[0].Body, []byte("one")) {
		t.Fatal("offline expiration must remove only raw SQL")
	}
	var recovered []Pending
	if err := read(filepath.Join(a.Config.StateDir, "database-queue.json"), &recovered); err != nil || len(recovered) != 1 || bytes.Contains(recovered[0].Body, []byte("expired-private-value")) {
		t.Fatal("expired raw SQL survived queue recovery", err)
	}
}
