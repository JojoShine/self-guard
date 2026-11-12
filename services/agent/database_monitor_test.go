package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func databaseMonitorFixture(t *testing.T) *databaseMonitor {
	t.Helper()
	dir := t.TempDir()
	source := filepath.Join(dir, "logs")
	if err := os.Mkdir(source, 0700); err != nil {
		t.Fatal(err)
	}
	return &databaseMonitor{config: databaseMonitorConfig{Schema: "selfguard-database-monitor-v1", InstanceID: "10000000-0000-4000-8000-000000000001", AssetID: "10000000-0000-4000-8000-000000000002", SourcePath: source, Engine: "postgresql", Format: "audit-sql-json"}, agent: &Agent{Config: Config{StateDir: dir}}, state: databaseMonitorState{Files: map[string]databaseMonitorCursor{}}}
}
func databaseMonitorLine(id string) []byte {
	return []byte(fmt.Sprintf(`{"eventId":%q,"timestamp":%q,"service":"postgresql","user":"app","operation":"SELECT","execution":{"sql":"private-select","protocol":"AUDIT"}}`+"\n", id, time.Now().UTC().Format(time.RFC3339Nano)))
}
func TestDatabaseMonitorAuthorizationPrecedesSourceRead(t *testing.T) {
	m := databaseMonitorFixture(t)
	os.WriteFile(filepath.Join(m.config.SourcePath, "a.json"), databaseMonitorLine("one"), 0600)
	authorized := false
	posts := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/agent/database-monitor" {
			json.NewEncoder(w).Encode(map[string]any{"enabled": authorized, "instanceId": m.config.InstanceID, "assetId": m.config.AssetID, "sourcePath": m.config.SourcePath, "engine": m.config.Engine, "format": m.config.Format})
			return
		}
		if r.URL.Path == "/api/agent/database-monitor/status" {
			return
		}
		posts++
		t.Errorf("unexpected endpoint %s", r.URL.Path)
	}))
	defer server.Close()
	m.agent.Config.Server = server.URL
	m.agent.Client = server.Client()
	if err := m.cycle(context.Background()); err == nil {
		t.Fatal("disabled authorization accepted")
	}
	if len(m.state.Files) != 0 || len(m.agent.DatabaseQueue) != 0 || posts != 0 {
		t.Fatal("source read without authorization")
	}
	authorized = true
	if err := m.cycle(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(m.agent.DatabaseQueue) != 1 {
		t.Fatal("authorized source not queued")
	}
}
func TestDatabaseMonitorDirectoryRotationAndEncryptedQueue(t *testing.T) {
	m := databaseMonitorFixture(t)
	first := filepath.Join(m.config.SourcePath, "a.json")
	os.WriteFile(first, databaseMonitorLine("one"), 0600)
	if err := m.scan(); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(m.agent.Config.StateDir, "database-queue.json"))
	if err != nil || bytes.Contains(raw, []byte("private-select")) {
		t.Fatal("plaintext or missing durable queue", err)
	}
	os.Rename(first, filepath.Join(m.config.SourcePath, "old.json"))
	os.WriteFile(first, databaseMonitorLine("two"), 0600)
	if err := m.scan(); err != nil {
		t.Fatal(err)
	}
	if len(m.agent.DatabaseQueue) != 2 {
		t.Fatal("rotation replayed or lost records", len(m.agent.DatabaseQueue))
	}
	var body struct {
		Events []map[string]any `json:"events"`
	}
	json.Unmarshal(m.agent.DatabaseQueue[0].Body, &body)
	if body.Events[0]["sourcePath"] != m.config.SourcePath || body.Events[0]["sourceSha256"] == "" {
		t.Fatal("source binding lost")
	}
	os.Remove(filepath.Join(m.config.SourcePath, "old.json"))
	m.scan()
	if m.state.RotationGaps != 0 {
		t.Fatal("fully consumed rotation removal falsely reported loss")
	}
}
func TestDatabaseMonitorFailedQueueAndBackpressureRetainCursor(t *testing.T) {
	m := databaseMonitorFixture(t)
	os.WriteFile(filepath.Join(m.config.SourcePath, "a.json"), databaseMonitorLine("one"), 0600)
	os.Mkdir(filepath.Join(m.agent.Config.StateDir, "database-queue.json.tmp"), 0700)
	if m.scan() == nil || len(m.state.Files) != 0 {
		t.Fatal("cursor advanced before durable queue")
	}
	os.Remove(filepath.Join(m.agent.Config.StateDir, "database-queue.json.tmp"))
	for i := 0; i < 48; i++ {
		m.agent.DatabaseQueue = append(m.agent.DatabaseQueue, Pending{Path: "/agent/database-audit", Body: json.RawMessage(`{"events":[]}`)})
	}
	if m.scan() == nil || len(m.state.Files) != 0 || m.health.DetailCode != "BACKPRESSURE" {
		t.Fatal("backpressure silently advanced cursor")
	}
}
func TestDatabaseMonitorExpiryAndBoundedSource(t *testing.T) {
	m := databaseMonitorFixture(t)
	m.agent.DatabaseQueue = []Pending{{Path: "/agent/database-audit", Body: json.RawMessage(`{"events":[{"timestamp":"2020-01-01T00:00:00Z","execution":{"sql":"private-old"}}]}`)}}
	if err := m.agent.expireDatabaseSQL(); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(m.agent.DatabaseQueue[0].Body, []byte("private-old")) {
		t.Fatal("expired SQL retained")
	}
	m.agent.DatabaseQueue = nil
	for i := 0; i < databaseMonitorMaxFiles+1; i++ {
		os.WriteFile(filepath.Join(m.config.SourcePath, fmt.Sprintf("%02d.json", i)), nil, 0600)
	}
	if m.scan() == nil || m.health.Status != "ERROR" {
		t.Fatal("file budget silently skipped")
	}
}

func TestDatabaseMonitorMultilineCSVAndPartialRecord(t *testing.T) {
	m := databaseMonitorFixture(t)
	m.config.Format = "postgresql-csv-sql"
	line := sqlCSV("SELECT", "LOG", "00000", "duration: 1 ms  statement: SELECT\n 'private-select'", "", "exec_simple_query, postgres.c:1277", "1")
	path := filepath.Join(m.config.SourcePath, "a.csv")
	os.WriteFile(path, []byte(line[:len(line)/2]), 0600)
	if err := m.scan(); err != nil {
		t.Fatal(err)
	}
	if len(m.agent.DatabaseQueue) != 0 {
		t.Fatal("partial CSV accepted")
	}
	for _, cursor := range m.state.Files {
		if cursor.Offset != 0 {
			t.Fatal("partial cursor advanced")
		}
	}
	os.WriteFile(path, []byte(line), 0600)
	if err := m.scan(); err != nil {
		t.Fatal(err)
	}
	if len(m.agent.DatabaseQueue) != 1 {
		t.Fatal("multiline CSV lost")
	}
	var body struct {
		Events []map[string]any `json:"events"`
	}
	json.Unmarshal(m.agent.DatabaseQueue[0].Body, &body)
	if len(body.Events) != 1 {
		t.Fatal("multiline CSV split", len(body.Events))
	}
}
func TestDatabaseMonitorAuthorizationBindingAndOfflineExpiry(t *testing.T) {
	m := databaseMonitorFixture(t)
	os.WriteFile(filepath.Join(m.config.SourcePath, "a.json"), databaseMonitorLine("one"), 0600)
	permission := map[string]any{"enabled": true, "instanceId": m.config.InstanceID, "assetId": m.config.AssetID, "sourcePath": m.config.SourcePath, "engine": m.config.Engine, "format": m.config.Format}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { json.NewEncoder(w).Encode(permission) }))
	m.agent.Config.Server = server.URL
	m.agent.Client = server.Client()
	for _, key := range []string{"instanceId", "assetId", "sourcePath", "engine", "format"} {
		saved := permission[key]
		permission[key] = "different"
		if m.cycle(context.Background()) == nil || len(m.state.Files) != 0 {
			t.Fatal("binding drift read source", key)
		}
		permission[key] = saved
	}
	server.Close()
	m.agent.DatabaseQueue = []Pending{{Path: "/agent/database-audit", Body: json.RawMessage(`{"events":[{"timestamp":"2020-01-01T00:00:00Z","execution":{"sql":"private-old"}}]}`)}}
	if m.cycle(context.Background()) == nil || len(m.state.Files) != 0 {
		t.Fatal("network failure read source")
	}
	if bytes.Contains(m.agent.DatabaseQueue[0].Body, []byte("private-old")) {
		t.Fatal("offline queue expiry not run")
	}
}
func TestDatabaseMonitorAcknowledgedEventsAndNoUnrelatedEndpoints(t *testing.T) {
	m := databaseMonitorFixture(t)
	os.WriteFile(filepath.Join(m.config.SourcePath, "a.json"), databaseMonitorLine("one"), 0600)
	if err := m.scan(); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/agent/database-audit" {
			t.Errorf("unexpected endpoint %s", r.URL.Path)
		}
		json.NewEncoder(w).Encode(map[string]int{"accepted": 1, "duplicates": 0})
	}))
	defer server.Close()
	m.agent.Config.Server = server.URL
	m.agent.Client = server.Client()
	if err := m.deliver(context.Background()); err != nil {
		t.Fatal(err)
	}
	if m.state.AcceptedEvents != 1 || m.state.LastEventAt == "" || len(m.agent.DatabaseQueue) != 0 {
		t.Fatal("server confirmation not tracked", m.state)
	}
}
func TestDatabaseMonitorRejectsSymlinksAndExpiresBackfillBeforeQueue(t *testing.T) {
	m := databaseMonitorFixture(t)
	outside := filepath.Join(t.TempDir(), "outside.json")
	os.WriteFile(outside, databaseMonitorLine("outside"), 0600)
	os.Symlink(outside, filepath.Join(m.config.SourcePath, "link.json"))
	if m.scan() == nil || len(m.agent.DatabaseQueue) != 0 {
		t.Fatal("symlink source read")
	}
	os.Remove(filepath.Join(m.config.SourcePath, "link.json"))
	raw := databaseMonitorLine("old")
	var row map[string]any
	json.Unmarshal(raw, &row)
	row["timestamp"] = "2020-01-01T00:00:00Z"
	raw, _ = json.Marshal(row)
	os.WriteFile(filepath.Join(m.config.SourcePath, "old.json"), append(raw, '\n'), 0600)
	if err := m.scan(); err != nil {
		t.Fatal(err)
	}
	if len(m.agent.DatabaseQueue) != 1 || bytes.Contains(m.agent.DatabaseQueue[0].Body, []byte("private-select")) {
		t.Fatal("expired backfill SQL persisted")
	}
}

func TestDatabaseMonitorByteAndRecordBudgetsDoNotSkipCursor(t *testing.T) {
	m := databaseMonitorFixture(t)
	var body []byte
	for i := 0; i < 101; i++ {
		body = append(body, databaseMonitorLine(fmt.Sprint(i))...)
	}
	os.WriteFile(filepath.Join(m.config.SourcePath, "a.json"), body, 0600)
	if err := m.scan(); err != nil {
		t.Fatal(err)
	}
	if m.health.DetailCode != "BACKPRESSURE" {
		t.Fatal("record budget hidden")
	}
	if err := m.scan(); err != nil {
		t.Fatal(err)
	}
	total := 0
	for _, batch := range m.agent.DatabaseQueue {
		var body struct {
			Events []json.RawMessage `json:"events"`
		}
		json.Unmarshal(batch.Body, &body)
		total += len(body.Events)
	}
	if total != 101 {
		t.Fatal("record limit skipped records", total)
	}
}
func TestDatabaseMonitorPrivateConfigAndLock(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	os.WriteFile(path, []byte(`{}`), 0644)
	if runDatabaseMonitor(path, true) == nil {
		t.Fatal("nonprivate config accepted")
	}
	lock := filepath.Join(dir, "lock")
	unlock, err := lockTrafficMonitor(lock)
	if err != nil {
		t.Fatal(err)
	}
	defer unlock()
	if second, err := lockTrafficMonitor(lock); err == nil {
		second()
		t.Fatal("two processes may alter expiry/cursors")
	}
}

func TestDatabaseMonitorExpireOnlyDoesNotReadSourceOrUseNetwork(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("isolated Linux root fixture required")
	}
	m := databaseMonitorFixture(t)
	m.config.InstanceID = fmt.Sprintf("10000000-0000-4000-8000-%012x", uint64(time.Now().UnixNano())&0xffffffffffff)
	m.config.StateDir = "/var/lib/selfguard-database/" + m.config.InstanceID
	m.config.SourcePath = "/nonexistent-authorized-database-source"
	m.config.Server = "https://must-not-contact.invalid"
	m.config.Token = "private-test-token"
	if err := os.MkdirAll(m.config.StateDir, 0700); err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(m.config.StateDir)
	path := filepath.Join(t.TempDir(), "config.json")
	if err := writePrivate(path, m.config); err != nil {
		t.Fatal(err)
	}
	queuePath := filepath.Join(m.config.StateDir, "database-queue.json")
	queue := []Pending{{Path: "/agent/database-audit", Body: json.RawMessage(`{"events":[{"timestamp":"2020-01-01T00:00:00Z","execution":{"sql":"private-expired"}}]}`)}}
	if err := writePrivate(queuePath, queue); err != nil {
		t.Fatal(err)
	}
	unlock, err := lockTrafficMonitor(filepath.Join(m.config.StateDir, "monitor.lock"))
	if err != nil {
		t.Fatal(err)
	}
	if err := runDatabaseMonitor(path, true); err != nil {
		unlock()
		t.Fatal(err)
	}
	if err := read(queuePath, &queue); err != nil {
		unlock()
		t.Fatal(err)
	}
	if !bytes.Contains(queue[0].Body, []byte("private-expired")) {
		unlock()
		t.Fatal("expire-only wrote while lock held")
	}
	unlock()
	if err := runDatabaseMonitor(path, true); err != nil {
		t.Fatal(err)
	}
	if err := read(queuePath, &queue); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(queue[0].Body, []byte("private-expired")) {
		t.Fatal("expire-only did not remove expired SQL")
	}
}

func TestDatabaseMonitorHourlyRetention250FilesBatchesWithoutReplay(t *testing.T) {
	m := databaseMonitorFixture(t)
	m.config.Format = "postgresql-csv-sql"
	for i := 0; i < 250; i++ {
		line := sqlCSV("SELECT", "LOG", "00000", "duration: 1 ms  statement: SELECT 1", "", "exec_simple_query, postgres.c:1277", fmt.Sprint(i))
		if err := os.WriteFile(filepath.Join(m.config.SourcePath, fmt.Sprintf("%03d.csv", i)), []byte(line), 0600); err != nil {
			t.Fatal(err)
		}
	}
	seen := map[string]bool{}
	drain := func() {
		count := 0
		for _, batch := range m.agent.DatabaseQueue {
			var body struct {
				Events []struct {
					ID string `json:"eventId"`
				} `json:"events"`
			}
			if err := json.Unmarshal(batch.Body, &body); err != nil {
				t.Fatal(err)
			}
			for _, row := range body.Events {
				if seen[row.ID] {
					t.Fatal("retained file replayed", row.ID)
				}
				seen[row.ID] = true
				count++
			}
		}
		if count > 100 {
			t.Fatal("record budget exceeded", count)
		}
		m.agent.DatabaseQueue = nil
		if err := writePrivate(filepath.Join(m.agent.Config.StateDir, "database-queue.json"), m.agent.DatabaseQueue); err != nil {
			t.Fatal(err)
		}
	}
	for pass := 0; pass < 12 && len(seen) < 250; pass++ {
		if err := m.scan(); err != nil {
			t.Fatalf("normal hourly retention blocks capture: %v", err)
		}
		drain()
	}
	if len(seen) != 250 || len(m.state.Files) != 250 {
		t.Fatal("retention cursor/record loss", len(seen), len(m.state.Files))
	}
	if err := m.scan(); err != nil {
		t.Fatal(err)
	}
	drain()
	os.Remove(filepath.Join(m.config.SourcePath, "000.csv"))
	line := sqlCSV("SELECT", "LOG", "00000", "duration: 1 ms  statement: SELECT 2", "", "exec_simple_query, postgres.c:1277", "250")
	os.WriteFile(filepath.Join(m.config.SourcePath, "250.csv"), []byte(line), 0600)
	if err := m.scan(); err != nil {
		t.Fatal(err)
	}
	drain()
	if len(seen) != 251 || m.state.RotationGaps != 0 || len(m.state.Files) != 250 {
		t.Fatal("consumed retention cleanup blocked new file", len(seen), m.state.RotationGaps, len(m.state.Files))
	}
	partial := filepath.Join(m.config.SourcePath, "partial.csv")
	os.WriteFile(partial, []byte(line[:len(line)/2]), 0600)
	if err := m.scan(); err != nil {
		t.Fatal(err)
	}
	os.Remove(partial)
	if err := m.scan(); err != nil {
		t.Fatal(err)
	}
	if m.state.RotationGaps != 1 {
		t.Fatal("unread deleted file gap hidden", m.state.RotationGaps)
	}
}

func TestDatabaseMonitorRetentionMetadataSignalsUnseenCapacityLoss(t *testing.T) {
	m := databaseMonitorFixture(t)
	marker := filepath.Join(m.agent.Config.StateDir, "source-retention.json")
	if err := writePrivate(marker, map[string]any{"capacityPrunedFiles": 3, "budgetExceeded": false}); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(m.config.SourcePath, "new.json"), databaseMonitorLine("new"), 0600)
	if err := m.scan(); err != nil {
		t.Fatal(err)
	}
	if m.state.RotationGaps != 3 || len(m.agent.DatabaseQueue) != 1 {
		t.Fatal("unseen capacity loss missing or new reads blocked", m.state.RotationGaps)
	}
	if err := m.scan(); err != nil {
		t.Fatal(err)
	}
	if m.state.RotationGaps != 3 {
		t.Fatal("retention loss counted repeatedly")
	}
	writePrivate(marker, map[string]any{"capacityPrunedFiles": 5, "budgetExceeded": true})
	if err := m.scan(); err != nil {
		t.Fatal(err)
	}
	if m.state.RotationGaps != 5 || m.health.Status != "ERROR" || m.health.DetailCode != "DISK_ERROR" {
		t.Fatal("capacity overflow hidden", m.health, m.state.RotationGaps)
	}
	for len(m.agent.DatabaseQueue) < 48 {
		m.agent.DatabaseQueue = append(m.agent.DatabaseQueue, Pending{Path: "/agent/database-audit", Body: json.RawMessage(`{"events":[]}`)})
	}
	if m.scan() == nil || m.health.DetailCode != "DISK_ERROR" {
		t.Fatal("backpressure hid capacity overflow")
	}

}

func TestDatabaseMonitorTracksUnreadFilesBeyondCurrentQueueBudget(t *testing.T) {
	m := databaseMonitorFixture(t)
	for i := 0; i < 70; i++ {
		os.WriteFile(filepath.Join(m.config.SourcePath, fmt.Sprintf("%03d.json", i)), databaseMonitorLine(fmt.Sprint(i)), 0600)
	}
	if err := m.scan(); err != nil {
		t.Fatal(err)
	}
	if len(m.state.Files) != 70 || len(m.agent.DatabaseQueue) != 48 {
		t.Fatal("unread census not preserved", len(m.state.Files), len(m.agent.DatabaseQueue))
	}
	os.Remove(filepath.Join(m.config.SourcePath, "069.json"))
	m.agent.DatabaseQueue = nil
	if err := m.scan(); err != nil {
		t.Fatal(err)
	}
	if m.state.RotationGaps != 1 || len(m.state.Files) != 69 {
		t.Fatal("budget-deferred deleted file loss hidden", m.state.RotationGaps, len(m.state.Files))
	}
}
func TestDatabaseMonitorRetentionMetadataMustBePrivateAndBounded(t *testing.T) {
	m := databaseMonitorFixture(t)
	marker := filepath.Join(m.agent.Config.StateDir, "source-retention.json")
	os.WriteFile(marker, []byte(`{"capacityPrunedFiles":1,"budgetExceeded":false}`), 0644)
	if m.scan() == nil || m.health.DetailCode != "DISK_ERROR" {
		t.Fatal("untrusted retention marker accepted")
	}
	os.Remove(marker)
	for i := 0; i < databaseMonitorMaxEntries+1; i++ {
		os.WriteFile(filepath.Join(m.config.SourcePath, fmt.Sprintf("%04d.txt", i)), nil, 0600)
	}
	if m.scan() == nil || m.health.Status != "ERROR" {
		t.Fatal("directory entry budget hidden")
	}
}

func TestDatabaseMonitorRetentionStateOutsidePostgresOwnedSource(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("isolated Linux root fixture required")
	}
	m := databaseMonitorFixture(t)
	parent := filepath.Join(m.agent.Config.StateDir, "postgres-owned")
	source := filepath.Join(parent, "logs")
	if err := os.MkdirAll(source, 0750); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(parent, 999, 999); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(source, 999, 999); err != nil {
		t.Fatal(err)
	}
	m.config.SourcePath = source
	if err := os.WriteFile(filepath.Join(source, "a.json"), databaseMonitorLine("postgres-owned"), 0600); err != nil {
		t.Fatal(err)
	}
	legacy := filepath.Join(source, ".selfguard-retention.status")
	if err := writePrivate(legacy, map[string]any{"capacityPrunedFiles": 99, "budgetExceeded": true}); err != nil {
		t.Fatal(err)
	}
	if executorTrustedConfig(legacy) == nil {
		t.Fatal("root-owned parent protection unexpectedly weakened")
	}
	stateMarker := filepath.Join(m.agent.Config.StateDir, "source-retention.json")
	if err := writePrivate(stateMarker, map[string]any{"capacityPrunedFiles": 2, "budgetExceeded": false}); err != nil {
		t.Fatal(err)
	}
	if err := m.scan(); err != nil {
		t.Fatalf("postgres-owned source blocked trusted state metadata: %v", err)
	}
	if len(m.agent.DatabaseQueue) != 1 || m.state.CapacityPrunedFiles != 2 || m.state.RotationGaps != 2 || m.health.DetailCode == "DISK_ERROR" {
		t.Fatal("trusted state marker not used independently of source ownership", m.health, m.state.RotationGaps)
	}
}
