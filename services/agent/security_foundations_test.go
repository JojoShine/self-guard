package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestAuditSixEnginesAndNoSQLRetention(t *testing.T) {
	now := time.Now().UTC()
	for _, engine := range []string{"oracle", "mysql", "postgresql", "sqlserver", "dm", "kingbase"} {
		rule := PolicyRule{ID: "audit", Config: PolicyConfig{Type: "DATABASE_ACTIVITY", Service: "audit-json", InstanceID: "instance", Engines: []string{engine}}}
		line := fmt.Sprintf(`{"eventId":"one","timestamp":%q,"service":%q,"database":"billing","schema":"app","table":"payment","columns":["card"],"user":"report","sourceIp":"192.0.2.1","operation":"GRANT","sql":"secret SQL"}`, now.Add(-time.Second).Format(time.RFC3339Nano), engine)
		rows, complete := databaseAuditRows(rule, []string{line})
		if !complete || len(rows) != 1 {
			t.Fatalf("%s: %#v", engine, rows)
		}
		raw, _ := json.Marshal(rows)
		if strings.Contains(string(raw), "secret SQL") {
			t.Fatal("SQL retained")
		}
		rule.Config.Engines = []string{"unsupported"}
		rows, _ = databaseAuditRows(rule, []string{line})
		if len(rows) != 0 {
			t.Fatal("wrong engine forwarded")
		}
	}
}
func TestConnectionInventoryBoundaries(t *testing.T) {
	root := t.TempDir()
	header := " sl local_address rem_address st\n"
	body := header + "0: 0100000A:C350 140200C0:1538 01\n1: 0100000A:C351 0100007F:0050 01\n2: 0100000A:0050 00000000:0000 0A\n"
	os.WriteFile(filepath.Join(root, "tcp"), []byte(body), 0600)
	os.WriteFile(filepath.Join(root, "tcp6"), []byte(header), 0600)
	rows, status := connectionInventory(root)
	if !status.Complete || len(rows) != 1 || rows[0].Address != "192.0.2.20" || rows[0].Port != 5432 {
		t.Fatalf("%#v %#v", rows, status)
	}
}

func TestDatabaseAuditRejectsWhitespaceAndUnsupportedEngine(t *testing.T) {
	rule := PolicyRule{Config: PolicyConfig{Type: "DATABASE_AUTH", Service: "audit-json", InstanceID: "instance"}}
	for _, row := range []string{`{"timestamp":"2026-11-02T00:00:00Z","service":"mysql","operation":"SELECT","user":" "}`, `{"timestamp":"2026-11-02T00:00:00Z","service":"mongodb","operation":"LOGIN","user":"app"}`, `{"timestamp":"2026-11-02T00:00:00Z","service":"mysql","operation":"SELECT","user":"app","columns":[" "]}`} {
		rows, complete := databaseAuditRows(rule, []string{row})
		if complete || len(rows) != 0 {
			t.Fatal("API-invalid row accepted")
		}
	}
}

func TestDatabaseReportsUseIndependentDurableQueue(t *testing.T) {
	a := &Agent{Config: Config{StateDir: t.TempDir()}}
	a.DatabaseEvents = []map[string]any{{"instanceId": "instance", "eventId": "one"}}
	if err := a.heartbeat(map[string]any{}, nil); err != nil {
		t.Fatal(err)
	}
	if len(a.Queue) != 1 || len(a.DatabaseQueue) != 1 || a.Queue[0].Path != "/agent/heartbeat" {
		t.Fatal("database audit shares host delivery queue")
	}
	var saved []Pending
	if err := read(filepath.Join(a.Config.StateDir, "database-queue.json"), &saved); err != nil || len(saved) != 1 {
		t.Fatal("audit not durable")
	}
	if err := a.heartbeat(map[string]any{}, nil); err != nil {
		t.Fatal(err)
	}
	if len(a.DatabaseQueue) != 1 {
		t.Fatal("duplicate pending audit requeued")
	}
}

func TestNativePostgresCSVAuditAndOracleVersions(t *testing.T) {
	line := `2026-11-02 00:00:00.000 UTC,app,orders,42,192.0.2.1:54321,session-one,3,SELECT,2026-11-02 00:00:00 UTC,1/1,0,LOG,00000,"AUDIT: SESSION,1,1,READ,SELECT,TABLE,public.payment,SELECT * FROM public.payment,<not logged>",,,,,,,,,application`
	rows, complete := databaseAuditRows(PolicyRule{Config: PolicyConfig{InstanceID: "instance", Path: "/audit.csv", Service: "postgresql-csv"}}, []string{line})
	if !complete || len(rows) != 1 || rows[0]["operation"] != "SELECT" || rows[0]["table"] != "payment" {
		t.Fatalf("native CSV %#v %v", rows, complete)
	}
	raw, _ := json.Marshal(rows)
	if strings.Contains(string(raw), "SELECT *") {
		t.Fatal("SQL retained")
	}
	for _, format := range []string{"oracle-traditional-json", "oracle-unified-json"} {
		line := `{"EVENT_TIMESTAMP":"2026-11-02T00:00:00Z","TIMESTAMP":"2026-11-02T00:00:00Z","DBUSERNAME":"APP","USERNAME":"APP","ACTION_NAME":"SELECT","RETURN_CODE":0,"RETURNCODE":0,"OBJECT_SCHEMA":"APP","OWNER":"APP","OBJECT_NAME":"PAYMENT","OBJ_NAME":"PAYMENT","SESSIONID":1,"ENTRYID":1,"DBID":1,"SQL_TEXT":"private SQL","USERHOST":"oracle-client.example"}`
		rows, complete := databaseAuditRows(PolicyRule{Config: PolicyConfig{InstanceID: "instance", Path: "/oracle.json", Service: format}}, []string{line})
		if !complete || len(rows) != 1 || rows[0]["operation"] != "SELECT" || rows[0]["sourceHost"] != "oracle-client.example" {
			t.Fatalf("%s %#v", format, rows)
		}
		raw, _ := json.Marshal(rows)
		if strings.Contains(string(raw), "private SQL") {
			t.Fatal("Oracle SQL retained")
		}
	}
}

func TestDatabaseRawBodyDoesNotEnterGeneralLogContext(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "audit.json")
	os.WriteFile(path, []byte(`{"eventId":"one","timestamp":"2026-11-02T00:00:00Z","service":"mysql","user":"app","operation":"SELECT","sql":"private SQL body"}`+"\n"), 0600)
	a := &Agent{Config: Config{StateDir: root, AllowedRoot: root, LogIncludeMessage: true}, LogRules: []PolicyRule{{ID: "db", Config: PolicyConfig{Type: "DATABASE_COLLECTION", Service: "audit-json", InstanceID: "instance", Path: path}}}}
	a.collectFilesAt(time.Now())
	if len(a.LogContexts) != 0 {
		t.Fatal("database SQL leaked into general telemetry context")
	}
}

func TestNativeRecordFramingAcrossPhysicalLines(t *testing.T) {
	body := "[\n {\n\"class\":\"general\",\n\"query\":\"private { SQL }\"\n },\n {\"id\":2}\n]"
	first, rest, ok := databaseRecord(body, "mysql-audit-json")
	if !ok || !strings.Contains(first, "private { SQL }") {
		t.Fatal("multiline JSON not framed")
	}
	second, _, ok := databaseRecord(rest, "mysql-audit-json")
	if !ok || second != "{\"id\":2}" {
		t.Fatal("JSON array next event lost")
	}
	first, rest, ok = databaseRecord("a,\"line1\nline2\",z\nnext\n", "postgresql-csv")
	if !ok || !strings.Contains(first, "line1\nline2") || rest != "next\n" {
		t.Fatal("quoted CSV newline split")
	}
}

func TestNativePermissionChecksAndDMIdentity(t *testing.T) {
	rule := PolicyRule{Config: PolicyConfig{InstanceID: "instance", Service: "sqlserver-audit-json"}}
	rows, complete := databaseAuditRows(rule, []string{`{"event_time":"2026-11-02T00:00:00Z","action_id":"SL","succeeded":false,"server_principal_name":"app","client_ip":"local machine"}`})
	if !complete || len(rows) != 1 || rows[0]["permissionGranted"] != false || rows[0]["sourceHost"] != "local machine" {
		t.Fatalf("SQL Server permission semantics: %#v %v", rows, complete)
	}
	if _, present := rows[0]["succeeded"]; present {
		t.Fatal("permission check misrepresented as execution result")
	}
	rule.Config.Service = "dm-audit-json"
	input := `{"EVENT_ID":"file:1","EVENT_TIMESTAMP":"2026-11-02T00:00:00Z","USERNAME":"app","DBNAME":"DAMENG","OPERATION":"SELECT","SUCC_FLAG":"Y","SQL_TEXT":"private SQL"}`
	rows, complete = databaseAuditRows(rule, []string{input})
	if !complete || len(rows) != 1 || rows[0]["eventId"] != "file:1" || rows[0]["succeeded"] != true {
		t.Fatalf("DM metadata: %#v %v", rows, complete)
	}
	rows, complete = databaseAuditRows(rule, []string{strings.Replace(input, `"EVENT_ID":"file:1",`, "", 1)})
	if complete || len(rows) != 0 {
		t.Fatal("DM event without stable source identity accepted")
	}
}

func TestNormalDatabaseCollectionDoesNotCreateGenericAlert(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "audit.json")
	os.WriteFile(path, []byte(`{"eventId":"one","timestamp":"2026-11-02T00:00:00Z","service":"mysql","user":"app","operation":"SELECT"}`+"\n"), 0600)
	a := &Agent{Config: Config{StateDir: root, AllowedRoot: root}, LogRules: []PolicyRule{{ID: "collect", Config: PolicyConfig{Type: "DATABASE_COLLECTION", Service: "audit-json", InstanceID: "instance", Path: path}}}}
	findings := a.collectFilesAt(time.Now())
	if len(findings) != 0 || len(a.DatabaseEvents) != 1 {
		t.Fatalf("normal audit raised findings: %#v", findings)
	}
}
