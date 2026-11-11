package main

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestDatabaseStatementSourcesAreExplicit(t *testing.T) {
	for _, engine := range []string{"postgresql", "mysql", "oracle", "dm", "kingbase", "vastbase", "redis"} {
		protocol, operation := "AUDIT", "SELECT"
		if engine == "redis" {
			protocol = "COMMAND"
			operation = "OTHER"
		}
		raw, _ := json.Marshal(map[string]any{"eventId": "statement-1", "timestamp": "2026-11-11T00:00:00Z", "service": engine, "user": "[unknown]", "userKnown": false, "operation": operation, "execution": map[string]any{"sql": "protected-statement", "protocol": protocol}})
		rule := PolicyRule{Config: PolicyConfig{Service: "audit-sql-json", InstanceID: "instance", Path: "/audit", Engines: []string{engine}}}
		rows, complete := databaseAuditRows(rule, []string{string(raw)})
		if !complete || len(rows) != 1 {
			t.Fatalf("explicit source did not accept %s", engine)
		}
		execution, ok := rows[0]["execution"].(map[string]any)
		if !ok || execution["sql"] != "protected-statement" || execution["sqlState"] != nil || rows[0]["userKnown"] != false {
			t.Fatalf("raw statement or unknown metadata lost for %s", engine)
		}
		rule.Config.Service = "audit-json"
		rows, complete = databaseAuditRows(rule, []string{string(raw)})
		if !complete || len(rows) != 1 || rows[0]["execution"] != nil {
			t.Fatalf("legacy metadata source changed for %s", engine)
		}
	}
}

func TestNativeAuditStatementOptIn(t *testing.T) {
	for _, sample := range []struct{ format, raw string }{
		{"mysql-audit-sql-json", `{"timestamp":"2026-11-11T00:00:00Z","id":1,"class":"general","account":{"user":"app"},"general_data":{"sql_command":"select","status":0,"query":"protected-statement"}}`},
		{"oracle-traditional-sql-json", `{"TIMESTAMP":"2026-11-11T00:00:00Z","USERNAME":"app","ACTION_NAME":"SELECT","RETURNCODE":0,"EVENT_ID":"event1","SQL_TEXT":"protected-statement"}`},
		{"oracle-unified-sql-json", `{"EVENT_TIMESTAMP":"2026-11-11T00:00:00Z","DBUSERNAME":"app","ACTION_NAME":"SELECT","RETURN_CODE":0,"EVENT_ID":"event1","SQL_TEXT":"protected-statement"}`},
		{"dm-audit-sql-json", `{"EVENT_TIMESTAMP":"2026-11-11T00:00:00Z","USERNAME":"app","OPERATION":"SELECT","SUCC_FLAG":"Y","EVENT_ID":"event1","SQL_TEXT":"protected-statement"}`},
	} {
		if !databaseFormat(sample.format) {
			t.Fatalf("statement format unavailable: %s", sample.format)
		}
		rows, complete := databaseAuditRows(PolicyRule{Config: PolicyConfig{Service: sample.format, InstanceID: "instance", Path: "/audit"}}, []string{sample.raw})
		if !complete || len(rows) != 1 {
			t.Fatalf("native statement was not read: %s", sample.format)
		}
		execution, ok := rows[0]["execution"].(map[string]any)
		if !ok || execution["sql"] != "protected-statement" || execution["protocol"] != "AUDIT" || execution["sqlState"] != nil {
			t.Fatalf("native raw metadata incorrect: %s", sample.format)
		}
	}
}

func TestStatementSourceRejectsOversizedOrUnknownExecution(t *testing.T) {
	for _, execution := range []map[string]any{{"sql": strings.Repeat("x", 32769), "protocol": "AUDIT"}, {"sql": "x", "protocol": "invented"}, {"sql": "x", "protocol": "AUDIT", "password": "must-not-be-retained"}} {
		raw, _ := json.Marshal(map[string]any{"eventId": "x", "timestamp": "2026-11-11T00:00:00Z", "service": "mysql", "user": "app", "operation": "SELECT", "execution": execution})
		rows, complete := databaseAuditRows(PolicyRule{Config: PolicyConfig{Service: "audit-sql-json", InstanceID: "instance", Path: "/audit"}}, []string{string(raw)})
		if complete || len(rows) > 0 {
			t.Fatal("invalid raw evidence was retained")
		}
	}
}
