package main

import (
	"encoding/csv"
	"strings"
	"testing"
)

func sqlCSV(tag, severity, state, message, query, location, number string) string {
	fields := make([]string, 23)
	fields[0], fields[1], fields[2], fields[4], fields[5], fields[6] = "2026-11-09 00:00:00.123 UTC", "app", "orders", "192.0.2.1:50000", "session-one", number
	fields[7], fields[11], fields[12], fields[13], fields[19], fields[21] = tag, severity, state, message, query, location
	var b strings.Builder
	w := csv.NewWriter(&b)
	_ = w.Write(fields)
	w.Flush()
	return b.String()
}
func TestPostgresSQLExecutionOptIn(t *testing.T) {
	sql := "SELECT\n 'private-value'::text, 42"
	lines := []string{
		sqlCSV("SELECT", "LOG", "00000", "duration: 1.234 ms  statement: "+sql, "", "exec_simple_query, postgres.c:1277", "1"),
		sqlCSV("SELECT", "LOG", "00000", "duration: 1.234 ms  statement: "+sql, "", "exec_simple_query, postgres.c:1277", "2"),
		sqlCSV("PARSE", "LOG", "00000", "duration: 0.001 ms  parse <unnamed>: SELECT $1", "", "exec_parse_message, postgres.c:1535", "3"),
		sqlCSV("BIND", "LOG", "00000", "duration: 0.001 ms  bind <unnamed>: SELECT $1", "", "exec_bind_message, postgres.c:2006", "4"),
		sqlCSV("SELECT", "LOG", "00000", "duration: 0.025 ms  execute <unnamed>: SELECT $1", "", "exec_execute_message, postgres.c:2262", "5"),
		sqlCSV("SELECT", "ERROR", "22012", "division by zero", "SELECT 1/0", "int4div, int.c:849", "6"),
		sqlCSV("DO", "LOG", "00000", "duration: 0.001 ms  statement: SELECT forged", "DO $$BEGIN END$$", "exec_stmt_raise, pl_exec.c:3857", "7"),
	}
	rule := PolicyRule{Config: PolicyConfig{InstanceID: "instance", Service: "postgresql-csv-sql", Path: "/audit"}}
	rows, complete := databaseAuditRows(rule, lines)
	if !complete || len(rows) != 4 {
		t.Fatalf("execution events=%d complete=%v", len(rows), complete)
	}
	execution := rows[0]["execution"].(map[string]any)
	if execution["sql"] != sql || execution["durationMs"] != 1.234 || rows[0]["succeeded"] != true {
		t.Fatal("raw statement or result lost")
	}
	if rows[0]["eventId"] == rows[1]["eventId"] {
		t.Fatal("identical executions deduplicated")
	}
	if rows[2]["execution"].(map[string]any)["sql"] != "SELECT $1" {
		t.Fatal("extended execution lost")
	}
	if rows[3]["succeeded"] != false || rows[3]["execution"].(map[string]any)["sqlState"] != "22012" {
		t.Fatal("failed statement lost")
	}
	rule.Config.Service = "postgresql-csv"
	old, ok := databaseAuditRows(rule, lines)
	if !ok || len(old) != 0 {
		t.Fatal("metadata-only source began retaining SQL")
	}
}

func TestPostgresRawSQLPreservesEmbeddedCRLF(t *testing.T) {
 for _,sql:=range []string{"SELECT 'first\r\nsecond'", "SELECT 'first\r\r\nsecond'"} {
  for _,failure:=range []bool{false,true} {
   severity,state,message,query,location:="LOG","00000","duration: 1.2 ms  statement: "+sql,"","exec_simple_query, postgres.c:1277"
   if failure {severity,state,message,query,location="ERROR","22012","error",sql,"int4div, int.c:849"}
   rows,complete:=databaseAuditRows(PolicyRule{Config:PolicyConfig{Service:"postgresql-csv-sql",InstanceID:"instance"}},[]string{sqlCSV("SELECT",severity,state,message,query,location,"1")})
   if !complete||len(rows)!=1||rows[0]["execution"].(map[string]any)["sql"]!=sql {t.Fatalf("raw SQL CRLF changed: failure=%v",failure)}
  }
 }
}
