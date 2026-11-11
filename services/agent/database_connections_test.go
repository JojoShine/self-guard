package main

import (
	"encoding/csv"
	"encoding/json"
	"strings"
	"testing"
)

func TestPostgresNativeConnectionLifecycle(t *testing.T) {
	for _, format := range []string{"postgresql-csv", "postgresql-audit-json"} {
		for _, event := range []struct {
			message, state, operation string
			success                   *bool
		}{
			{"connection authorized: user=app database=orders application_name=client", "00000", "LOGIN", boolPointer(true)},
			{"password authentication failed for user \"app\"", "28P01", "LOGIN", boolPointer(false)},
			{"disconnection: session time: 0:00:01.123 user=app database=orders host=192.0.2.1 port=50000", "00000", "LOGOUT", nil},
		} {
			var line string
			if format == "postgresql-csv" {
				fields := make([]string, 23)
				fields[0], fields[1], fields[2], fields[4], fields[5], fields[6], fields[12], fields[13], fields[22] = "2026-11-09 00:00:00.123 UTC", "app", "orders", "192.0.2.1:50000", "session-one", "3", event.state, event.message, "client"
				fields[7] = "authentication"
				if event.operation == "LOGOUT" {
					fields[7] = "idle"
				}
				var out strings.Builder
				writer := csv.NewWriter(&out)
				_ = writer.Write(fields)
				writer.Flush()
				line = strings.TrimSpace(out.String())
			} else {
				raw, _ := json.Marshal(map[string]any{"timestamp": "2026-11-09T00:00:00.123Z", "user": "app", "dbname": "orders", "remote_host": "192.0.2.1", "session_id": "session-one", "line_num": 3, "state_code": event.state, "message": event.message, "application_name": "client", "command_tag": map[bool]string{true: "idle", false: "authentication"}[event.operation == "LOGOUT"]})
				line = string(raw)
			}
			rows, complete := databaseAuditRows(PolicyRule{Config: PolicyConfig{InstanceID: "instance", Service: format, Path: "/audit"}}, []string{line})
			if !complete || len(rows) != 1 || rows[0]["operation"] != event.operation || rows[0]["sourceIp"] != "192.0.2.1" {
				t.Fatalf("%s %s: %#v complete=%v", format, event.operation, rows, complete)
			}
			if event.success == nil {
				if _, ok := rows[0]["succeeded"]; ok {
					t.Fatal("disconnect must not invent a graceful outcome")
				}
			} else if rows[0]["succeeded"] != *event.success {
				t.Fatal("connection outcome missing", rows)
			}
		}
	}
}

func boolPointer(v bool) *bool { return &v }

func TestPostgresApplicationErrorIsNotAuthentication(t *testing.T) {
	value, ok, ordinary := databaseNative(`{"timestamp":"2026-11-09T00:00:00Z","user":"app","dbname":"orders","command_tag":"DO","state_code":"28P01","message":"application error"}`, "postgresql-audit-json")
	if !ok || !ordinary || value != nil {
		t.Fatal("application SQLSTATE must not become a failed login", value)
	}
}

func TestPostgresStderrAuthenticationMethodsAndDisconnectBoundaries(t *testing.T) {
	prefix := "SGDB1|1794182400.123|42|69100000.2a|192.0.2.1(50000)|"
	rule := PolicyRule{Config: PolicyConfig{Service: "postgresql-stderr", InstanceID: "instance"}}
	for _, message := range []string{
		`Peer authentication failed for user "app"`,
		`certificate authentication failed for user "app"`,
		`no pg_hba.conf entry for host "192.0.2.1", user "app", database "orders", no encryption`,
		`pg_hba.conf rejects connection for host "192.0.2.1", user "app", database "orders", SSL encryption`,
	} {
		rows, complete := databaseAuditRows(rule, []string{prefix + "28000|authentication|FATAL:  " + message})
		if !complete || len(rows) != 1 || rows[0]["succeeded"] != false || rows[0]["user"] != "app" {
			t.Fatal("authentication failure lost", message, rows)
		}
	}
	for _, tag := range []string{"idle in transaction", "idle in transaction (aborted)"} {
		rows, complete := databaseAuditRows(rule, []string{prefix + "00000|" + tag + "|LOG:  disconnection: session time: 0:00:01.123 user=app database=orders host=192.0.2.1 port=50000"})
		if !complete || len(rows) != 1 || rows[0]["operation"] != "LOGOUT" {
			t.Fatal("transaction disconnect lost", rows)
		}
	}
	for _, line := range []string{
		strings.Replace(prefix, "192.0.2.1(50000)", "", 1) + "00000|authentication|LOG:  connection authorized: user=app database=orders",
		prefix + "00000|SELECT|LOG:  disconnection: session time: 0:00:01.123 user=app database=orders host=192.0.2.1 port=50000",
	} {
		rows, complete := databaseAuditRows(rule, []string{line})
		if complete || len(rows) != 0 {
			t.Fatal("unsupported evidence silently accepted", rows)
		}
	}
}

func TestPostgresStderrUsesExplicitClockSessionAndEndpoint(t *testing.T) {
	prefix := "SGDB1|1794182400.123|42|69100000.2a|192.0.2.1(50000)|"
	lines := []string{
		prefix + "00000|authentication|LOG:  connection authorized: user=app database=orders application_name=private-value SSL enabled (protocol=TLSv1.3, cipher=secret, bits=256)",
		prefix + "28P01|authentication|FATAL:  password authentication failed for user \"app\"",
		prefix + "00000|idle|LOG:  disconnection: session time: 0:00:01.123 user=app database=orders host=192.0.2.1 port=50000",
		prefix + "00000|SELECT|STATEMENT:  SELECT 'private SQL and password'",
		prefix + "00000|authentication|LOG:  connection received: host=192.0.2.1 port=50000",
		prefix + "00000|DO|LOG:  connection authorized: user=forged database=orders",
		"SGDB1|1794182400.123|7|||00000||LOG:  checkpoint complete",
	}
	rows, complete := databaseAuditRows(PolicyRule{Config: PolicyConfig{InstanceID: "instance", Service: "postgresql-stderr", Path: "/audit"}}, lines)
	if !complete || len(rows) != 3 {
		t.Fatalf("%#v complete=%v", rows, complete)
	}
	for i, op := range []string{"LOGIN", "LOGIN", "LOGOUT"} {
		if rows[i]["operation"] != op || rows[i]["sourceIp"] != "192.0.2.1" || rows[i]["sessionId"] != "69100000.2a" || rows[i]["timestamp"] != "2026-11-09T00:00:00.123Z" {
			t.Fatal("wrong identity or clock", rows[i])
		}
		if _, ok := rows[i]["tls"]; ok {
			t.Fatal("client application text cannot prove TLS")
		}
	}
	raw, _ := json.Marshal(rows)
	for _, secret := range []string{"private-value", "secret", "private SQL", "password"} {
		if strings.Contains(string(raw), secret) {
			t.Fatal("raw message retained", secret)
		}
	}
	for _, invalid := range []string{
		"2026-11-09 00:00:00 CST [42] LOG:  connection authorized: user=app database=orders",
		strings.Replace(lines[0], "1794182400.123", "invalid", 1),
		strings.Replace(lines[0], "app database=orders", "has space database=orders", 1),
		strings.Replace(lines[0], "192.0.2.1(50000)", "192.0.2.1(99999)", 1),
	} {
		rows, complete = databaseAuditRows(PolicyRule{Config: PolicyConfig{Service: "postgresql-stderr", InstanceID: "instance"}}, []string{invalid})
		if complete || len(rows) != 0 {
			t.Fatal("unverified metadata accepted", rows)
		}
	}
}
