package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestDatabaseBruteForceSourceWindowAndRestart(t *testing.T) {
	now := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	rule := PolicyRule{ID: "db", Kind: "LOG", Config: PolicyConfig{Type: "DATABASE_AUTH", Service: "postgresql", Threshold: 3, WindowSeconds: 60}}
	line := func(ip, user string, at time.Time) string {
		b, _ := json.Marshal(map[string]string{"timestamp": at.Format(time.RFC3339Nano), "remote_host": ip, "user": user, "state_code": "28P01", "message": "password=private-secret"})
		return string(b)
	}
	lines := []string{line("192.0.2.1", "a", now.Add(-5*time.Second)), line("192.0.2.2", "b", now.Add(-4*time.Second)), line("192.0.2.1", "c", now.Add(-3*time.Second)), line("192.0.2.1", "old", now.Add(-time.Hour))}
	state, findings := databaseWindows(nil, rule, "/db.json", lines, now)
	if len(findings) != 0 {
		t.Fatalf("premature %#v", findings)
	}
	raw, _ := json.Marshal(state)
	if strings.Contains(string(raw), "private-secret") {
		t.Fatal("credential retained")
	}
	var restored map[string]logWindow
	json.Unmarshal(raw, &restored)
	_, findings = databaseWindows(restored, rule, "/db.json", []string{line("192.0.2.1", "d", now.Add(-time.Second))}, now)
	if len(findings) != 1 || findings[0]["title"] != "数据库疑似口令爆破" {
		t.Fatalf("%#v", findings)
	}
	evidence := findings[0]["evidence"].(map[string]any)
	if evidence["sourceIp"] != "192.0.2.1" || evidence["count"] != 3 || evidence["action"] != "DETECT_ONLY" {
		t.Fatalf("%#v", evidence)
	}
}
func TestDatabasePlaintextRequiresExplicitSuccessfulAudit(t *testing.T) {
	now := time.Now().UTC()
	rule := PolicyRule{ID: "plain", Config: PolicyConfig{Type: "DATABASE_CLEARTEXT", Service: "audit-json", WindowSeconds: 60}}
	for _, fields := range []string{`"outcome":"CONNECTED"`, `"outcome":"CONNECTED","tls":true`, `"outcome":"AUTH_FAILURE","tls":false`} {
		line := fmtAudit(now, fields)
		_, findings := databaseWindows(nil, rule, "/audit", []string{line}, now)
		if len(findings) != 0 {
			t.Fatal("unknown, TLS or rejected connection called plaintext")
		}
	}
	_, findings := databaseWindows(nil, rule, "/audit", []string{fmtAudit(now, `"outcome":"CONNECTED","tls":false`)}, now)
	if len(findings) != 1 || findings[0]["title"] != "数据库未加密连接" {
		t.Fatalf("%#v", findings)
	}
}
func fmtAudit(now time.Time, fields string) string {
	return `{"timestamp":"` + now.Format(time.RFC3339Nano) + `","service":"mysql","sourceIp":"192.0.2.5",` + fields + "}"
}
func TestDatabaseBaselines(t *testing.T) {
	cases := []struct {
		key, body, mode string
		match, unknown  bool
	}{
		{"MYSQL_TLS_REQUIRED", "[mysqld]\nrequire_secure_transport = ON", "", false, false},
		{"MYSQL_TLS_REQUIRED", "[client]\nrequire_secure_transport=ON", "", false, true},
		{"MYSQL_TLS_REQUIRED", "[mysqld]\nrequire_secure_transport=off", "", true, false},
		{"MYSQL_TLS_REQUIRED", "!includedir /etc/mysql/conf.d\n[mysqld]\nrequire_secure_transport=ON", "", false, true},
		{"POSTGRES_TLS_ENABLED", "ssl = 'on' # supported", "", false, false},
		{"POSTGRES_TLS_ENABLED", "ssl=off", "", true, false},
		{"POSTGRES_HBA_TLS", "host all all 0.0.0.0/0 scram-sha-256", "", true, false},
		{"POSTGRES_HBA_TLS", "hostssl all all 0.0.0.0/0 scram-sha-256\nhost all all 0.0.0.0/0 reject", "", false, false},
		{"POSTGRES_HBA_AUTH", "hostssl all all 0.0.0.0/0 trust", "", true, false},
		{"POSTGRES_HBA_AUTH", "include 'more.conf'", "", false, true},
		{"POSTGRES_HBA_TLS", "local all all trust", "", false, false},
		{"CREDENTIAL_FILE_MODE", "", "0400", false, false}, {"CREDENTIAL_FILE_MODE", "", "0644", true, false},
	}
	for _, c := range cases {
		a, e, s := databaseBaseline(Check{Key: c.key}, c.body, c.mode)
		unknown := s != "checked"
		match := !unknown && a != e
		if match != c.match || unknown != c.unknown {
			t.Errorf("%s %q => %q %q %q", c.key, c.body, a, e, s)
		}
	}
}
func TestDatabaseCollectorRealFileAndPolicyBoundary(t *testing.T) {
	root := t.TempDir()
	p := filepath.Join(root, "audit.json")
	now := time.Now().UTC()
	os.WriteFile(p, []byte(fmtAudit(now, `"outcome":"CONNECTED","tls":false`)+"\n"), 0600)
	a := &Agent{Config: Config{AllowedRoot: root, StateDir: root}, Identity: Identity{AssetID: "asset"}}
	a.applyPolicy([]PolicyRule{{ID: "db", Kind: "LOG", Config: PolicyConfig{Type: "DATABASE_CLEARTEXT", Service: "audit-json", Path: p, Threshold: 1, WindowSeconds: 60}}})
	findings := a.collectFilesAt(now)
	found := false
	for _, f := range findings {
		if f["title"] == "数据库未加密连接" {
			found = true
		}
	}
	if !found {
		t.Fatalf("no live collection: %#v", findings)
	}
}
func TestDatabaseDeniedPolicyReportsCoverageAndNoRead(t *testing.T) {
	root := t.TempDir()
	outside := filepath.Join(t.TempDir(), "audit")
	os.WriteFile(outside, []byte("must-not-read"), 0600)
	a := &Agent{Config: Config{AllowedRoot: root, StateDir: root}, Identity: Identity{AssetID: "asset"}}
	a.applyPolicy([]PolicyRule{{ID: "db", Kind: "LOG", Config: PolicyConfig{Type: "DATABASE_AUTH", Service: "mysql", Path: outside, Threshold: 5, WindowSeconds: 60}}})
	if len(a.LogRules) != 0 || len(a.PolicyFindings) != 1 {
		t.Fatal("unsafe path accepted or silent rejection")
	}
	findings := a.collectFilesAt(time.Now())
	if len(findings) != 1 || findings[0]["severity"] != "INFO" {
		t.Fatal(findings)
	}
}
func TestDatabasePostgresNativeNumericPort(t *testing.T) {
	raw := `{"timestamp":"2026-11-01 08:25:09.831 UTC","user":"audit_fixture_user","dbname":"postgres","remote_host":"127.0.0.1","remote_port":53226,"state_code":"28P01"}`
	o, ok := databaseLog(raw, "postgresql")
	if !ok || o.SourcePort != 53226 {
		t.Fatalf("native PostgreSQL numeric port rejected: %+v", o)
	}
}

func TestDatabasePostgresOrdinaryNativeMessagesAreNotCoverageFailures(t *testing.T) {
	now := time.Now().UTC()
	body, _ := json.Marshal(map[string]string{"timestamp": now.Format(time.RFC3339Nano), "error_severity": "LOG", "message": "database system is ready to accept connections"})
	raw := string(body)
	_, findings := databaseWindows(nil, PolicyRule{ID: "pg", Config: PolicyConfig{Type: "DATABASE_AUTH", Service: "postgresql", Threshold: 3, WindowSeconds: 60}}, "/db", []string{raw}, now)
	if len(findings) != 0 {
		t.Fatalf("ordinary native LOG misclassified: %#v", findings)
	}
}
