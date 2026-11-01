package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPathLimitsAndInvalidSnapshotRetainsRouting(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("alive")) }))
	defer up.Close()
	e := newEngine()
	raw := `{"sites":[{"id":"a","hostname":"a","upstream":"` + up.URL + `","mode":"BLOCK","enabled":true,"config":{"ratePerMinute":100,"pathRateLimits":[{"path":"/login","ratePerMinute":1}]}}]}`
	c, err := readConfig([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	if err = e.update(c); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		path string
		want int
	}{{"/login", 200}, {"/login", 403}, {"/other", 200}, {"/login/other", 200}} {
		r := httptest.NewRequest("GET", tc.path, nil)
		r.Host = "a"
		w := httptest.NewRecorder()
		e.ServeHTTP(w, r)
		if w.Code != tc.want {
			t.Fatalf("%s: got %d want %d", tc.path, w.Code, tc.want)
		}
	}
	c.Sites[0].Upstream = "file:///bad"
	if e.update(c) == nil {
		t.Fatal("invalid accepted")
	}
	r := httptest.NewRequest("GET", "/still", nil)
	r.Host = "a"
	w := httptest.NewRecorder()
	e.ServeHTTP(w, r)
	if w.Code != 200 || w.Body.String() != "alive" {
		t.Fatal("old route lost")
	}
	for _, bad := range []string{`{"path":"login","ratePerMinute":1}`, `{"path":"/login","ratePerMinute":0}`, `{"path":"/login?x=1","ratePerMinute":1}`} {
		c, err = readConfig([]byte(strings.Replace(raw, `{"path":"/login","ratePerMinute":1}`, bad, 1)))
		if err == nil && e.update(c) == nil {
			t.Fatal("invalid limit accepted", bad)
		}
	}
}

func TestAccessLogRecordsEveryOutcomeAndSurvivesRestart(t *testing.T) {
	dir := t.TempDir()
	e := newEngine()
	var err error
	e.access, err = openAccessLog(dir, 3)
	if err != nil {
		t.Fatal(err)
	}
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(201) }))
	defer up.Close()
	if err = e.update(Config{Sites: []Site{{ID: "a", Hostname: "a", Upstream: up.URL, Mode: "BLOCK", Enabled: true}}}); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		host, path string
		want       int
	}{{"a", "/private?token=secret", 201}, {"a", "/?q=union%20select", 403}, {"unknown", "/secret", 404}, {"a", "/ok", 201}} {
		r := httptest.NewRequest("GET", tc.path, nil)
		r.Host = tc.host
		r.Header.Set("Authorization", "secret")
		w := httptest.NewRecorder()
		e.ServeHTTP(w, r)
		if w.Code != tc.want {
			t.Fatal(w.Code)
		}
	}
	if e.totalRequests.Load() != 4 || e.blockedRequests.Load() != 1 {
		t.Fatal("incorrect totals")
	}
	reopened, err := openAccessLog(dir, 3)
	if err != nil {
		t.Fatal(err)
	}
	if len(reopened.items) != 3 || reopened.items[0].Status != 403 || reopened.items[1].Status != 404 {
		t.Fatal("bounded log not retained", reopened.items)
	}
	data, err := os.ReadFile(filepath.Join(dir, "access.json"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "token=secret") || strings.Contains(string(data), "union%20select") || strings.Contains(string(data), "Authorization") {
		t.Fatal("sensitive log")
	}
	var rows []map[string]any
	if json.Unmarshal(data, &rows) != nil {
		t.Fatal("invalid json")
	}
}

// These requests exercise each inspection input rather than only inspect().
func TestAttackCarriersAndNarrowException(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer up.Close()
	for _, tc := range []struct{ name, method, path, ct, body, header, rule string }{
		{"query SQLI", "GET", "/?q=union%20select", "", "", "", "SQLI"},
		{"header XSS", "GET", "/", "", "", "<script>", "XSS"},
		{"form traversal", "POST", "/", "application/x-www-form-urlencoded", "file=..%2F..%2Fpasswd", "", "TRAVERSAL"},
		{"json command", "POST", "/", "application/json", `{"q":"; cat /etc/passwd"}`, "", "COMMAND"},
		{"path traversal", "GET", "/a/../private", "", "", "", "TRAVERSAL"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := newEngine()
			if err := e.update(Config{Sites: []Site{{ID: "a", Hostname: "a", Upstream: up.URL, Mode: "BLOCK", Enabled: true}}}); err != nil {
				t.Fatal(err)
			}
			r := httptest.NewRequest(tc.method, tc.path, strings.NewReader(tc.body))
			r.Host = "a"
			r.Header.Set("Content-Type", tc.ct)
			if tc.header != "" {
				r.Header.Set("X-Test", tc.header)
			}
			w := httptest.NewRecorder()
			e.ServeHTTP(w, r)
			if w.Code != 403 {
				t.Fatal(w.Code)
			}
			if ev := <-e.events; ev.RuleID != tc.rule {
				t.Fatal(ev.RuleID)
			}
		})
	}
	e := newEngine()
	s := Site{ID: "a", Hostname: "a", Upstream: up.URL, Mode: "BLOCK", Enabled: true, Config: Policy{Exceptions: []Exception{{RuleID: "SQLI", Path: "/search", Param: "q"}}}}
	if err := e.update(Config{Sites: []Site{s}}); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		path string
		want int
	}{{"/search?q=union%20select", 200}, {"/other?q=union%20select", 403}, {"/search?other=union%20select", 403}, {"/search?q=%3Cscript%3E", 403}} {
		r := httptest.NewRequest("GET", tc.path, nil)
		r.Host = "a"
		w := httptest.NewRecorder()
		e.ServeHTTP(w, r)
		if w.Code != tc.want {
			t.Fatal(tc.path, w.Code)
		}
	}
}

func TestTrustedProxyChainAndHeaderStripping(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Real-IP") != "" || r.Header.Get("Forwarded") != "" {
			t.Error("identity header forwarded")
		}
	}))
	defer up.Close()
	for _, tc := range []struct {
		remote, chain string
		want          int
	}{{"10.0.0.2:123", "198.51.100.1, 10.0.0.3", 403}, {"10.0.0.2:123", "198.51.100.1, 203.0.113.2", 200}, {"203.0.113.2:123", "198.51.100.1", 200}, {"10.0.0.2:123", "198.51.100.1, invalid", 200}} {
		e := newEngine()
		if err := e.update(Config{Sites: []Site{{ID: "a", Hostname: "a", Upstream: up.URL, Mode: "BLOCK", Enabled: true, Config: Policy{DenyCidrs: []string{"198.51.100.0/24"}, TrustedProxyCidrs: []string{"10.0.0.0/8"}}}}}); err != nil {
			t.Fatal(err)
		}
		r := httptest.NewRequest("GET", "/", nil)
		r.Host = "a"
		r.RemoteAddr = tc.remote
		r.Header.Set("X-Forwarded-For", tc.chain)
		r.Header.Set("Forwarded", "for=198.51.100.1")
		r.Header.Set("X-Real-IP", "198.51.100.1")
		w := httptest.NewRecorder()
		e.ServeHTTP(w, r)
		if w.Code != tc.want {
			t.Fatal(tc, w.Code)
		}
	}
}

func TestOfflineConfigAndOutboxRestart(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	raw := []byte(`{"sites":[{"id":"a","hostname":"a","upstream":"http://127.0.0.1:1","mode":"BLOCK","enabled":true}]}`)
	if err := persistConfig(path, raw); err != nil {
		t.Fatal(err)
	}
	first := newEngine()
	var err error
	first.outbox, err = openOutbox(dir, 2)
	if err != nil {
		t.Fatal(err)
	}
	c, err := readConfig(raw)
	if err != nil {
		t.Fatal(err)
	}
	if err = first.update(c); err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("GET", "/?q=union%20select", nil)
	r.Host = "a"
	first.ServeHTTP(httptest.NewRecorder(), r)
	cached, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	c, err = readConfig(cached)
	if err != nil {
		t.Fatal(err)
	}
	restarted := newEngine()
	if err = restarted.update(c); err != nil {
		t.Fatal(err)
	}
	restarted.outbox, err = openOutbox(dir, 2)
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	r = httptest.NewRequest("GET", "/?q=union%20select", nil)
	r.Host = "a"
	restarted.ServeHTTP(w, r)
	if w.Code != 403 || len(restarted.outbox.items) != 2 || restarted.outbox.items[0].ID == restarted.outbox.items[1].ID {
		t.Fatal("offline protection or pending event lost")
	}
}

func TestDiskFailureCountsAndRetainsPendingEvent(t *testing.T) {
	dir := t.TempDir()
	e := newEngine()
	var err error
	e.outbox, err = openOutbox(dir, 2)
	if err != nil {
		t.Fatal(err)
	}
	e.access, err = openAccessLog(dir, 2)
	if err != nil {
		t.Fatal(err)
	}
	if err = e.outbox.append(Event{ID: "retained"}); err != nil {
		t.Fatal(err)
	}
	// A directory at each destination makes atomic rename fail even when tests run as root.
	if err = os.Remove(e.outbox.path); err != nil {
		t.Fatal(err)
	}
	if err = os.Mkdir(e.outbox.path, 0700); err != nil {
		t.Fatal(err)
	}
	if err = os.Mkdir(e.access.path, 0700); err != nil {
		t.Fatal(err)
	}
	if err = e.update(Config{Sites: []Site{{ID: "a", Hostname: "a", Upstream: "http://127.0.0.1:1", Mode: "BLOCK", Enabled: true}}}); err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("GET", "/?q=union%20select", nil)
	r.Host = "a"
	w := httptest.NewRecorder()
	e.ServeHTTP(w, r)
	if w.Code != 403 || e.dropped.Load() != 1 || e.accessLogDropped.Load() != 1 || len(e.outbox.items) != 1 || e.outbox.items[0].ID != "retained" {
		t.Fatal("disk failure lost pending event or counter")
	}
}

func TestHeartbeatAccessHistoryStableIDsAndRetentionMetadata(t *testing.T) {
	dir := t.TempDir()
	e := newEngine()
	var err error
	e.access, err = openAccessLog(dir, 2)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		r := httptest.NewRequest("GET", "/private?token=secret", nil)
		r.Host = "unknown"
		e.ServeHTTP(httptest.NewRecorder(), r)
	}
	heartbeat := e.heartbeatPayload()
	rows := heartbeat["accessHistory"].([]AccessEntry)
	if len(rows) != 2 || rows[0].ID == "" || rows[0].ID == rows[1].ID {
		t.Fatal("missing stable unique IDs", rows)
	}
	if heartbeat["accessHistoryCapacity"] != 2 || heartbeat["accessHistoryCount"] != 2 || heartbeat["accessHistoryEvictedSinceStart"] != uint64(1) {
		t.Fatal("missing retention metadata", heartbeat)
	}
	encoded, _ := json.Marshal(rows)
	if strings.Contains(string(encoded), "token=secret") || strings.Contains(string(encoded), "Authorization") {
		t.Fatal("sensitive history")
	}
	restored, err := openAccessLog(dir, 2)
	if err != nil {
		t.Fatal(err)
	}
	next := newEngine()
	next.access = restored
	retained := next.heartbeatPayload()["accessHistory"].([]AccessEntry)
	if retained[0].ID != rows[0].ID || retained[1].ID != rows[1].ID {
		t.Fatal("restart changed record IDs")
	}
	retained[0].ID = "mutated"
	if next.heartbeatPayload()["accessHistory"].([]AccessEntry)[0].ID == "mutated" {
		t.Fatal("snapshot is mutable")
	}
}

func TestLegacyAccessHistoryReceivesPersistentIDs(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "access.json")
	if err := os.WriteFile(path, []byte(`[{"siteId":"a","method":"GET","path":"[redacted]","status":200,"timestamp":"2026-10-30T01:00:00Z","durationMicros":10}]`), 0600); err != nil {
		t.Fatal(err)
	}
	first, err := openAccessLog(dir, 2)
	if err != nil {
		t.Fatal(err)
	}
	if first.items[0].ID == "" {
		t.Fatal("legacy record missing ID")
	}
	second, err := openAccessLog(dir, 2)
	if err != nil {
		t.Fatal(err)
	}
	if second.items[0].ID != first.items[0].ID {
		t.Fatal("legacy ID not stable")
	}
}

func TestAccessSnapshotEncodingRetainsExactJSONAcrossEvictionAndFailures(t *testing.T) {
	directory := t.TempDir()
	history, err := openAccessLog(directory, 4)
	if err != nil {
		t.Fatal(err)
	}
	for index := 0; index < 20; index++ {
		entry := AccessEntry{ID: fmt.Sprintf("stable-%d", index), SiteID: "fixture", Method: "GET", Path: "<>&\"界", Status: 200 + index, Timestamp: "2026-11-01T00:00:00Z"}
		if err = history.append(entry); err != nil {
			t.Fatal(err)
		}
		expected, _ := json.Marshal(history.items)
		actual, err := os.ReadFile(history.path)
		if err != nil || string(actual) != string(expected) {
			t.Fatal("cached encoding changed durable snapshot", err)
		}
		reopened, err := openAccessLog(directory, 4)
		if err != nil || len(reopened.items) != len(history.items) {
			t.Fatal(err)
		}
		for i := range reopened.items {
			if reopened.items[i] != history.items[i] {
				t.Fatal("reopen changed ordered history")
			}
		}
	}
	before := append([]AccessEntry(nil), history.items...)
	saved := history.path
	history.path = directory // rename over a directory must fail, even under root.
	if err = history.append(AccessEntry{ID: "must-not-commit", Status: 200}); err == nil {
		t.Fatal("failed persist accepted")
	}
	for i := range before {
		if before[i] != history.items[i] {
			t.Fatal("failed persist mutated acknowledged history")
		}
	}
	history.path = saved
	if err = history.append(AccessEntry{ID: "after-failure", Status: 200}); err != nil {
		t.Fatal(err)
	}
	expected, _ := json.Marshal(history.items)
	actual, _ := os.ReadFile(history.path)
	if string(actual) != string(expected) {
		t.Fatal("failed update poisoned encoded cache")
	}
}

func BenchmarkDurableAccessHistoryAppend(b *testing.B) {
	history, err := openAccessLog(b.TempDir(), 1024)
	if err != nil {
		b.Fatal(err)
	}
	for index := 0; index < 1024; index++ {
		if err = history.append(AccessEntry{ID: fmt.Sprintf("warm-%d", index), SiteID: "fixture-site", Method: "GET", Path: "[redacted]", Status: 200, Timestamp: "2026-11-01T00:00:00Z"}); err != nil {
			b.Fatal(err)
		}
	}
	b.ReportAllocs()
	b.ResetTimer()
	for index := 0; index < b.N; index++ {
		if err = history.append(AccessEntry{ID: fmt.Sprintf("actual-%d", index), SiteID: "fixture-site", Method: "GET", Path: "[redacted]", Status: 200, Timestamp: "2026-11-01T00:00:00Z"}); err != nil {
			b.Fatal(err)
		}
	}
}
