package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBuiltinEventRetainsActualMatchedFieldAndRuleBasisWithoutRawPayload(t *testing.T) {
	e := newEngine()
	site := Site{ID: "actual-basic", Hostname: "business.test", Upstream: "http://127.0.0.1:1", Mode: "BLOCK", Enabled: true, Version: 2}
	if err := e.update(Config{Sites: []Site{site}}); err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("GET", "/?q=union%20select", nil)
	r.Host = site.Hostname
	w := httptest.NewRecorder()
	e.ServeHTTP(w, r)
	if w.Code != 403 {
		t.Fatal(w.Code)
	}
	event := <-e.events
	if event.Inspection == nil || !event.Inspection.Complete || len(event.Inspection.Evidence) != 1 {
		t.Fatalf("basic rule event lacks actual evidence: %+v", event)
	}
	proof := event.Inspection
	sum := sha256.Sum256([]byte("union select"))
	if proof.Evidence[0].Variable != "ARGS:q" || proof.Evidence[0].ValueSHA256 != hex.EncodeToString(sum[:]) || proof.Evidence[0].MessageTemplate == "" || proof.SiteHostname != site.Hostname {
		t.Fatalf("actual rule context lost: %+v", proof)
	}
	raw, _ := json.Marshal(event)
	if strings.Contains(string(raw), "union select") {
		t.Fatal("raw payload leaked")
	}
}

func TestProxy(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok")) }))
	defer up.Close()
	for _, tc := range []struct {
		mode, path string
		want       int
	}{{"BLOCK", "/hello", 200}, {"BLOCK", "/?q=union%20select", 403}, {"OBSERVE", "/?q=union%20select", 200}} {
		e := newEngine()
		err := e.update(Config{Sites: []Site{{ID: "a", Hostname: "example.test", Upstream: up.URL, Mode: tc.mode, Enabled: true}}})
		if err != nil {
			t.Fatal(err)
		}
		r := httptest.NewRequest("GET", tc.path, nil)
		r.Host = "example.test"
		w := httptest.NewRecorder()
		e.ServeHTTP(w, r)
		if w.Code != tc.want {
			t.Fatalf("%s: %d", tc.path, w.Code)
		}
	}
}
func TestInvalidConfigRetained(t *testing.T) {
	e := newEngine()
	if e.update(Config{Sites: []Site{{Hostname: "a", Upstream: "file:///etc/passwd", Mode: "BLOCK"}}}) == nil {
		t.Fatal("accepted invalid upstream")
	}
}
func TestRateAndSpoof(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer up.Close()
	e := newEngine()
	s := Site{ID: "a", Hostname: "a", Upstream: up.URL, Mode: "BLOCK", Enabled: true}
	s.Config.RatePerMinute = 1
	if err := e.update(Config{Sites: []Site{s}}); err != nil {
		t.Fatal(err)
	}
	for i, want := range []int{200, 403} {
		r := httptest.NewRequest("GET", "/", nil)
		r.Host = "a"
		r.Header.Set("X-Forwarded-For", []string{"1.2.3.4", "5.6.7.8"}[i])
		w := httptest.NewRecorder()
		e.ServeHTTP(w, r)
		if w.Code != want {
			t.Fatalf("got %d", w.Code)
		}
	}
}

func TestBodyLimit(t *testing.T) {
	e := newEngine()
	s := Site{ID: "a", Hostname: "a", Upstream: "http://127.0.0.1:1", Mode: "OBSERVE", Enabled: true}
	s.Config.MaxBodyBytes = 2
	if err := e.update(Config{Sites: []Site{s}}); err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("POST", "/", strings.NewReader("large"))
	r.Host = "a"
	w := httptest.NewRecorder()
	e.ServeHTTP(w, r)
	if w.Code != 413 {
		t.Fatal(w.Code)
	}
}

func TestEncodedJSONAndExactHost(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer up.Close()
	e := newEngine()
	if err := e.update(Config{Sites: []Site{{ID: "a", Hostname: "example.test", Upstream: up.URL, Mode: "BLOCK", Enabled: true}}}); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		host, body string
		want       int
	}{{"example.test", `{"q":"\u003cscript>"}`, 403}, {"evil.example.test", `{}`, 404}, {"example.test.evil", `{}`, 404}} {
		r := httptest.NewRequest("POST", "/", strings.NewReader(tc.body))
		r.Host = tc.host
		r.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		e.ServeHTTP(w, r)
		if w.Code != tc.want {
			t.Fatalf("%s got %d", tc.host, w.Code)
		}
	}
}
func TestEventUniquenessAndPrivacy(t *testing.T) {
	e := newEngine()
	if err := e.update(Config{Sites: []Site{{ID: "a", Hostname: "a", Upstream: "http://127.0.0.1:1", Mode: "BLOCK", Enabled: true}}}); err != nil {
		t.Fatal(err)
	}
	ids := map[string]bool{}
	for i := 0; i < 10; i++ {
		r := httptest.NewRequest("GET", "/secret-token?q=union%20select", nil)
		r.Host = "a"
		w := httptest.NewRecorder()
		e.ServeHTTP(w, r)
		ev := <-e.events
		if ids[ev.ID] {
			t.Fatal("duplicate event")
		}
		ids[ev.ID] = true
		if ev.Path != "/secret-token" || ev.Context == nil || strings.Contains(ev.Path,"?") {
			t.Fatal("path leaked")
		}
	}
}

func TestManagementPolicy(t *testing.T) {
	for _, tc := range []struct {
		u       string
		dev, ok bool
	}{{"http://example.com", false, false}, {"http://127.0.0.1:80", false, true}, {"https://example.com", false, true}, {"http://api:4000", true, true}, {"https://user:secret@example.com", false, false}} {
		if (validateManagementURL(tc.u, tc.dev) == nil) != tc.ok {
			t.Fatal(tc.u)
		}
	}
}
func TestEncodingPolicy(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer up.Close()
	for _, mode := range []string{"BLOCK", "OBSERVE"} {
		e := newEngine()
		if err := e.update(Config{Sites: []Site{{ID: "a", Hostname: "a", Upstream: up.URL, Mode: mode, Enabled: true}}}); err != nil {
			t.Fatal(err)
		}
		r := httptest.NewRequest("POST", "/", strings.NewReader("compressed"))
		r.Host = "a"
		r.Header.Set("Content-Encoding", "gzip")
		r.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		e.ServeHTTP(w, r)
		want := 200
		if mode == "BLOCK" {
			want = 403
		}
		if w.Code != want {
			t.Fatal(mode, w.Code)
		}
		if ev := <-e.events; ev.RuleID != "ENCODING" {
			t.Fatal(ev)
		}
	}
}

func TestPersistConfig(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	b := []byte(`{"sites":[]}`)
	if err := persistConfig(path, b); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil || string(data) != string(b) {
		t.Fatal("snapshot not persisted")
	}
	info, _ := os.Stat(path)
	if info.Mode().Perm() != 0600 {
		t.Fatal("snapshot permissions")
	}
	if _, err = readConfig(data); err != nil {
		t.Fatal(err)
	}
}
