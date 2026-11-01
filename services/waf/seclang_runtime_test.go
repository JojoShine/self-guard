package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
)

func signedRuntimeSite(t *testing.T, key ed25519.PrivateKey, site Site, source string) Site {
	t.Helper()
	files, _ := json.Marshal([]secLangFile{{Name: "runtime.conf", Source: source}})
	if source == "" {
		files = []byte("[]")
	}
	sum := sha256.Sum256(files)
	bundleID := "test-bundle"
	if source == "" {
		bundleID = ""
	}
	payload, err := json.Marshal(secRuntimeRelease{SchemaVersion: 1, Engine: "selfguard-seclang-v1", BundleID: bundleID, BundleSHA256: hex.EncodeToString(sum[:]), Threshold: 5, Site: site, Files: files, Builtin: source == ""})
	if err != nil {
		t.Fatal(err)
	}
	site.RuleRelease = &secSignedRelease{Payload: base64.StdEncoding.EncodeToString(payload), Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(key, payload))}
	return site
}

func TestSignedActivePolicySimulationUsesVerifiedSnapshotWithoutChangingLiveProxy(t *testing.T) {
	public, private, _ := ed25519.GenerateKey(rand.Reader)
	e := newEngine()
	e.rulePublicKey = public
	e.rulePool = newSecLangPool(poolTestBinary(t), 1)
	defer e.rulePool.close()
	site := signedRuntimeSite(t, private, Site{ID: "simulated", Hostname: "simulated.test", Upstream: "http://127.0.0.1:1", Mode: "BLOCK", Enabled: true, Version: 1}, `SecRule ARGS:q "@streq attack" "id:120002,phase:2,deny,status:451"`)
	if err := e.update(Config{Sites: []Site{site}}); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(e.policyTestHandler("component-test-token"))
	defer server.Close()
	for _, sample := range []struct {
		path   string
		status int
	}{{"/?q=attack", 451}, {"/?q=normal", 200}} {
		raw, _ := json.Marshal(policyTestRequest{SiteID: site.ID, Method: "GET", Path: sample.path})
		request, _ := http.NewRequest("POST", server.URL, bytes.NewReader(raw))
		request.Header.Set("Authorization", "Bearer component-test-token")
		response, err := server.Client().Do(request)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(response.Body)
		response.Body.Close()
		if response.StatusCode != 200 {
			t.Fatalf("signed active policy rejected by simulation: %s", body)
		}
		var output struct {
			Version int `json:"version"`
			Results []struct {
				Status     int                 `json:"status"`
				Inspection *secEventInspection `json:"inspection"`
			} `json:"results"`
		}
		if json.Unmarshal(body, &output) != nil || output.Version != site.Version || len(output.Results) != 1 || output.Results[0].Status != sample.status {
			t.Fatalf("incorrect actual rule simulation: %s", body)
		}
		if sample.status == 451 && output.Results[0].Inspection == nil {
			t.Fatal("simulation lost actual rule evidence")
		}
	}
	if e.totalRequests.Load() != 0 || len(e.events) != 0 {
		t.Fatal("private simulation changed live counters or events")
	}
	for _, site := range e.sites.Load().(map[string]runtimeSite) {
		if _, ok := site.proxy.Transport.(*http.Transport); !ok {
			t.Fatal("simulation replaced live upstream transport")
		}
	}
}

func TestSignedRemoteConfigRejectsDowngradeBeforePersistenceAndRetainsFloorsAfterRemoval(t *testing.T) {
	public, private, _ := ed25519.GenerateKey(rand.Reader)
	e := newEngine()
	e.rulePublicKey = public
	e.rulePool = newSecLangPool(poolTestBinary(t), 1)
	defer e.rulePool.close()
	path := filepath.Join(t.TempDir(), "config.json")
	site := signedRuntimeSite(t, private, Site{ID: "retained", Hostname: "retained.test", Upstream: "http://127.0.0.1:1", Mode: "OBSERVE", Enabled: true, Version: 12}, "")
	raw, _ := json.Marshal(Config{Sites: []Site{site}})
	if err := e.applyRemoteConfig(path, raw); err != nil {
		t.Fatal(err)
	}
	committed, _ := os.ReadFile(path)
	older := site
	older.RuleRelease = nil
	older.Version = 11
	older = signedRuntimeSite(t, private, older, "")
	raw, _ = json.Marshal(Config{Sites: []Site{older}})
	if e.applyRemoteConfig(path, raw) == nil {
		t.Fatal("older signed policy accepted")
	}
	current, _ := os.ReadFile(path)
	if !bytes.Equal(current, committed) {
		t.Fatal("rejected downgrade overwrote persisted cache")
	}
	if e.applyRemoteConfig(path, []byte(`{"sites":[]}`)) != nil {
		t.Fatal("cannot remove site")
	}
	cache, _ := os.ReadFile(path)
	config, err := readConfig(cache)
	if err != nil {
		t.Fatal(err)
	}
	restarted := newEngine()
	restarted.rulePublicKey = public
	restarted.rulePool = e.rulePool
	if err = restarted.update(config); err != nil {
		t.Fatal(err)
	}
	if restarted.applyRemoteConfig(path, raw) == nil {
		t.Fatal("removed site lost its version floor across restart")
	}
	unsigned := site
	unsigned.RuleRelease = nil
	unsigned.Version = 13
	raw, _ = json.Marshal(Config{Sites: []Site{unsigned}})
	if restarted.applyRemoteConfig(path, raw) == nil {
		t.Fatal("unsigned replacement accepted with pinned trust")
	}
}

func TestSignedRulesProtectRealProxyAndRetainPriorPolicyOnRejectedUpdate(t *testing.T) {
	public, private, _ := ed25519.GenerateKey(rand.Reader)
	var forwarded atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { forwarded.Add(1); w.WriteHeader(200) }))
	defer upstream.Close()
	e := newEngine()
	e.rulePublicKey = public
	e.rulePool = newSecLangPool(poolTestBinary(t), 2)
	defer e.rulePool.close()
	source := `SecRule ARGS:q "@streq newly-detected" "id:120001,phase:2,deny,status:451,msg:'Local detection'"`
	site := signedRuntimeSite(t, private, Site{ID: "signed-site", Hostname: "signed.test", Upstream: upstream.URL, Mode: "BLOCK", Enabled: true, Version: 10}, source)
	if err := e.update(Config{Sites: []Site{site}}); err != nil {
		t.Fatal(err)
	}
	call := func(path string) int {
		r := httptest.NewRequest("GET", path, nil)
		r.Host = "signed.test"
		w := httptest.NewRecorder()
		e.ServeHTTP(w, r)
		return w.Code
	}
	if code := call("/?q=newly-detected"); code != 451 {
		t.Fatalf("signed rule response = %d", code)
	}
	if code := call("/?q=safe"); code != 200 {
		t.Fatalf("normal response = %d", code)
	}
	if forwarded.Load() != 1 {
		t.Fatal("blocked request reached upstream")
	}
	event := <-e.events
	if event.Inspection == nil || !event.Inspection.Complete || event.Inspection.DecisionStatus != 451 || event.Inspection.SiteHostname != "signed.test" || len(event.Inspection.Evidence) == 0 {
		t.Fatalf("real event evidence missing: %+v", event)
	}
	rawEvent, _ := json.Marshal(event)
	if bytes.Contains(rawEvent, []byte("newly-detected")) {
		t.Fatal("matched payload leaked into persisted event")
	}
	for _, mutate := range []func(*Site){
		func(s *Site) {
			copy := *s.RuleRelease
			copy.Signature = base64.StdEncoding.EncodeToString(make([]byte, 64))
			s.RuleRelease = &copy
		},
		func(s *Site) { s.Mode = "OBSERVE" },
		func(s *Site) { s.ID = "other-site" },
		func(s *Site) { s.Config.MaxBodyBytes = 2048 },
		func(s *Site) { s.RuleRelease = nil },
		func(s *Site) { s.RuleRelease = nil; s.Version++ },
	} {
		candidate := site
		mutate(&candidate)
		if err := e.update(Config{Sites: []Site{candidate}}); err == nil {
			t.Fatal("changed signed binding accepted")
		}
		if call("/?q=newly-detected") != 451 {
			t.Fatal("failed update replaced active protection")
		}
	}
	older := site
	older.RuleRelease = nil
	older.Version = 9
	if e.update(Config{Sites: []Site{older}}) == nil {
		t.Fatal("older unsigned configuration bypassed active version")
	}
	// A deliberate rollback is a new version and remains a signed decision.
	rollback := site
	rollback.RuleRelease = nil
	rollback.Version = 11
	rollback.Mode = "OBSERVE"
	rollback = signedRuntimeSite(t, private, rollback, source)
	if err := e.update(Config{Sites: []Site{rollback}}); err != nil {
		t.Fatal(err)
	}
	if call("/?q=newly-detected") != 200 {
		t.Fatal("new observation policy did not reach upstream")
	}
	if call("/?q=%ZZ") != 503 {
		t.Fatal("incomplete inspection silently allowed in observation mode")
	}
	var last Event
	for len(e.events) > 0 {
		last = <-e.events
	}
	if last.Inspection == nil || last.Inspection.Complete || last.RuleID != "INSPECTION_INCOMPLETE" || last.Inspection.DecisionStatus != 503 {
		t.Fatalf("incomplete check evidence lost: %+v", last)
	}
	builtin := rollback
	builtin.RuleRelease = nil
	builtin.Version = 12
	builtin.Mode = "BLOCK"
	builtin = signedRuntimeSite(t, private, builtin, "")
	if err := e.update(Config{Sites: []Site{builtin}}); err != nil {
		t.Fatal(err)
	}
	if call("/?q=union%20select") != 403 || call("/?q=newly-detected") != 200 {
		t.Fatal("signed builtin rollback did not restore builtin detection")
	}
}

func TestSignedRuntimeAcceptsExactManagementBytesAcrossLanguages(t *testing.T) {
	path := os.Getenv("WAF_RUNTIME_FIXTURE")
	if path == "" {
		t.Skip("requires isolated management signature fixture")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		RunID     string `json:"runId"`
		PublicKey string `json:"publicKey"`
		Config    Config `json:"config"`
	}
	if json.Unmarshal(raw, &fixture) != nil {
		t.Fatal("invalid management fixture")
	}
	key, err := base64.StdEncoding.DecodeString(fixture.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	e := newEngine()
	e.rulePublicKey = key
	e.rulePool = newSecLangPool(poolTestBinary(t), 1)
	defer e.rulePool.close()
	if err = e.update(fixture.Config); err != nil {
		t.Fatal("management-produced signature rejected: ", err)
	}
	if len(e.sites.Load().(map[string]runtimeSite)) != 1 {
		t.Fatal("signed management site lost")
	}
	if output := os.Getenv("WAF_RUNTIME_EVENT_FIXTURE"); output != "" {
		var hostname string
		for host, site := range e.sites.Load().(map[string]runtimeSite) {
			hostname = host
			site.proxy.Transport = noUpstream{}
		}
		server := httptest.NewServer(e)
		defer server.Close()
		request, _ := http.NewRequest("GET", server.URL+"/?q=new-proof", nil)
		request.Host = hostname
		response, err := server.Client().Do(request)
		if err != nil {
			t.Fatal(err)
		}
		response.Body.Close()
		if response.StatusCode != 200 {
			t.Fatalf("management observation request = %d", response.StatusCode)
		}
		select {
		case event := <-e.events:
			if event.Inspection == nil || !event.Inspection.Complete {
				t.Fatal("actual request produced no complete evidence")
			}
			raw, _ := json.Marshal(map[string]any{"runId": fixture.RunID, "event": event})
			if os.WriteFile(output, raw, 0600) != nil {
				t.Fatal("cannot write isolated event fixture")
			}
		default:
			t.Fatal("actual management rule did not emit an event")
		}
	}
}
