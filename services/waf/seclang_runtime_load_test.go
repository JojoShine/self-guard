//go:build pcre2 && cgo

package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestFrozenCRSRealHTTPFixedLoad(t *testing.T) {
	setting := os.Getenv("WAF_LOAD_DURATION")
	if setting == "" {
		t.Skip("requires explicit fixed-load environment")
	}
	duration, err := time.ParseDuration(setting)
	if err != nil || duration < time.Second || duration > 30*time.Minute || duration%time.Second != 0 {
		t.Fatal("load duration must be whole seconds, 1s to 30m")
	}
	raw, err := os.ReadFile(os.Getenv("WAF_CRS_INPUT"))
	if err != nil {
		t.Fatal(err)
	}
	var fixture secLangFixture
	if json.Unmarshal(raw, &fixture) != nil {
		t.Fatal("invalid frozen CRS")
	}
	profile, err := os.ReadFile(os.Getenv("WAF_CRS_PROFILE"))
	if err != nil {
		t.Fatal(err)
	}
	fixture.Files = append(fixture.Files, secLangFile{Name: "crs-setup.conf", Source: string(profile)})
	binary := os.Getenv("WAF_LOAD_BINARY")
	if binary == "" {
		binary = filepath.Join(t.TempDir(), "waf-pcre")
		if out, err := exec.Command("go", "build", "-tags", "pcre2", "-o", binary, ".").CombinedOutput(); err != nil {
			t.Fatalf("%s %v", out, err)
		}
	}
	public, private, _ := ed25519.GenerateKey(rand.Reader)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.Copy(io.Discard, r.Body); w.WriteHeader(200) }))
	defer upstream.Close()
	u, _ := url.Parse(upstream.URL)
	baseline := httptest.NewServer(httputil.NewSingleHostReverseProxy(u))
	defer baseline.Close()
	e := newEngine()
	e.rulePublicKey = public
	e.rulePool = newSecLangPool(binary, 3)
	defer e.rulePool.close()
	site := Site{ID: "load-only", Hostname: "load.fixture.test", Upstream: upstream.URL, Enabled: true, Mode: "BLOCK", Version: 1, Config: Policy{RatePerMinute: 100000}}
	files, _ := json.Marshal(fixture.Files)
	sum := sha256.Sum256(files)
	payload, _ := json.Marshal(secRuntimeRelease{SchemaVersion: 1, Engine: "selfguard-seclang-v1", BundleID: "frozen-crs-4.25.1", BundleSHA256: hex.EncodeToString(sum[:]), Threshold: 5, Site: site, Files: files})
	site.RuleRelease = &secSignedRelease{Payload: base64.StdEncoding.EncodeToString(payload), Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(private, payload))}
	if err = e.update(Config{Sites: []Site{site}}); err != nil {
		t.Fatal(err)
	}
	// Drain and classify every actual event; a full channel must not hide failures.
	failureCounts := map[string]int{}
	eventDone := make(chan struct{})
	go func() {
		defer close(eventDone)
		for event := range e.events {
			if event.Inspection != nil && !event.Inspection.Complete {
				failureCounts[event.Inspection.FailureKind]++
			}
		}
	}()
	server := httptest.NewServer(e)
	defer server.Close()
	client := &http.Client{Transport: &http.Transport{Proxy: nil, MaxIdleConns: 200, MaxIdleConnsPerHost: 100}, Timeout: 3 * time.Second}
	defer client.CloseIdleConnections()
	body := func(attack bool) string {
		prefix := "q=normal&padding="
		if attack {
			prefix = "q=%3Cscript%3Ealert(1)%3C%2Fscript%3E&padding="
		}
		return prefix + strings.Repeat("a", 4096-len(prefix))
	}
	call := func(address string, attack bool) (int, float64) {
		request, _ := http.NewRequest("POST", address+"/submit", strings.NewReader(body(attack)))
		request.Host = site.Hostname
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		request.Header.Set("User-Agent", "SelfGuard-Acceptance")
		request.Header.Set("Accept", "*/*")
		started := time.Now()
		response, err := client.Do(request)
		if err != nil {
			return 0, float64(time.Since(started).Microseconds()) / 1000
		}
		io.Copy(io.Discard, response.Body)
		response.Body.Close()
		return response.StatusCode, float64(time.Since(started).Microseconds()) / 1000
	}
	for index := 0; index < 20; index++ {
		code, _ := call(server.URL, index%20 == 0)
		if code != 200 && code != 403 {
			t.Fatalf("warmup inspection failed: %d", code)
		}
	}
	type sample struct {
		Index           int     `json:"index"`
		Attack          bool    `json:"attack"`
		BaselineMS      float64 `json:"baselineMs"`
		WafMS           float64 `json:"wafMs"`
		AddedMS         float64 `json:"addedMs"`
		Status          int     `json:"status"`
		BaselineStatus  int     `json:"baselineStatus"`
		DispatchDelayMS float64 `json:"dispatchDelayMs"`
	}
	count := int(duration/time.Second) * 100
	results := make(chan sample, count)
	inflight := make(chan struct{}, 100)
	var wg sync.WaitGroup
	started := time.Now()
	for index := 0; index < count; index++ {
		deadline := started.Add(time.Duration(index) * 10 * time.Millisecond)
		if remaining := time.Until(deadline); remaining > 0 {
			time.Sleep(remaining)
		}
		select {
		case inflight <- struct{}{}:
		default:
			t.Fatal("generator exceeded bounded concurrency; target throughput not reached")
		}
		wg.Add(1)
		go func(index int, deadline time.Time) {
			defer wg.Done()
			defer func() { <-inflight }()
			attack := index%20 == 0
			delay := float64(time.Since(deadline).Microseconds()) / 1000
			baseCode, baseMS := call(baseline.URL, attack)
			code, wafMS := call(server.URL, attack)
			results <- sample{index, attack, baseMS, wafMS, wafMS - baseMS, code, baseCode, delay}
		}(index, deadline)
	}
	wg.Wait()
	close(e.events)
	<-eventDone
	close(results)
	elapsed := time.Since(started)
	samples := make([]sample, 0, count)
	added := make([]float64, 0, count)
	errors := 0
	for row := range results {
		samples = append(samples, row)
		added = append(added, row.AddedMS)
		want := 200
		if row.Attack {
			want = 403
		}
		if row.Status != want || row.BaselineStatus != 200 {
			errors++
		}
	}
	sort.Slice(samples, func(i, j int) bool { return samples[i].Index < samples[j].Index })
	sort.Float64s(added)
	p95 := added[(len(added)-1)*95/100]
	report := map[string]any{"at": time.Now().UTC(), "durationSeconds": duration.Seconds(), "elapsedSeconds": elapsed.Seconds(), "requests": len(samples), "wafRps": float64(len(samples)) / elapsed.Seconds(), "bodyBytes": 4096, "normalPercent": 95, "attackPercent": 5, "engine": "selfguard-seclang-v1", "bundleSha256": hex.EncodeToString(sum[:]), "workerStarts": e.rulePool.stats(), "errors": errors, "inspectionFailures": failureCounts, "droppedEvents": e.dropped.Load(), "addedP50Ms": added[(len(added)-1)/2], "addedP95Ms": p95, "environment": os.Getenv("WAF_LOAD_ENVIRONMENT"), "fullAcceptance": false, "meaning": "Paired actual HTTP proxy comparison; a short run or non-reference environment does not complete 30-minute acceptance or stable-memory verification", "samples": samples}
	if output := os.Getenv("WAF_LOAD_OUTPUT"); output != "" {
		raw, _ := json.Marshal(report)
		if err = os.WriteFile(output, raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
	t.Logf("actual HTTP 4KiB 95/5 requests=%d elapsed=%s rps=%.2f errors=%d addedP95=%.3fms workerStarts=%d", len(samples), elapsed, float64(len(samples))/elapsed.Seconds(), errors, p95, e.rulePool.stats())
	if errors > 0 || p95 > 20 || float64(len(samples))/elapsed.Seconds() < 99 {
		t.Fatal("fixed-load smoke target not reached; full acceptance remains pending")
	}
}

func BenchmarkFrozenCRS4KiBRequest(b *testing.B) {
	file := os.Getenv("WAF_CRS_INPUT")
	if file == "" {
		b.Skip("requires frozen CRS")
	}
	raw, err := os.ReadFile(file)
	if err != nil {
		b.Fatal(err)
	}
	var fixture secLangFixture
	if json.Unmarshal(raw, &fixture) != nil {
		b.Fatal("invalid CRS fixture")
	}
	profile, err := os.ReadFile(os.Getenv("WAF_CRS_PROFILE"))
	if err != nil {
		b.Fatal(err)
	}
	fixture.Files = append(fixture.Files, secLangFile{Name: "crs-setup.conf", Source: string(profile)})
	rules, err := parseSecLangFiles(fixture.Files)
	if err != nil {
		b.Fatal(err)
	}
	plan, err := prepareSecLangPlan(rules)
	if err != nil {
		b.Fatal(err)
	}
	body := "q=normal&padding="
	body += strings.Repeat("a", 4096-len(body))
	request := httptest.NewRequest("POST", "/submit", strings.NewReader(body))
	request.Host = "load.fixture.test"
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("User-Agent", "SelfGuard-Acceptance")
	request.Header.Set("Accept", "*/*")
	input := secLangFixture{Request: newSecLiveRequest(request, []byte(body)), Threshold: 5}
	b.ReportAllocs()
	b.ResetTimer()
	for index := 0; index < b.N; index++ {
		result, err := evaluateSecLangRequest(plan, input)
		if err != nil || result.Blocked {
			b.Fatalf("normal corpus failed: %+v %v", result, err)
		}
	}
}
