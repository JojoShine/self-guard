package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

type persistentLoadSample struct {
	Index           int     `json:"index"`
	Attack          bool    `json:"attack"`
	Status          int     `json:"status"`
	BaselineStatus  int     `json:"baselineStatus"`
	WafMS           float64 `json:"wafMs"`
	BaselineMS      float64 `json:"baselineMs"`
	AddedMS         float64 `json:"addedMs"`
	DispatchDelayMS float64 `json:"dispatchDelayMs"`
	Failure         string  `json:"failure,omitempty"`
}

// Keep WAF dispatch independent of baseline latency. Serial comparison can
// turn an upstream pause into a burst of delayed WAF requests.
func persistentPairedSample(call func(string, bool) (int, float64, string), baseline, target string, attack bool) persistentLoadSample {
	type baselineResult struct {
		status  int
		ms      float64
		failure string
	}
	completed := make(chan baselineResult, 1)
	go func() {
		status, ms, failure := call(baseline, attack)
		completed <- baselineResult{status, ms, failure}
	}()
	code, wafMS, failure := call(target, attack)
	base := <-completed
	if base.failure != "" {
		failure = "BASELINE_" + base.failure
	}
	return persistentLoadSample{Attack: attack, Status: code, BaselineStatus: base.status, WafMS: wafMS, BaselineMS: base.ms, AddedMS: wafMS - base.ms, Failure: failure}
}

type persistentLoadMemory struct {
	ElapsedSeconds float64   `json:"elapsedSeconds"`
	At             time.Time `json:"at"`
	RSSBytes       uint64    `json:"rssBytes"`
	Processes      int       `json:"processes"`
	PendingAccess  int       `json:"pendingAccess"`
	PendingEvents  int       `json:"pendingEvents"`
	Error          string    `json:"error,omitempty"`
}

func persistentMemorySample(state, mainPID string) persistentLoadMemory {
	result := persistentLoadMemory{At: time.Now().UTC()}
	tasks, err := os.ReadDir("/proc/" + mainPID + "/task")
	if err != nil {
		result.Error = "PROCESS_LIST_UNAVAILABLE"
		return result
	}
	unique := map[string]bool{mainPID: true}
	// A Go process can fork from any OS thread; inspect every task's children.
	for _, task := range tasks {
		children, err := os.ReadFile("/proc/" + mainPID + "/task/" + task.Name() + "/children")
		if err != nil {
			continue
		}
		for _, pid := range strings.Fields(string(children)) {
			unique[pid] = true
		}
	}
	pids := make([]string, 0, len(unique))
	for pid := range unique {
		pids = append(pids, pid)
	}
	for _, pid := range pids {
		if pid == strconv.Itoa(os.Getpid()) {
			continue
		}
		raw, err := os.ReadFile("/proc/" + pid + "/statm")
		if err != nil {
			continue
		}
		fields := strings.Fields(string(raw))
		if len(fields) < 2 {
			continue
		}
		pages, err := strconv.ParseUint(fields[1], 10, 64)
		if err != nil {
			result.Error = "RSS_UNAVAILABLE"
			continue
		}
		result.RSSBytes += pages * uint64(os.Getpagesize())
		result.Processes++
	}
	entries, err := os.ReadDir(filepath.Join(state, "access-pending"))
	if err != nil {
		result.Error = "ACCESS_QUEUE_UNAVAILABLE"
	} else {
		result.PendingAccess = len(entries)
	}
	raw, err := os.ReadFile(filepath.Join(state, "events.json"))
	if err == nil {
		var events []json.RawMessage
		if len(raw) > 2<<20 || json.Unmarshal(raw, &events) != nil {
			result.Error = "EVENT_QUEUE_UNREADABLE"
		} else {
			result.PendingEvents = len(events)
		}
	} else if !os.IsNotExist(err) {
		result.Error = "EVENT_QUEUE_UNAVAILABLE"
	}
	return result
}
func TestPersistentWAFProcessFixedLoad(t *testing.T) {
	setting := os.Getenv("WAF_PERSISTENT_LOAD_DURATION")
	if setting == "" {
		t.Skip("requires explicit owned persistent-load fixture")
	}
	duration, err := time.ParseDuration(setting)
	if err != nil || duration < time.Second || duration > 30*time.Minute || duration%time.Second != 0 {
		t.Fatal("invalid persistent load duration")
	}
	target, err := url.Parse(os.Getenv("WAF_PERSISTENT_TARGET"))
	if err != nil || target.Scheme != "http" || (target.Host != "127.0.0.1:8081" && target.Host != "127.0.0.1:18081") || target.User != nil || target.RawQuery != "" || target.Path != "" {
		t.Fatal("owned local WAF process required")
	}
	upstream, err := url.Parse(os.Getenv("WAF_PERSISTENT_UPSTREAM"))
	if err != nil || upstream.Scheme != "http" || (upstream.Host != "selfguard-persistent-api:4401" && upstream.Host != "host.lima.internal:14421" && upstream.Host != "127.0.0.1:18082") || upstream.Path != "" || upstream.User != nil || upstream.RawQuery != "" || upstream.Fragment != "" {
		t.Fatal("owned upstream required")
	}
	state := os.Getenv("WAF_STATE_DIR")
	if state != "/state/runtime" && (!strings.HasPrefix(state, "/opt/selfguard-waf-load/persistent-") || filepath.Base(state) != "state" || strings.Contains(state, "..")) {
		t.Fatal("owned persistent state directory required")
	}
	mainPID := os.Getenv("WAF_PERSISTENT_MAIN_PID")
	if mainPID == "" {
		mainPID = "1"
	}
	if _, err := strconv.ParseUint(mainPID, 10, 31); err != nil {
		t.Fatal("invalid owned process identity")
	}
	binaryPath := os.Getenv("WAF_PERSISTENT_BINARY")
	if binaryPath == "" {
		binaryPath = "/waf"
	}
	actualBinary, err := os.Readlink("/proc/" + mainPID + "/exe")
	if err != nil || actualBinary != binaryPath {
		t.Fatal("RSS target does not match owned WAF executable")
	}
	baseline := httptest.NewServer(httputil.NewSingleHostReverseProxy(upstream))
	defer baseline.Close()
	client := &http.Client{Transport: &http.Transport{Proxy: nil, MaxIdleConns: 200, MaxIdleConnsPerHost: 100}, Timeout: 3 * time.Second}
	defer client.CloseIdleConnections()
	call := func(origin string, attack bool) (int, float64, string) {
		prefix := "q=normal&padding="
		if attack {
			prefix = "q=%3Cscript%3Ealert(1)%3C%2Fscript%3E&padding="
		}
		body := prefix + strings.Repeat("a", 4096-len(prefix))
		request, _ := http.NewRequest("POST", origin+"/submit", strings.NewReader(body))
		request.Host = "persistent-load.fixture.test"
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		request.Header.Set("User-Agent", "SelfGuard-Acceptance")
		request.Header.Set("Accept", "*/*")
		started := time.Now()
		response, err := client.Do(request)
		if err != nil {
			return 0, float64(time.Since(started).Microseconds()) / 1000, "HTTP_REQUEST_FAILED"
		}
		_, err = io.Copy(io.Discard, response.Body)
		response.Body.Close()
		if err != nil {
			return response.StatusCode, float64(time.Since(started).Microseconds()) / 1000, "HTTP_RESPONSE_INCOMPLETE"
		}
		return response.StatusCode, float64(time.Since(started).Microseconds()) / 1000, ""
	}
	for index := 0; index < 20; index++ {
		code, _, failure := call(target.String(), index%20 == 0)
		want := 200
		if index%20 == 0 {
			want = 403
		}
		if code != want || failure != "" {
			t.Fatalf("warmup failed status=%d kind=%s", code, failure)
		}
	}
	memoryStarted := time.Now()
	sampleMemory := func() persistentLoadMemory {
		row := persistentMemorySample(state, mainPID)
		row.ElapsedSeconds = time.Since(memoryStarted).Seconds()
		return row
	}
	memory := []persistentLoadMemory{sampleMemory()}
	stop := make(chan struct{})
	memoryDone := make(chan struct{})
	go func() {
		defer close(memoryDone)
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-stop:
				return
			case <-ticker.C:
				memory = append(memory, sampleMemory())
			}
		}
	}()
	count := int(duration/time.Second) * 100
	samples := make([]persistentLoadSample, count)
	inflight := make(chan struct{}, 100)
	var wg sync.WaitGroup
	started := time.Now()
	for index := 0; index < count; index++ {
		deadline := started.Add(time.Duration(index) * 10 * time.Millisecond)
		if remaining := time.Until(deadline); remaining > 0 {
			time.Sleep(remaining)
		}
		attack := index%20 == 0
		select {
		case inflight <- struct{}{}:
		default:
			samples[index] = persistentLoadSample{Index: index, Attack: attack, Failure: "GENERATOR_CAPACITY"}
			continue
		}
		wg.Add(1)
		go func(index int, attack bool, deadline time.Time) {
			defer wg.Done()
			defer func() { <-inflight }()
			dispatch := float64(time.Since(deadline).Microseconds()) / 1000
			sample := persistentPairedSample(call, baseline.URL, target.String(), attack)
			sample.Index, sample.DispatchDelayMS = index, dispatch
			samples[index] = sample
		}(index, attack, deadline)
	}
	wg.Wait()
	elapsed := time.Since(started)
	// Database counts alone cannot prove that disk queues were acknowledged.
	// Keep the real node and API alive while independently observing both queues.
	drainStarted := time.Now()
	drain := sampleMemory()
	for drain.Error == "" && (drain.PendingAccess > 0 || drain.PendingEvents > 0) && time.Since(drainStarted) < 30*time.Second {
		time.Sleep(100 * time.Millisecond)
		drain = sampleMemory()
	}
	close(stop)
	<-memoryDone
	memory = append(memory, sampleMemory())
	added := make([]float64, 0, count)
	errors := 0
	failures := map[string]int{}
	for _, sample := range samples {
		added = append(added, sample.AddedMS)
		want := 200
		if sample.Attack {
			want = 403
		}
		if sample.Status != want || sample.BaselineStatus != 200 || sample.Failure != "" {
			errors++
			key := sample.Failure
			if key == "" {
				key = fmt.Sprintf("WAF_%d_BASE_%d", sample.Status, sample.BaselineStatus)
			}
			failures[key]++
		}
	}
	sort.Float64s(added)
	p95 := added[(len(added)-1)*95/100]
	binary, err := os.ReadFile(binaryPath)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(binary)
	report := map[string]any{"requests": count, "warmupRequests": 20, "warmupAttacks": 1, "expectedAttacks": count/20 + 1, "errors": errors, "failures": failures, "durationSeconds": duration.Seconds(), "elapsedSeconds": elapsed.Seconds(), "rps": float64(count) / elapsed.Seconds(), "bodyBytes": 4096, "normalPercent": 95, "attackPercent": 5, "addedP50Ms": added[(len(added)-1)/2], "addedP95Ms": p95, "engineSha256": hex.EncodeToString(digest[:]), "memoryTimeBase": "GO_MONOTONIC_ELAPSED", "memoryAndQueues": memory, "drain": map[string]any{"at": drain.At, "pendingAccess": drain.PendingAccess, "pendingEvents": drain.PendingEvents, "error": drain.Error, "elapsedSeconds": time.Since(drainStarted).Seconds()}, "samples": samples, "fullAcceptance": false, "meaning": "Actual separate WAF process with disk queues; API driver must independently verify persisted counts, queue drain, reference resources and sustained memory before acceptance"}
	output := os.Getenv("WAF_PERSISTENT_OUTPUT")
	if !strings.HasPrefix(output, "/reports/") && output != filepath.Join(filepath.Dir(state), "reports", "load.json") {
		t.Fatal("owned report path required")
	}
	raw, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(output, raw, 0600); err != nil {
		t.Fatal(err)
	}
	t.Logf("persistent process requests=%d errors=%d addedP95=%.3fms rps=%.2f", count, errors, p95, float64(count)/elapsed.Seconds())
	if errors > 0 || p95 > 20 || float64(count)/elapsed.Seconds() < 99 || drain.Error != "" || drain.PendingAccess > 0 || drain.PendingEvents > 0 {
		t.Fatal("persistent load threshold not reached")
	}
}
