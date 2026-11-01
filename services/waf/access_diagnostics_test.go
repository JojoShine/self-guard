package main

import (
	"encoding/json"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestAccessDiagnosticsAreDevelopmentOnlyAndBounded(t *testing.T) {
	t.Setenv("WAF_DEVELOPMENT", "false")
	if newEngine().accessWriteTimings != nil {
		t.Fatal("normal runtime enabled persistence profiling")
	}
	t.Setenv("WAF_DEVELOPMENT", "true")
	d := newEngine().accessWriteTimings
	if d == nil {
		t.Fatal("development runtime omitted persistence profiling")
	}
	var workers sync.WaitGroup
	for range 8 {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for range 1000 {
				d.observe(accessHistoryStage, 25*time.Millisecond, false)
			}
		}()
	}
	workers.Wait()
	snapshot := d.snapshot()
	if snapshot.History.Count != 8000 || snapshot.History.TotalMicros != 200000000 || snapshot.History.MaxMicros != 25000 || snapshot.History.Buckets[7] != 8000 {
		t.Fatalf("lost or incorrect concurrent timing observations: %+v", snapshot.History)
	}
	snapshot.History.Buckets[7] = 0
	if d.snapshot().History.Buckets[7] != 8000 {
		t.Fatal("snapshot exposed mutable timing state")
	}
}

func TestAccessDiagnosticsDistinguishActualHistoryQueueAndCompletion(t *testing.T) {
	dir := t.TempDir()
	queue, err := openAccessQueue(dir, 16)
	if err != nil {
		t.Fatal(err)
	}
	history, err := openAccessLog(dir, 16)
	if err != nil {
		t.Fatal(err)
	}
	d := &accessWriteDiagnostics{}
	e := &engine{accessPending: queue, access: history, accessWriteTimings: d, nodeID: "owned-stage", startedAt: "owned-start"}
	e.sites.Store(map[string]runtimeSite{})
	queue.mu.Lock()
	held := true
	done := make(chan struct{})
	go func() {
		e.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "http://owned.fixture.test/private-input", nil))
		close(done)
	}()
	defer func() {
		if held {
			queue.mu.Unlock()
		}
		<-done
	}()
	deadline := time.Now().Add(time.Second)
	for d.snapshot().History.Count == 0 {
		if time.Now().After(deadline) {
			t.Fatal("independent history stage did not complete")
		}
		time.Sleep(time.Millisecond)
	}
	before := d.snapshot()
	if before.HandlerBeforeAudit.Count != 1 || before.Queue.Count != 0 || before.AuditCompletion.Count != 0 {
		t.Fatalf("blocked queue reported as completed: %+v", before)
	}
	select {
	case <-done:
		t.Fatal("response returned before both stores completed")
	default:
	}
	queue.mu.Unlock()
	held = false
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("durable stores did not complete")
	}
	after := d.snapshot()
	if after.Queue.Count != 1 || after.History.Count != 1 || after.AuditCompletion.Count != 1 || after.Queue.Errors != 0 || after.History.Errors != 0 {
		t.Fatalf("actual persistence stages missing: %+v", after)
	}
	e.rulePool = newSecLangPool("unused", 3)
	defer e.rulePool.close()
	request := httptest.NewRequest("GET", "/seclang/pool", nil)
	request.Header.Set("Authorization", "Bearer owned-private-diagnostic")
	response := httptest.NewRecorder()
	e.rulePoolHandler("owned-private-diagnostic").ServeHTTP(response, request)
	var result struct {
		AccessWrites accessWriteSnapshot `json:"accessWrites"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil || result.AccessWrites.AuditCompletion.Count != 1 || response.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("private diagnostics omitted actual completion", err)
	}
	if strings.Contains(response.Body.String(), "private-input") || strings.Contains(response.Body.String(), "owned-stage") {
		t.Fatal("duration diagnostics exposed request or node identity")
	}
}

func TestAccessDiagnosticsCountActualPersistenceFailure(t *testing.T) {
	dir := t.TempDir()
	history, err := openAccessLog(dir, 16)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(history.path, 0700); err != nil {
		t.Fatal(err)
	}
	d := &accessWriteDiagnostics{}
	e := &engine{access: history, accessWriteTimings: d, nodeID: "owned-failure", startedAt: "owned-start"}
	e.sites.Store(map[string]runtimeSite{})
	e.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "http://owned.fixture.test/", nil))
	result := d.snapshot()
	if result.History.Count != 1 || result.History.Errors != 1 || result.AuditCompletion.Errors != 1 || e.accessLogDropped.Load() != 1 || len(history.items) != 0 {
		t.Fatalf("actual failed persistence was hidden: %+v", result)
	}
}

func TestExplicitHTTPManagementTransport(t *testing.T) {
	t.Setenv("WAF_ALLOW_HTTP", "")
	if validateManagementURL("http://platform.example:8080", false) == nil {
		t.Fatal("HTTP must be explicit")
	}
	t.Setenv("WAF_ALLOW_HTTP", "true")
	if err := validateManagementURL("http://platform.example:8080", false); err != nil {
		t.Fatal(err)
	}
	if validateManagementURL("ftp://platform.example:8080", false) == nil {
		t.Fatal("unsupported scheme accepted")
	}
}
