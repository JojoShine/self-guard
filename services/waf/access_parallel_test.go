package main

import (
	"net/http/httptest"
	"os"
	"testing"
	"time"
)

func TestIndependentAccessWritesOverlapAndBothRemainDurable(t *testing.T) {
	dir := t.TempDir()
	queue, err := openAccessQueue(dir, 16)
	if err != nil {
		t.Fatal(err)
	}
	history, err := openAccessLog(dir, 16)
	if err != nil {
		t.Fatal(err)
	}
	e := &engine{accessPending: queue, access: history, nodeID: "owned-overlap", startedAt: "owned-start"}
	e.sites.Store(map[string]runtimeSite{})
	queue.mu.Lock()
	held := true
	done := make(chan struct{})
	go func() {
		e.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "http://owned.fixture.test/safe", nil))
		close(done)
	}()
	defer func() {
		if held {
			queue.mu.Unlock()
		}
		<-done
	}()
	deadline := time.Now().Add(time.Second)
	for {
		if _, err := os.Stat(history.path); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("independent history persistence was blocked behind the delivery queue")
		}
		time.Sleep(time.Millisecond)
	}
	select {
	case <-done:
		t.Fatal("HTTP handler returned before the delivery record was durable")
	default:
	}
	queue.mu.Unlock()
	held = false
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("durable writes did not finish")
	}
	reopenedQueue, err := openAccessQueue(dir, 16)
	if err != nil {
		t.Fatal(err)
	}
	reopenedHistory, err := openAccessLog(dir, 16)
	if err != nil {
		t.Fatal(err)
	}
	if reopenedQueue.count() != 1 || len(reopenedHistory.items) != 1 || reopenedHistory.items[0].ID != "owned-overlap:owned-start:1" || e.accessLogDropped.Load() != 0 {
		t.Fatal("a completed request must survive in both independent stores")
	}
}
