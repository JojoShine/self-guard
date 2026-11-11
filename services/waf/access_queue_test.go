package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"
)

func TestAccessQueueDurableBatchAckAndOverflow(t *testing.T) {
	dir := t.TempDir()
	q, err := openAccessQueue(dir, 1100)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 1100; i++ {
		if err = q.append(AccessEntry{ID: fmt.Sprintf("id-%04d", i), Status: 200}); err != nil {
			t.Fatal(err)
		}
	}
	if q.append(AccessEntry{ID: "overflow"}) == nil {
		t.Fatal("overflow must be explicit")
	}
	q, err = openAccessQueue(dir, 1100)
	if err != nil {
		t.Fatal(err)
	}
	status := 503
	received := []string{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/telemetry/access" || r.Header.Get("Authorization") != "Bearer token" {
			t.Error("identity or endpoint")
		}
		var b struct {
			Events []AccessEntry `json:"events"`
		}
		if json.NewDecoder(r.Body).Decode(&b) != nil {
			t.Error("body")
		}
		if len(b.Events) != 100 {
			t.Error("batch size", len(b.Events))
		}
		for _, e := range b.Events {
			received = append(received, e.ID)
		}
		w.WriteHeader(status)
	}))
	defer server.Close()
	if q.deliver(server.Client(), server.URL, "token", "node") == nil {
		t.Fatal("failed status ACKed")
	}
	status = 201
	if err = q.deliver(server.Client(), server.URL, "token", "node"); err != nil {
		t.Fatal(err)
	}
	if received[0] != received[100] {
		t.Fatal("retry changed stable IDs")
	}
	q, err = openAccessQueue(dir, 1100)
	if err != nil || q.count() != 1000 {
		t.Fatal("ACK not durable", err, q.count())
	}
}

func TestAcknowledgedQueueFileRemovalDoesNotHoldAppendMutex(t *testing.T) {
	q, err := openAccessQueue(t.TempDir(), 10)
	if err != nil {
		t.Fatal(err)
	}
	if err = q.append(AccessEntry{ID: "owned-record", Status: 200}); err != nil {
		t.Fatal(err)
	}
	arrived, ack := make(chan struct{}), make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		close(arrived)
		<-ack
		w.WriteHeader(201)
	}))
	defer server.Close()
	done := make(chan error, 1)
	go func() { done <- q.deliver(server.Client(), server.URL, "test-token", "node") }()
	<-arrived
	q.mu.Lock()
	held := true
	defer func() {
		if held {
			q.mu.Unlock()
		}
		<-done
	}()
	close(ack)
	deadline := time.Now().Add(time.Second)
	removed := false
	for time.Now().Before(deadline) {
		files, e := os.ReadDir(q.dir)
		if e != nil {
			t.Fatal(e)
		}
		if len(files) == 0 {
			removed = true
			break
		}
		time.Sleep(time.Millisecond)
	}
	if !removed {
		t.Fatal("acknowledged file deletion waits for append mutex; disk I/O stalls new durable records")
	}
	q.mu.Unlock()
	held = false
}
