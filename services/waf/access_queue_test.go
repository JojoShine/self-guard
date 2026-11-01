package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
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
