package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestEventOutboxByteBudgetRetainsReadableCommittedHistory(t *testing.T) {
	directory := t.TempDir()
	queue, err := openOutbox(directory, 1024)
	if err != nil {
		t.Fatal(err)
	}
	if err = queue.append(Event{ID: "committed"}); err != nil {
		t.Fatal(err)
	}
	if err = queue.append(Event{ID: "oversize", Path: strings.Repeat("x", 2<<20)}); err == nil {
		t.Fatal("unrecoverable oversized outbox accepted")
	}
	restored, err := openOutbox(directory, 1024)
	if err != nil {
		t.Fatal(err)
	}
	if len(restored.items) != 1 || restored.items[0].ID != "committed" {
		t.Fatal("failed append changed committed history")
	}
}

func TestOutboxRecoveryRetryAndAck(t *testing.T) {
	dir := t.TempDir()
	q, err := openOutbox(dir, 2)
	if err != nil {
		t.Fatal(err)
	}
	if err = q.append(Event{ID: "stable"}); err != nil {
		t.Fatal(err)
	}
	q, err = openOutbox(dir, 2)
	if err != nil {
		t.Fatal(err)
	}
	status := 500
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(status) }))
	defer server.Close()
	if q.deliver(server.Client(), server.URL, "token") == nil {
		t.Fatal("failure acknowledged")
	}
	if len(q.items) != 1 {
		t.Fatal("lost retry")
	}
	status = 201
	if err = q.deliver(server.Client(), server.URL, "token"); err != nil {
		t.Fatal(err)
	}
	q, err = openOutbox(dir, 2)
	if err != nil || len(q.items) != 0 {
		t.Fatal("ack not persisted", err)
	}
}
func TestOutboxOverflow(t *testing.T) {
	q, err := openOutbox(t.TempDir(), 1)
	if err != nil {
		t.Fatal(err)
	}
	if err = q.append(Event{ID: "a"}); err != nil {
		t.Fatal(err)
	}
	if q.append(Event{ID: "b"}) == nil {
		t.Fatal("capacity exceeded")
	}
	if q.items[0].ID != "a" {
		t.Fatal("old item replaced")
	}
}

func TestEventOutboxBatchesBoundedPrefixAndKeepsConcurrentAppendsOnAck(t *testing.T) {
	q, err := openOutbox(t.TempDir(), 200)
	if err != nil {
		t.Fatal(err)
	}
	for n := 0; n < 105; n++ {
		if err = q.append(Event{ID: fmt.Sprint(n)}); err != nil {
			t.Fatal(err)
		}
	}
	status := 500
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Events []Event `json:"events"`
		}
		if json.NewDecoder(r.Body).Decode(&body) != nil || len(body.Events) != 100 || body.Events[0].ID != "0" || body.Events[99].ID != "99" {
			t.Errorf("batch lost its bounded ordered prefix: %d", len(body.Events))
		}
		calls++
		if calls == 2 {
			if err := q.append(Event{ID: "concurrent"}); err != nil {
				t.Error(err)
			}
		}
		w.WriteHeader(status)
	}))
	defer server.Close()
	if q.deliver(server.Client(), server.URL, "token") == nil || len(q.items) != 105 {
		t.Fatal("failed batch lost events")
	}
	status = 201
	if err = q.deliver(server.Client(), server.URL, "token"); err != nil {
		t.Fatal(err)
	}
	restored, err := openOutbox(strings.TrimSuffix(q.path, "/events.json"), 200)
	if err != nil || len(restored.items) != 6 || restored.items[0].ID != "100" || restored.items[5].ID != "concurrent" {
		t.Fatal("batch ACK removed unsent events", err)
	}
}

func TestEventOutboxBatchHonorsWireBudget(t *testing.T) {
	q, err := openOutbox(t.TempDir(), 100)
	if err != nil {
		t.Fatal(err)
	}
	for n := 0; n < 100; n++ {
		if err = q.append(Event{ID: fmt.Sprint(n), Path: strings.Repeat("x", 3000)}); err != nil {
			t.Fatal(err)
		}
	}
	received := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if len(body) > 128<<10 {
			t.Error("event batch exceeded wire-size budget")
		}
		var batch struct {
			Events []Event `json:"events"`
		}
		if json.Unmarshal(body, &batch) != nil {
			t.Error("invalid batch")
		}
		received = len(batch.Events)
	}))
	defer server.Close()
	if err = q.deliver(server.Client(), server.URL, "token"); err != nil {
		t.Fatal(err)
	}
	if received < 1 || received >= 100 || len(q.items) != 100-received {
		t.Fatal("batch size did not reflect wire budget")
	}
}

func TestEventOutboxRejectsSingleRecordOverWireBudgetBeforePersistence(t *testing.T) {
	dir := t.TempDir()
	queue, err := openOutbox(dir, 10)
	if err != nil {
		t.Fatal(err)
	}
	if err = queue.append(Event{ID: "retained"}); err != nil {
		t.Fatal(err)
	}
	if queue.append(Event{ID: "too-large-for-wire", Path: strings.Repeat("x", 128<<10)}) == nil {
		t.Fatal("single unsendable event entered durable queue")
	}
	recovered, err := openOutbox(dir, 10)
	if err != nil || len(recovered.items) != 1 || recovered.items[0].ID != "retained" {
		t.Fatal("failed append changed committed history", err)
	}
}
