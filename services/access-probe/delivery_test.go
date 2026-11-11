package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
)

func TestDeliveryRetriesWithPersistentQueueAndRejectsForeignAcknowledgement(t *testing.T) {
	q, err := openQueue(filepath.Join(t.TempDir(), "queue"), 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	e := q.newEvent()
	e.Operation = "GET"
	e.request.Write([]byte("abc"))
	e.RequestBytes = 3
	e.finish()
	if err = q.commit(e); err != nil {
		t.Fatal(err)
	}
	received := false
	foreign := true
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Header.Get("Authorization") != "Bearer source-secret" {
			w.WriteHeader(401)
			return
		}
		if r.URL.Path == "/api/access-probe/chunks" {
			var v struct {
				EventID   string `json:"eventId"`
				SHA256    string `json:"sha256"`
				Direction string `json:"direction"`
				Sequence  int    `json:"sequence"`
			}
			json.NewDecoder(r.Body).Decode(&v)
			received = true
			json.NewEncoder(w).Encode(map[string]any{"persisted": true, "eventId": v.EventID, "sha256": v.SHA256, "direction": v.Direction, "sequence": v.Sequence})
			return
		}
		if !received {
			w.WriteHeader(409)
			w.Write([]byte(`{"message":"pending"}`))
			return
		}
		id := e.EventID
		if foreign {
			id = "wrong-event"
		}
		json.NewEncoder(w).Encode(map[string]any{"accepted": true, "eventId": id, "id": "stored-id"})
	}))
	defer server.Close()
	client, err := newProbeClient(ProbeLocalConfig{Server: server.URL, Token: "source-secret", AllowHTTP: true})
	if err != nil {
		t.Fatal(err)
	}
	if err = deliverPending(client, q); err == nil {
		t.Fatal("foreign acknowledgement accepted")
	}
	pending, _ := q.pending()
	if len(pending) != 1 {
		t.Fatal("unconfirmed evidence deleted")
	}
	foreign = false
	if err = deliverPending(client, q); err != nil {
		t.Fatal(err)
	}
	pending, _ = q.pending()
	if len(pending) != 0 {
		t.Fatal("acknowledged evidence remained")
	}
}

func TestPermanentlyRejectedRecordDoesNotBlockFollowingEvidence(t *testing.T) {
	for _, status := range []int{400, 413, 422} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			q, err := openQueue(filepath.Join(t.TempDir(), "queue"), 1<<20)
			if err != nil {
				t.Fatal(err)
			}
			bad := q.newEvent()
			bad.EventID = "00000000-0000-4000-8000-000000000001"
			bad.Operation = "BAD-CMD"
			bad.finish()
			if err = q.commit(bad); err != nil {
				t.Fatal(err)
			}
			good := q.newEvent()
			good.EventID = "00000000-0000-4000-8000-000000000002"
			good.Operation = "GET"
			good.finish()
			if err = q.commit(good); err != nil {
				t.Fatal(err)
			}
			accepted := false
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var event Exchange
				if err := json.NewDecoder(r.Body).Decode(&event); err != nil {
					t.Error(err)
					return
				}
				if event.EventID == bad.EventID {
					w.WriteHeader(status)
					return
				}
				accepted = true
				json.NewEncoder(w).Encode(eventAcknowledgement{Accepted: true, EventID: event.EventID, ID: "persisted"})
			}))
			defer server.Close()
			client, err := newProbeClient(ProbeLocalConfig{Server: server.URL, AllowHTTP: true})
			if err != nil {
				t.Fatal(err)
			}
			if err = deliverPending(client, q); err == nil {
				t.Fatal("rejection must remain visible")
			}
			if !accepted {
				t.Fatal("invalid record blocked later evidence")
			}
			if pending, _ := q.pending(); len(pending) != 0 {
				t.Fatal("poison still active")
			}
			if rejected, _ := q.rejectedCount(); rejected != 1 {
				t.Fatal("rejected encrypted evidence not retained")
			}
		})
	}
}

func TestPermanentChunkRejectionIsIsolatedWithoutDeletingItsEvidence(t *testing.T) {
	q, err := openQueue(filepath.Join(t.TempDir(), "queue"), 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	bad := q.newEvent()
	bad.EventID = "00000000-0000-4000-8000-000000000001"
	bad.Operation = "GET"
	bad.request.Write([]byte("retained"))
	bad.RequestBytes = 8
	bad.finish()
	if err = q.commit(bad); err != nil {
		t.Fatal(err)
	}
	good := q.newEvent()
	good.EventID = "00000000-0000-4000-8000-000000000002"
	good.Operation = "GET"
	good.finish()
	if err = q.commit(good); err != nil {
		t.Fatal(err)
	}
	accepted := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/access-probe/chunks" {
			w.WriteHeader(413)
			return
		}
		var event Exchange
		if err := json.NewDecoder(r.Body).Decode(&event); err != nil {
			t.Error(err)
			return
		}
		if event.EventID == bad.EventID {
			w.WriteHeader(409)
			return
		}
		accepted = true
		json.NewEncoder(w).Encode(eventAcknowledgement{Accepted: true, EventID: event.EventID, ID: "persisted"})
	}))
	defer server.Close()
	client, err := newProbeClient(ProbeLocalConfig{Server: server.URL, AllowHTTP: true})
	if err != nil {
		t.Fatal(err)
	}
	if err = deliverPending(client, q); err == nil {
		t.Fatal("permanent rejection hidden")
	}
	if !accepted {
		t.Fatal("chunk rejection blocked later record")
	}
	data, err := q.chunk(bad.EventID, bad.Chunks[0])
	if err != nil || string(data) != "retained" {
		t.Fatal("unconfirmed rejected evidence lost", err)
	}
	if count, _ := q.rejectedCount(); count != 1 {
		t.Fatal("rejected manifest missing")
	}
}
