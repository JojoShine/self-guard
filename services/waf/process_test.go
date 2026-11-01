package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestWAFSubprocess(t *testing.T) {
	if os.Getenv("WAF_SUBPROCESS") == "true" {
		main()
	}
}

func TestProcessOfflineRestartHeartbeatAndDelivery(t *testing.T) {
	if testing.Short() {
		t.Skip("process lifecycle test")
	}
	dir := t.TempDir()
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("old route")) }))
	defer up.Close()
	data := []byte(fmt.Sprintf(`{"sites":[{"id":"a","hostname":"a","upstream":%q,"mode":"BLOCK","enabled":true,"version":7}]}`, up.URL))
	config := filepath.Join(dir, "config.json")
	if err := persistConfig(config, data); err != nil {
		t.Fatal(err)
	}
	var online atomic.Bool
	delivered := make(chan Event, 8)
	accessDelivered := make(chan AccessEntry, 100)
	heartbeats := make(chan map[string]any, 8)
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !online.Load() {
			w.WriteHeader(503)
			return
		}
		switch r.URL.Path {
		case "/api/telemetry/access":
			if r.Header.Get("Authorization") != "Bearer test-token" {
				w.WriteHeader(401)
				return
			}
			var batch struct {
				Events []AccessEntry `json:"events"`
			}
			if json.NewDecoder(r.Body).Decode(&batch) != nil {
				w.WriteHeader(400)
				return
			}
			for _, row := range batch.Events {
				accessDelivered <- row
			}
			w.WriteHeader(201)
		case "/api/waf/config":
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"sites":[{"hostname":"a","upstream":"file:///invalid","mode":"BLOCK"}]}`))
		case "/api/waf/events":
			var batch struct {
				Events []Event `json:"events"`
			}
			if json.NewDecoder(r.Body).Decode(&batch) != nil {
				w.WriteHeader(400)
				return
			}
			for _, ev := range batch.Events {
				delivered <- ev
			}
			w.WriteHeader(201)
		case "/api/waf/heartbeat":
			var body map[string]any
			if json.NewDecoder(r.Body).Decode(&body) != nil {
				w.WriteHeader(400)
				return
			}
			heartbeats <- body
			w.WriteHeader(201)
		default:
			w.WriteHeader(404)
		}
	}))
	defer api.Close()
	client := &http.Client{Timeout: time.Second}
	start := func() (string, func()) {
		t.Helper()
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		addr := listener.Addr().String()
		listener.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
		cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestWAFSubprocess$")
		cmd.Env = append(os.Environ(), "WAF_SUBPROCESS=true", "WAF_LISTEN="+addr, "WAF_STATE_DIR="+dir, "WAF_CONFIG="+config, "WAF_API_URL="+api.URL, "WAF_TOKEN=test-token", "WAF_TLS_CONFIG=", "WAF_TLS_CERT=", "WAF_TLS_KEY=", "WAF_NODE_ID=restart-test")
		if err = cmd.Start(); err != nil {
			cancel()
			t.Fatal(err)
		}
		stop := func() { cancel(); _ = cmd.Wait() }
		t.Cleanup(stop)
		deadline := time.Now().Add(5 * time.Second)
		for time.Now().Before(deadline) {
			req, _ := http.NewRequest("GET", "http://"+addr+"/", nil)
			req.Host = "a"
			resp, err := client.Do(req)
			if err == nil {
				resp.Body.Close()
				if resp.StatusCode == 200 {
					return addr, stop
				}
			}
			time.Sleep(20 * time.Millisecond)
		}
		stop()
		t.Fatal("WAF process did not start")
		return "", func() {}
	}
	attack := func(addr string) {
		t.Helper()
		req, _ := http.NewRequest("GET", "http://"+addr+"/?q=union%20select", nil)
		req.Host = "a"
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != 403 {
			t.Fatal(resp.StatusCode)
		}
	}
	addr, stop := start()
	attack(addr)
	stop()
	q, err := openOutbox(dir, 1024)
	if err != nil || len(q.items) != 1 {
		t.Fatal("offline event not saved", err)
	}
	id := q.items[0].ID
	pending, err := openAccessQueue(dir, 100000)
	if err != nil || pending.count() < 2 {
		t.Fatal("full request queue missing", err)
	}
	wantAccess := map[string]bool{}
	for name := range pending.files {
		b, err := os.ReadFile(filepath.Join(pending.dir, name))
		if err != nil {
			t.Fatal(err)
		}
		var row AccessEntry
		if json.Unmarshal(b, &row) != nil {
			t.Fatal("record")
		}
		wantAccess[row.ID] = true
	}
	online.Store(true)
	addr, stop = start()
	defer stop()
	attack(addr)
	select {
	case ev := <-delivered:
		if ev.ID != id {
			t.Fatal("restart changed event ID")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("pending event not replayed")
	}
	deadlineAccess := time.After(5 * time.Second)
	for len(wantAccess) > 0 {
		select {
		case row := <-accessDelivered:
			delete(wantAccess, row.ID)
		case <-deadlineAccess:
			t.Fatal("pending full request records not replayed")
		}
	}
	select {
	case heartbeat := <-heartbeats:
		if heartbeat["nodeId"] != "restart-test" || heartbeat["totalRequests"].(float64) < 2 || heartbeat["blockedRequests"] != float64(1) {
			t.Fatal(heartbeat)
		}
		history, ok := heartbeat["accessHistory"].([]any)
		if !ok || len(history) < 4 || heartbeat["accessHistoryCapacity"] != float64(1024) || heartbeat["accessHistoryEvictedSinceStart"] != float64(0) {
			t.Fatal("missing access history metadata", heartbeat)
		}
		ids := map[string]bool{}
		for _, row := range history {
			entry := row.(map[string]any)
			id, ok := entry["id"].(string)
			if !ok || id == "" || ids[id] {
				t.Fatal("invalid access ID", entry)
			}
			ids[id] = true
			if path, ok := entry["path"].(string); !ok || strings.Contains(path, "?") || entry["context"] == nil {
				t.Fatal("unredacted history", entry)
			}
		}
		sites := heartbeat["sites"].([]any)
		if len(sites) != 1 || sites[0].(map[string]any)["version"] != float64(7) {
			t.Fatal("invalid remote config displaced cached route", heartbeat)
		}
		if len(heartbeat["upstreamHealth"].([]any)) != 1 {
			t.Fatal("health missing", heartbeat)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("heartbeat not received")
	}
	req, _ := http.NewRequest("GET", "http://"+addr+"/", nil)
	req.Host = "a"
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatal("invalid snapshot lost old routing")
	}
}
