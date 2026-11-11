package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"
)

func monitorFixture() TrafficMonitorConfig {
	return TrafficMonitorConfig{Schema: "selfguard-traffic-monitor-config-v1", MonitorID: "10000000-0000-4000-8000-000000000001", AssetID: "10000000-0000-4000-8000-000000000002", StateDir: "/var/lib/selfguard-traffic-monitor", Capture: TrafficCaptureConfig{Interface: "lo", Protocol: "TCP", Ports: []int{443}, MaxPackets: 1, MaxBytes: 4096, SnapLen: 128}}
}
func TestTrafficMonitorConfig(t *testing.T) {
	c := monitorFixture()
	if err := c.validate(); err != nil || c.Capture.DurationSeconds != 60 {
		t.Fatalf("default interval: %v %+v", err, c)
	}
	c.Capture.IncludePayload = true
	if c.validate() == nil {
		t.Fatal("payload accepted")
	}
	c = monitorFixture()
	c.Capture.SnapLen = 129
	if c.validate() == nil {
		t.Fatal("nonmetadata snap accepted")
	}
}
func TestTrafficMonitorWindowsContinueAfterBudget(t *testing.T) {
	c := monitorFixture()
	c.Capture.DurationSeconds = 1
	start := time.Now()
	w := newTrafficMonitorWindow(c.Capture, start)
	w.summary.Packets = 1
	w.consume(nil, start)
	if w.summary.StopReason != "PACKET_LIMIT" {
		t.Fatal(w.summary.StopReason)
	}
	first := w.roll(start.Add(time.Second), false)
	if first == nil || first.Complete || first.StopReason != "PACKET_LIMIT" {
		t.Fatalf("%+v", first)
	}
	second := w.roll(start.Add(2*time.Second), false)
	if second == nil || !second.Complete || second.StopReason != "WINDOW_ELAPSED" {
		t.Fatalf("%+v", second)
	}
	last := w.roll(start.Add(2500*time.Millisecond), true)
	if last.StopReason != "MONITOR_STOPPED" {
		t.Fatal(last.StopReason)
	}
}
func TestTrafficMonitorQueueRestartAndBackpressure(t *testing.T) {
	path := t.TempDir() + "/state.json"
	q := &trafficMonitorQueue{path: path, state: trafficMonitorState{MonitorID: "monitor"}}
	for i := 0; i < 70; i++ {
		if err := q.enqueue("RUNNING", newTrafficSummary(monitorFixture().Capture, time.Now()), ""); err != nil {
			t.Fatal(err)
		}
	}
	if len(q.state.Pending) != 64 || q.state.DroppedWindows != 6 || q.state.Sequence != 70 {
		t.Fatalf("%+v", q.state)
	}
	restored, err := loadTrafficMonitorQueue(path, "monitor")
	if err != nil {
		t.Fatal(err)
	}
	if err = restored.enqueue("STOPPED", newTrafficSummary(monitorFixture().Capture, time.Now()), ""); err != nil {
		t.Fatal(err)
	}
	if restored.state.Sequence != 71 || restored.state.Pending[63].DroppedWindows != 7 {
		t.Fatal("restart lost sequence/drop count")
	}
	if _, err = loadTrafficMonitorQueue(path, "other"); err == nil {
		t.Fatal("state reused across monitors")
	}
}

func TestTrafficMonitorDeliveryRetryAndControl(t *testing.T) {
	var sequences []int64
	fail := true
	c := monitorFixture()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer fixture" {
			t.Error("identity not applied")
		}
		if r.Method == "GET" {
			if r.ContentLength != 0 {
				// The platform's strict JSON parser rejects a literal null body.
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			json.NewEncoder(w).Encode(map[string]string{"monitorId": c.MonitorID, "assetId": c.AssetID, "desiredState": "STOPPED"})
			return
		}
		var report TrafficMonitorReport
		if err := json.NewDecoder(r.Body).Decode(&report); err != nil {
			t.Error(err)
		}
		sequences = append(sequences, report.Sequence)
		if fail {
			w.WriteHeader(503)
		}
	}))
	defer server.Close()
	a := &Agent{Config: Config{Server: server.URL}, Client: server.Client(), Identity: Identity{Token: "fixture"}}
	q := &trafficMonitorQueue{path: t.TempDir() + "/queue.json", state: trafficMonitorState{MonitorID: c.MonitorID}}
	if err := q.enqueue("RUNNING", nil, ""); err != nil {
		t.Fatal(err)
	}
	if err := deliverTrafficMonitor(context.Background(), a, q); err == nil {
		t.Fatal("offline delivery accepted")
	}
	if q.first() == nil {
		t.Fatal("failed report discarded")
	}
	fail = false
	if err := deliverTrafficMonitor(context.Background(), a, q); err != nil {
		t.Fatal(err)
	}
	if q.first() != nil || len(sequences) != 2 || sequences[0] != sequences[1] {
		t.Fatal("retry did not preserve dedup identity")
	}
	stop, err := monitorDesiredState(context.Background(), a, c)
	if err != nil || !stop {
		t.Fatalf("stop not honored: %v", err)
	}
	for _, code := range []trafficMonitorHTTPError{401, 403, 404} {
		if !monitorRevoked(code) {
			t.Fatal("revocation ignored")
		}
	}
	if monitorRevoked(trafficMonitorHTTPError(503)) {
		t.Fatal("offline mistaken for revocation")
	}
}
func TestTrafficMonitorPersistenceFailureAndCrash(t *testing.T) {
	q := &trafficMonitorQueue{path: t.TempDir() + "/missing/state.json", state: trafficMonitorState{MonitorID: "monitor"}}
	if q.enqueue("RUNNING", nil, "") == nil || q.state.Sequence != 0 {
		t.Fatal("persistence failure silently accepted")
	}
	q = &trafficMonitorQueue{path: t.TempDir() + "/state.json", state: trafficMonitorState{MonitorID: "monitor"}}
	if err := q.enqueue("RUNNING", nil, ""); err != nil {
		t.Fatal(err)
	}
	restored, err := loadTrafficMonitorQueue(q.path, "monitor")
	if err != nil {
		t.Fatal(err)
	}
	if err = restored.enqueue("RUNNING", nil, ""); err != nil {
		t.Fatal(err)
	}
	if restored.state.DroppedWindows != 1 {
		t.Fatal("interrupted aggregation window not counted")
	}
	if err = restored.enqueue("STOPPED", newTrafficSummary(monitorFixture().Capture, time.Now()), ""); err != nil {
		t.Fatal(err)
	}
	restored, err = loadTrafficMonitorQueue(q.path, "monitor")
	if err != nil {
		t.Fatal(err)
	}
	if err = restored.enqueue("RUNNING", nil, ""); err != nil {
		t.Fatal(err)
	}
	if restored.state.DroppedWindows != 1 {
		t.Fatal("clean shutdown counted as lost window")
	}
}

func TestTrafficMonitorQueueByteBound(t *testing.T) {
	q := &trafficMonitorQueue{path: t.TempDir() + "/state.json", state: trafficMonitorState{MonitorID: "monitor"}}
	s := newTrafficSummary(monitorFixture().Capture, time.Now())
	for i := 0; i < 1000; i++ {
		s.Flows = append(s.Flows, TrafficFlow{SourceIP: "2001:db8:1234:5678:1234:5678:1234:5678", DestinationIP: "2001:db8:1234:5678:1234:5678:1234:5679", SourcePort: 65535, DestinationPort: 65535, Protocol: "TCP", Packets: 100000, WireBytes: 999999999})
	}
	for i := 0; i < 64; i++ {
		if err := q.enqueue("RUNNING", s, ""); err != nil {
			t.Fatal(err)
		}
	}
	b, err := os.ReadFile(q.path)
	if err != nil {
		t.Fatal(err)
	}
	if len(b) > 8<<20 || len(q.state.Pending) >= 64 || q.state.DroppedWindows == 0 {
		t.Fatalf("byte bound not applied: bytes=%d pending=%d dropped=%d", len(b), len(q.state.Pending), q.state.DroppedWindows)
	}
	q.state.Sequence = trafficMonitorMaxSequence
	if q.enqueue("RUNNING", nil, "") == nil {
		t.Fatal("sequence overflow accepted")
	}
}

func TestTrafficMonitorSessionServerStopAndRevocation(t *testing.T) {
	for _, code := range []int{200, 401, 403, 404} {
		t.Run(fmt.Sprint(code), func(t *testing.T) {
			c := monitorFixture()
			c.Capture.DurationSeconds = 1
			polls := 0
			var reports []TrafficMonitorReport
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == "GET" {
					polls++
					if polls > 1 && code != 200 {
						w.WriteHeader(code)
						return
					}
					desired := "RUNNING"
					if polls > 1 {
						desired = "STOPPED"
					}
					json.NewEncoder(w).Encode(map[string]string{"monitorId": c.MonitorID, "assetId": c.AssetID, "desiredState": desired})
					return
				}
				var report TrafficMonitorReport
				if err := json.NewDecoder(r.Body).Decode(&report); err != nil {
					t.Error(err)
				}
				reports = append(reports, report)
			}))
			defer server.Close()
			a := &Agent{Config: Config{Server: server.URL}, Client: server.Client()}
			q := &trafficMonitorQueue{path: t.TempDir() + "/state.json", state: trafficMonitorState{MonitorID: c.MonitorID}}
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			capture := func(ctx context.Context, c TrafficCaptureConfig, emit func(*TrafficSummary) error) error {
				<-ctx.Done()
				s := newTrafficMonitorWindow(c, time.Now())
				return emit(s.roll(time.Now(), true))
			}
			if err := runTrafficMonitorSession(ctx, a, c, q, capture); err != nil {
				t.Fatal(err)
			}
			if code == 200 {
				if len(reports) != 3 || reports[1].Summary == nil || reports[1].Summary.StopReason != "MONITOR_STOPPED" || reports[2].Status != "STOPPED" {
					t.Fatalf("server stop failed: %+v", reports)
				}
			} else if len(reports) != 1 || reports[0].Status != "STOPPED" || reports[0].DroppedWindows != 1 {
				t.Fatalf("revoked terminal failed: %+v", reports)
			}
		})
	}
}

func TestTrafficMonitorRevokedQueueDoesNotBlockTerminal(t *testing.T) {
	for _, controlCode := range []int{200, 401, 403, 404} {
		t.Run(fmt.Sprint(controlCode), func(t *testing.T) {
			c := monitorFixture()
			var accepted []TrafficMonitorReport
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == "GET" {
					if controlCode != 200 {
						w.WriteHeader(controlCode)
						return
					}
					json.NewEncoder(w).Encode(map[string]string{"monitorId": c.MonitorID, "assetId": c.AssetID, "desiredState": "STOPPED"})
					return
				}
				var report TrafficMonitorReport
				if err := json.NewDecoder(r.Body).Decode(&report); err != nil {
					t.Error(err)
				}
				if report.Status != "STOPPED" {
					w.WriteHeader(403)
					return
				}
				accepted = append(accepted, report)
			}))
			defer server.Close()
			q := &trafficMonitorQueue{path: t.TempDir() + "/state.json", state: trafficMonitorState{MonitorID: c.MonitorID}}
			if err := q.enqueue("RUNNING", newTrafficSummary(c.Capture, time.Now()), ""); err != nil {
				t.Fatal(err)
			}
			a := &Agent{Config: Config{Server: server.URL}, Client: server.Client()}
			capture := func(context.Context, TrafficCaptureConfig, func(*TrafficSummary) error) error {
				t.Error("capture started after stop/revocation")
				return nil
			}
			if err := runTrafficMonitorSession(context.Background(), a, c, q, capture); err != nil {
				t.Fatalf("revocation would restart service: %v", err)
			}
			if len(accepted) == 0 || accepted[len(accepted)-1].DroppedWindows < 1 || q.first() != nil {
				t.Fatalf("terminal blocked or loss hidden: accepted=%+v pending=%+v", accepted, q.first())
			}
		})
	}
}

func TestTrafficMonitorRunningReportRevocationStopsCapture(t *testing.T) {
	c := monitorFixture()
	c.Capture.DurationSeconds = 60
	var terminal *TrafficMonitorReport
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" {
			json.NewEncoder(w).Encode(map[string]string{"monitorId": c.MonitorID, "assetId": c.AssetID, "desiredState": "RUNNING"})
			return
		}
		var report TrafficMonitorReport
		if err := json.NewDecoder(r.Body).Decode(&report); err != nil {
			t.Error(err)
		}
		if report.Status != "STOPPED" {
			w.WriteHeader(403)
			return
		}
		terminal = &report
	}))
	defer server.Close()
	q := &trafficMonitorQueue{path: t.TempDir() + "/state.json", state: trafficMonitorState{MonitorID: c.MonitorID}}
	a := &Agent{Config: Config{Server: server.URL}, Client: server.Client()}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	captureStopped := false
	capture := func(ctx context.Context, c TrafficCaptureConfig, emit func(*TrafficSummary) error) error {
		s := newTrafficSummary(c, time.Now())
		s.StopReason = "WINDOW_ELAPSED"
		if err := emit(s); err != nil {
			return err
		}
		<-ctx.Done()
		captureStopped = true
		s = newTrafficSummary(c, time.Now())
		s.StopReason = "MONITOR_STOPPED"
		return emit(s)
	}
	if err := runTrafficMonitorSession(ctx, a, c, q, capture); err != nil {
		t.Fatal(err)
	}
	if !captureStopped || terminal == nil || terminal.DroppedWindows != 2 || terminal.Status != "STOPPED" || q.first() != nil {
		t.Fatalf("revoked capture/terminal incomplete: stopped=%t terminal=%+v", captureStopped, terminal)
	}
}
func TestTrafficMonitorStoppedOfflineKeepsUnauthorizedUnknownQueue(t *testing.T) {
	c := monitorFixture()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" {
			json.NewEncoder(w).Encode(map[string]string{"monitorId": c.MonitorID, "assetId": c.AssetID, "desiredState": "STOPPED"})
			return
		}
		w.WriteHeader(503)
	}))
	defer server.Close()
	q := &trafficMonitorQueue{path: t.TempDir() + "/state.json", state: trafficMonitorState{MonitorID: c.MonitorID}}
	if err := q.enqueue("RUNNING", newTrafficSummary(c.Capture, time.Now()), ""); err != nil {
		t.Fatal(err)
	}
	a := &Agent{Config: Config{Server: server.URL}, Client: server.Client()}
	capture := func(context.Context, TrafficCaptureConfig, func(*TrafficSummary) error) error {
		t.Error("stopped capture restarted")
		return nil
	}
	if runTrafficMonitorSession(context.Background(), a, c, q, capture) == nil {
		t.Fatal("offline failure hidden")
	}
	if len(q.state.Pending) != 2 || q.first().Status != "RUNNING" || q.first().Summary == nil {
		t.Fatal("ordinary offline reports discarded as revoked")
	}
}

func TestTrafficMonitorRevokedTerminalRejectedExitsWithoutRestart(t *testing.T) {
	c := monitorFixture()
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { requests++; w.WriteHeader(401) }))
	defer server.Close()
	q := &trafficMonitorQueue{path: t.TempDir() + "/state.json", state: trafficMonitorState{MonitorID: c.MonitorID}}
	a := &Agent{Config: Config{Server: server.URL}, Client: server.Client()}
	capture := func(context.Context, TrafficCaptureConfig, func(*TrafficSummary) error) error {
		t.Error("revoked capture started")
		return nil
	}
	if err := runTrafficMonitorSession(context.Background(), a, c, q, capture); err != nil {
		t.Fatalf("revocation causes restart: %v", err)
	}
	if requests != 2 || len(q.state.Pending) != 1 || q.first().Status != "STOPPED" {
		t.Fatalf("terminal not retained without retry loop: requests=%d pending=%+v", requests, q.first())
	}
}
