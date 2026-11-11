//go:build linux

package main

import (
	"context"
	"errors"
	"net"
	"os"
	"testing"
	"time"
)

func TestTrafficMonitorActualContinuousWindows(t *testing.T) {
	if os.Getenv("SELFGUARD_CAPTURE_INTEGRATION") != "1" {
		t.Skip("isolated NET_RAW fixture required")
	}
	conn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	port := conn.LocalAddr().(*net.UDPAddr).Port
	c := monitorFixture().Capture
	c.Protocol = "UDP"
	c.Ports = []int{port}
	c.DurationSeconds = 1
	c.MaxPackets = 1
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		client, e := net.Dial("udp4", conn.LocalAddr().String())
		if e != nil {
			return
		}
		defer client.Close()
		ticker := time.NewTicker(50 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				client.Write([]byte("owned metadata fixture"))
			}
		}
	}()
	var windows []*TrafficSummary
	if err = captureTrafficMonitor(ctx, c, func(s *TrafficSummary) error {
		windows = append(windows, s)
		if len(windows) == 3 {
			cancel()
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if len(windows) != 4 {
		t.Fatalf("expected 3 full windows and final flush, got %d", len(windows))
	}
	for _, s := range windows[:3] {
		if s.Packets != 1 || s.StopReason != "PACKET_LIMIT" || s.Complete || s.PayloadFile != "" {
			t.Fatalf("budget stopped monitor or payload recorded: %+v", s)
		}
	}
	if windows[3].StopReason != "MONITOR_STOPPED" {
		t.Fatal(windows[3].StopReason)
	}
}
func TestTrafficMonitorCaptureFailure(t *testing.T) {
	c := monitorFixture().Capture
	c.Interface = "absent-fixture"
	if captureTrafficMonitor(context.Background(), c, func(*TrafficSummary) error { return nil }) == nil {
		t.Fatal("missing interface accepted")
	}
	if os.Getenv("SELFGUARD_CAPTURE_INTEGRATION") != "1" {
		return
	}
	c.Interface = "lo"
	c.DurationSeconds = 1
	expected := errors.New("durability fixture failure")
	if err := captureTrafficMonitor(context.Background(), c, func(*TrafficSummary) error { return expected }); !errors.Is(err, expected) {
		t.Fatalf("queue failure lost: %v", err)
	}
}
