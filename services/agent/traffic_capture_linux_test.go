//go:build linux

package main

import (
	"io"
	"net"
	"os"
	"testing"
	"time"
)

func TestTrafficCaptureActualLoopback(t *testing.T) {
	if os.Getenv("SELFGUARD_CAPTURE_INTEGRATION") != "1" {
		t.Skip("explicit isolated NET_RAW test only")
	}
	conn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	port := conn.LocalAddr().(*net.UDPAddr).Port
	c := TrafficCaptureConfig{Interface: "lo", Protocol: "UDP", Ports: []int{port}, CIDRs: []string{"127.0.0.0/8"}, DurationSeconds: 1, MaxPackets: 100, MaxBytes: 65536, SnapLen: 128}
	s := newTrafficSummary(c, time.Now())
	go func() {
		time.Sleep(200 * time.Millisecond)
		client, e := net.Dial("udp4", conn.LocalAddr().String())
		if e == nil {
			defer client.Close()
			client.Write([]byte("capture-owned-loopback-fixture"))
		}
	}()
	if err = captureTraffic(c, s, io.Discard); err != nil {
		t.Fatal(err)
	}
	if s.Packets != 1 || len(s.Flows) != 1 || s.Flows[0].DestinationPort != port || s.StopReason != "DURATION_ELAPSED" {
		t.Fatalf("actual packet not captured once: %+v", s)
	}
}

func TestTrafficCaptureUsesElapsedWindowNotReportedClock(t *testing.T) {
	if os.Getenv("SELFGUARD_CAPTURE_INTEGRATION") != "1" {
		t.Skip("isolated capture test")
	}
	c := TrafficCaptureConfig{Interface: "lo", Protocol: "UDP", Ports: []int{45679}, DurationSeconds: 1, MaxPackets: 100, MaxBytes: 65536, SnapLen: 128}
	s := newTrafficSummary(c, time.Now().Add(-24*time.Hour))
	started := time.Now()
	if err := captureTraffic(c, s, io.Discard); err != nil {
		t.Fatal(err)
	}
	if time.Since(started) < 800*time.Millisecond || time.Since(started) > 3*time.Second {
		t.Fatal("capture duration incorrectly follows report wall time")
	}
}

func TestTrafficCaptureActualEthernetEgress(t *testing.T) {
	target := os.Getenv("SELFGUARD_CAPTURE_EGRESS_TARGET")
	if target == "" {
		t.Skip("owned internal Ethernet peer required")
	}
	c := TrafficCaptureConfig{Interface: "eth0", Protocol: "UDP", Ports: []int{45678}, CIDRs: []string{target + "/32"}, DurationSeconds: 1, MaxPackets: 100, MaxBytes: 65536, SnapLen: 128}
	s := newTrafficSummary(c, time.Now())
	go func() {
		time.Sleep(200 * time.Millisecond)
		conn, err := net.Dial("udp4", net.JoinHostPort(target, "45678"))
		if err == nil {
			defer conn.Close()
			conn.Write([]byte("owned-egress-fixture"))
		}
	}()
	if err := captureTraffic(c, s, io.Discard); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, f := range s.Flows {
		if f.DestinationIP == target && f.DestinationPort == 45678 {
			found = true
		}
	}
	if !found {
		t.Fatal("outbound traffic on real Ethernet interface was omitted")
	}
}
