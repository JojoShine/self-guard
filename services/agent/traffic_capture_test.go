package main

import (
	"bytes"
	"encoding/binary"
	"net"
	"testing"
	"time"
)

func trafficFrame() []byte {
	b := make([]byte, 14+20+20+12)
	binary.BigEndian.PutUint16(b[12:14], 0x0800)
	b[14] = 0x45
	binary.BigEndian.PutUint16(b[16:18], uint16(len(b)-14))
	b[23] = 6
	copy(b[26:30], net.ParseIP("192.0.2.10").To4())
	copy(b[30:34], net.ParseIP("198.51.100.5").To4())
	binary.BigEndian.PutUint16(b[34:36], 32000)
	binary.BigEndian.PutUint16(b[36:38], 443)
	b[46] = 0x50
	copy(b[54:], "secret-value")
	return b
}
func TestTrafficCaptureScopeAndPrivacy(t *testing.T) {
	cfg := TrafficCaptureConfig{Interface: "lo", Protocol: "TCP", Ports: []int{443}, CIDRs: []string{"192.0.2.0/24"}, DurationSeconds: 2, MaxPackets: 10, MaxBytes: 4096, SnapLen: 128}
	if err := cfg.validate(); err != nil {
		t.Fatal(err)
	}
	s := newTrafficSummary(cfg, time.Now())
	var pcap bytes.Buffer
	if !s.consume(trafficFrame(), time.Now(), &pcap) {
		t.Fatal("matching frame missing")
	}
	if len(s.Flows) != 1 || s.Flows[0].DestinationPort != 443 || pcap.Len() != 0 {
		t.Fatalf("metadata capture incorrect: %+v", s)
	}
	raw := s.Flows[0]
	if raw.SourceIP != "192.0.2.10" || raw.Packets != 1 {
		t.Fatal(raw)
	}
	cfg.Ports = []int{80}
	other := newTrafficSummary(cfg, time.Now())
	if other.consume(trafficFrame(), time.Now(), &pcap) {
		t.Fatal("out of scope port retained")
	}
	cfg.Ports = []int{443}
	cfg.CIDRs = []string{"203.0.113.0/24"}
	other = newTrafficSummary(cfg, time.Now())
	if other.consume(trafficFrame(), time.Now(), &pcap) {
		t.Fatal("out of scope address retained")
	}
}
func TestTrafficCaptureBudgetsAndPCAP(t *testing.T) {
	cfg := TrafficCaptureConfig{Interface: "lo", Protocol: "TCP", Ports: []int{443}, DurationSeconds: 1, MaxPackets: 1, MaxBytes: 4096, SnapLen: 60, IncludePayload: true, RetentionHours: 1}
	if err := cfg.validate(); err != nil {
		t.Fatal(err)
	}
	s := newTrafficSummary(cfg, time.Now())
	var out bytes.Buffer
	writePCAPHeader(&out, cfg.SnapLen)
	if !s.consume(trafficFrame(), time.Now(), &out) || s.consume(trafficFrame(), time.Now(), &out) {
		t.Fatal("packet budget not enforced")
	}
	if out.Len() != 24+16+60 || s.CapturedBytes != 60 || s.Flows[0].WireBytes != uint64(len(trafficFrame())) {
		t.Fatal(out.Len(), s)
	}
	if binary.LittleEndian.Uint32(out.Bytes()[32:36]) != 60 {
		t.Fatal("incorrect pcap captured length")
	}
	for _, invalid := range []TrafficCaptureConfig{{}, {Interface: "lo", Protocol: "TCP", Ports: []int{0}, DurationSeconds: 1, MaxPackets: 1, MaxBytes: 4096, SnapLen: 128}, {Interface: "lo", Protocol: "TCP", Ports: []int{80}, DurationSeconds: 601, MaxPackets: 1, MaxBytes: 4096, SnapLen: 128}} {
		if invalid.validate() == nil {
			t.Fatal("invalid authorization accepted")
		}
	}
}
func TestTrafficCaptureMalformedPackets(t *testing.T) {
	for i := 0; i < len(trafficFrame()); i++ {
		_, ok := decodeTrafficPacket(trafficFrame()[:i])
		if i < 54 && ok {
			t.Fatal("truncated headers accepted", i)
		}
	}
	b := trafficFrame()
	binary.BigEndian.PutUint16(b[20:22], 1)
	if _, ok := decodeTrafficPacket(b); ok {
		t.Fatal("noninitial fragment interpreted as ports")
	}
}

func TestTrafficCaptureDoesNotInterpretFirstFragmentPorts(t *testing.T) {
	b := trafficFrame()
	binary.BigEndian.PutUint16(b[20:22], 0x2000)
	if _, ok := decodeTrafficPacket(b); ok {
		t.Fatal("fragmented datagram interpreted as a complete packet")
	}
}

func TestTrafficCapturePersistsExpiryBeforePacketRead(t *testing.T) {
	dir := t.TempDir()
	s := newTrafficSummary(TrafficCaptureConfig{IncludePayload: true, RetentionHours: 1, SnapLen: 128}, time.Now())
	f, err := initializeTrafficCapture(dir, s)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var retained TrafficSummary
	if err = read(dir+"/summary.json", &retained); err != nil {
		t.Fatal(err)
	}
	if retained.PayloadExpiresAt == nil || retained.PayloadFile != "capture.pcap" || retained.Complete {
		t.Fatal("interrupted capture lacks private cleanup manifest")
	}
	if _, err = initializeTrafficCapture(dir, s); err == nil {
		t.Fatal("existing capture overwritten")
	}
}
