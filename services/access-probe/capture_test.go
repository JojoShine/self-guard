package main

import (
	"bytes"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
	"net"
	"testing"
	"time"
)

func TestTCPReassemblyEliminatesRetransmitButKeepsTwoRealRequests(t *testing.T) {
	var pcap bytes.Buffer
	w := pcapgo.NewWriter(&pcap)
	w.WriteFileHeader(65535, layers.LinkTypeEthernet)
	at := time.Now()
	write := func(server bool, seq uint32, syn, fin bool, payload []byte) {
		t.Helper()
		src, dst := net.ParseIP("10.1.0.2").To4(), net.ParseIP("10.1.0.1").To4()
		sp, dp := layers.TCPPort(45000), layers.TCPPort(8080)
		if server {
			src, dst = dst, src
			sp, dp = dp, sp
		}
		eth := &layers.Ethernet{SrcMAC: net.HardwareAddr{1, 2, 3, 4, 5, 6}, DstMAC: net.HardwareAddr{6, 5, 4, 3, 2, 1}, EthernetType: layers.EthernetTypeIPv4}
		ip := &layers.IPv4{Version: 4, IHL: 5, TTL: 64, SrcIP: src, DstIP: dst, Protocol: layers.IPProtocolTCP}
		tcp := &layers.TCP{SrcPort: sp, DstPort: dp, Seq: seq, SYN: syn, FIN: fin, ACK: !syn, Window: 65535}
		tcp.SetNetworkLayerForChecksum(ip)
		buf := gopacket.NewSerializeBuffer()
		if err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, eth, ip, tcp, gopacket.Payload(payload)); err != nil {
			t.Fatal(err)
		}
		if err := w.WritePacket(gopacket.CaptureInfo{Timestamp: at, CaptureLength: len(buf.Bytes()), Length: len(buf.Bytes())}, buf.Bytes()); err != nil {
			t.Fatal(err)
		}
		at = at.Add(time.Millisecond)
	}
	req := []byte("GET /orders HTTP/1.1\r\nHost: fixture\r\n\r\n")
	res := []byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
	write(false, 100, true, false, nil)
	write(true, 200, true, false, nil)
	// Deliberately reorder a split request, then replay its complete TCP segment.
	write(false, 111, false, false, req[10:])
	write(false, 101, false, false, req[:10])
	write(false, 101, false, false, req)
	write(true, 201, false, false, res)
	write(false, 101+uint32(len(req)), false, false, req)
	write(true, 201+uint32(len(res)), false, false, res)
	write(false, 101+uint32(len(req)*2), false, true, nil)
	write(true, 201+uint32(len(res)*2), false, true, nil)
	var events []*Exchange
	err := observePCAP(bytes.NewReader(pcap.Bytes()), ProbeConfiguration{Protocol: "HTTP", Address: "10.1.0.1", Port: 8080}, func() *Exchange { return newExchange(new(bytes.Buffer), new(bytes.Buffer)) }, func(e *Exchange) error { events = append(events, e); return nil }, func(string) {})
	if err != nil || len(events) != 2 {
		t.Fatal("reassembly lost or duplicated visits", len(events), err)
	}
	for _, e := range events {
		if e.Route != "/orders" || e.Completeness != "COMPLETE" {
			t.Fatal("unexpected visit", e.Route, e.Gaps)
		}
	}
	var replay []*Exchange
	err = observePCAP(bytes.NewReader(pcap.Bytes()), ProbeConfiguration{Protocol: "HTTP", Address: "10.1.0.1", Port: 8080}, func() *Exchange { return newExchange(new(bytes.Buffer), new(bytes.Buffer)) }, func(e *Exchange) error { replay = append(replay, e); return nil }, func(string) {})
	if err != nil || len(replay) != 2 || replay[0].EventID != events[0].EventID || replay[1].EventID != events[1].EventID || events[0].EventID == events[1].EventID {
		t.Fatal("stable source offsets required across replay; real repeated requests must stay distinct")
	}
}

func TestCaptureEndWithoutFinCannotCertifyAnEOFDelimitedResponse(t *testing.T) {
	for _, fin := range []bool{false, true} {
		var events []*Exchange
		f := &streamFactory{configuration: ProbeConfiguration{Protocol: "HTTP"}, factory: func() *Exchange { return newExchange(&bytes.Buffer{}, &bytes.Buffer{}) }, emit: func(e *Exchange) error { events = append(events, e); return nil }, gap: func(string) {}}
		s := &accessStream{owner: f, client: newStreamReader(), server: newStreamReader(), firstAt: time.Now(), gaps: map[string]bool{}}
		s.client.push([]byte("GET / HTTP/1.0\r\n\r\n"), time.Now())
		s.server.push([]byte("HTTP/1.0 200 OK\r\n\r\npartial-or-whole"), time.Now())
		if fin {
			s.client.close(nil)
			s.server.close(nil)
		}
		s.startDecoder()
		s.ReassemblyComplete(nil)
		f.wg.Wait()
		if len(events) != 1 {
			t.Fatal("event missing")
		}
		if !fin && events[0].Completeness == "COMPLETE" {
			t.Fatal("capture EOF was confused with real TCP FIN")
		}
		if fin && events[0].Completeness != "COMPLETE" {
			t.Fatal("observed FIN lost completeness", events[0].Gaps)
		}
	}
}

func TestCaptureStopAfterFramedResponseIsAnIdleBoundary(t *testing.T) {
	f := &streamFactory{configuration: ProbeConfiguration{Protocol: "HTTP"}, factory: func() *Exchange { return newExchange(&bytes.Buffer{}, &bytes.Buffer{}) }, emit: func(e *Exchange) error {
		if e.Completeness != "COMPLETE" {
			t.Error("framed response lost completeness", e.Gaps)
		}
		return nil
	}, gap: func(string) {}}
	s := &accessStream{owner: f, client: newStreamReader(), server: newStreamReader(), firstAt: time.Now(), gaps: map[string]bool{}}
	s.client.push([]byte("GET / HTTP/1.1\r\nHost: test\r\n\r\n"), time.Now())
	s.server.push([]byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"), time.Now())
	s.startDecoder()
	s.ReassemblyComplete(nil)
	f.wg.Wait()
	if f.failure != nil {
		t.Fatal("idle stop treated as malformed request", f.failure)
	}
}
