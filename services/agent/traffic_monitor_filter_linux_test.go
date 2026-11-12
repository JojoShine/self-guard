//go:build linux

package main

import (
	"encoding/binary"
	"syscall"
	"testing"
)

func monitorFilterAccepts(t *testing.T, c TrafficCaptureConfig, frame []byte) bool {
	t.Helper()
	sockets, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_DGRAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer syscall.Close(sockets[0])
	defer syscall.Close(sockets[1])
	if err = attachTrafficMonitorFilter(sockets[1], c); err != nil {
		t.Fatal(err)
	}
	if err = syscall.Sendto(sockets[0], frame, 0, nil); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 65536)
	_, _, err = syscall.Recvfrom(sockets[1], buf, syscall.MSG_DONTWAIT)
	if err == syscall.EAGAIN {
		return false
	}
	if err != nil {
		t.Fatal(err)
	}
	return true
}
func TestTrafficMonitorKernelFilterScope(t *testing.T) {
	c := monitorFixture().Capture
	frame := trafficFrame()
	if !monitorFilterAccepts(t, c, frame) {
		t.Fatal("authorized TCP frame rejected")
	}
	c.Ports = []int{9999}
	if monitorFilterAccepts(t, c, frame) {
		t.Fatal("unauthorized port queued")
	}
	c = monitorFixture().Capture
	c.Protocol = "UDP"
	if monitorFilterAccepts(t, c, frame) {
		t.Fatal("unauthorized protocol queued")
	}
	c = monitorFixture().Capture
	c.CIDRs = []string{"203.0.113.0/24"}
	if monitorFilterAccepts(t, c, frame) {
		t.Fatal("unauthorized network queued")
	}
	c.CIDRs = []string{"192.0.2.0/24"}
	if !monitorFilterAccepts(t, c, frame) {
		t.Fatal("authorized network rejected")
	}
	for depth := 1; depth <= 2; depth++ {
		vlan := append([]byte{}, frame[:12]...)
		for i := 0; i < depth; i++ {
			vlan = append(vlan, 0x81, 0, 0, 1)
		}
		vlan = append(vlan, frame[12:]...)
		if !monitorFilterAccepts(t, c, vlan) {
			t.Fatalf("VLAN %d rejected", depth)
		}
	}
	c.CIDRs = nil
	v6 := make([]byte, 14+40+20)
	binary.BigEndian.PutUint16(v6[12:14], 0x86dd)
	v6[14] = 0x60
	v6[20] = 6
	v6[54] = 1
	binary.BigEndian.PutUint16(v6[56:58], 443)
	if !monitorFilterAccepts(t, c, v6) {
		t.Fatal("IPv6 port rejected")
	}
	c.CIDRs = []string{"2001:db8::/32"}
	v6[22] = 0x20
	v6[23] = 1
	v6[24] = 0xd
	v6[25] = 0xb8
	if !monitorFilterAccepts(t, c, v6) {
		t.Fatal("IPv6 CIDR rejected")
	}
	v6[25] = 0xb9
	if !monitorFilterAccepts(t, c, v6) {
		t.Fatal("IPv6 CIDR must remain a conservative superset for userspace validation")
	}
	c.CIDRs = []string{"192.0.2.0/24"}
	mapped := make([]byte, 14+40+20)
	binary.BigEndian.PutUint16(mapped[12:14], 0x86dd)
	mapped[14] = 0x60
	binary.BigEndian.PutUint16(mapped[18:20], 20)
	mapped[20] = 6
	copy(mapped[22:38], []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 192, 0, 2, 10})
	binary.BigEndian.PutUint16(mapped[56:58], 443)
	mapped[66] = 0x50
	if flow, ok := decodeTrafficPacket(mapped); !ok || flow.SourceIP != "192.0.2.10" || !monitorFilterAccepts(t, c, mapped) {
		t.Fatal("authorized IPv4-mapped IPv6 endpoint narrowed")
	}
	c.CIDRs = []string{}
	c.Ports = []int{}
	for i := 1; i <= 16; i++ {
		c.Ports = append(c.Ports, i)
		c.CIDRs = append(c.CIDRs, "2001:db8::/32")
	}
	monitorFilterAccepts(t, c, v6) // Kernel verifier must accept the largest authorized filter too.
	if _, err := trafficMonitorFilter(c); err != nil {
		t.Fatal("maximum supported scope", err)
	}
}

func TestTrafficMonitorKernelFilterDrainsUnrelatedFloodBeforeQueue(t *testing.T) {
	sockets, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_DGRAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer syscall.Close(sockets[0])
	defer syscall.Close(sockets[1])
	c := monitorFixture().Capture
	if err = attachTrafficMonitorFilter(sockets[1], c); err != nil {
		t.Fatal(err)
	}
	unrelated := trafficFrame()
	binary.BigEndian.PutUint16(unrelated[36:38], 9999)
	for i := 0; i < 20000; i++ {
		if err = syscall.Sendto(sockets[0], unrelated, syscall.MSG_DONTWAIT, nil); err != nil {
			t.Fatalf("unrelated flood entered receive queue at %d: %v", i, err)
		}
	}
	allowed := trafficFrame()
	if err = syscall.Sendto(sockets[0], allowed, syscall.MSG_DONTWAIT, nil); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 2048)
	n, _, err := syscall.Recvfrom(sockets[1], buf, syscall.MSG_DONTWAIT)
	if err != nil || n != len(allowed) || binary.BigEndian.Uint16(buf[36:38]) != 443 {
		t.Fatal("approved boundary packet lost", n, err)
	}
	if _, _, err = syscall.Recvfrom(sockets[1], buf, syscall.MSG_DONTWAIT); err != syscall.EAGAIN {
		t.Fatal("unrelated packet leaked", err)
	}
}
