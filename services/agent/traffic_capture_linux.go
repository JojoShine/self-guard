//go:build linux

package main

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
	"syscall"
	"time"
	"unsafe"
)

func captureTraffic(c TrafficCaptureConfig, s *TrafficSummary, w io.Writer) error {
	iface, err := net.InterfaceByName(c.Interface)
	if err != nil {
		return errors.New("capture interface unavailable")
	}
	// AF_PACKET SOCK_RAW, interface-bound, no promiscuous membership, no transmit.
	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW|syscall.SOCK_CLOEXEC, int(networkShort(3)))
	if err != nil {
		return errors.New("packet capture requires explicitly authorized CAP_NET_RAW/root")
	}
	defer syscall.Close(fd)
	if err = syscall.Bind(fd, &syscall.SockaddrLinklayer{Protocol: networkShort(3), Ifindex: iface.Index}); err != nil {
		return err
	}
	if err = syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &syscall.Timeval{Usec: 100000}); err != nil {
		return err
	}
	if err = syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_RCVBUF, 256<<10); err != nil {
		return err
	}
	deadline := time.Now().Add(time.Duration(c.DurationSeconds) * time.Second)
	b := make([]byte, 65536)
	examinedBytes := 0
	for time.Now().Before(deadline) {
		n, from, err := syscall.Recvfrom(fd, b, 0)
		if err == syscall.EAGAIN || err == syscall.EINTR {
			continue
		}
		if err != nil {
			return err
		}
		// Loopback reports outgoing and incoming copies: retain the incoming copy once.
		if link, ok := from.(*syscall.SockaddrLinklayer); ok && iface.Flags&net.FlagLoopback != 0 && link.Pkttype == syscall.PACKET_OUTGOING {
			continue
		}
		s.ExaminedPackets++
		examinedBytes += n
		s.consume(b[:n], time.Now(), w)
		if s.StopReason != "" {
			break
		}
		if s.Packets >= c.MaxPackets {
			s.StopReason = "PACKET_LIMIT"
			break
		}
		if s.CapturedBytes+c.SnapLen > c.MaxBytes {
			s.StopReason = "BYTE_LIMIT"
			break
		}
		if s.ExaminedPackets >= 200000 || examinedBytes >= 128<<20 {
			s.StopReason = "EXAMINATION_LIMIT"
			break
		}
	}
	if s.StopReason == "" {
		s.StopReason = "DURATION_ELAPSED"
	}
	var stats [8]byte
	length := uint32(len(stats))
	_, _, errno := syscall.Syscall6(syscall.SYS_GETSOCKOPT, uintptr(fd), syscall.SOL_PACKET, 6, uintptr(unsafe.Pointer(&stats[0])), uintptr(unsafe.Pointer(&length)), 0)
	if errno != 0 {
		return errors.New("capture loss statistics unavailable")
	}
	s.SocketDropped = binary.NativeEndian.Uint32(stats[4:8])
	return nil
}
func networkShort(n uint16) uint16 {
	var b [2]byte
	binary.BigEndian.PutUint16(b[:], n)
	return binary.NativeEndian.Uint16(b[:])
}
