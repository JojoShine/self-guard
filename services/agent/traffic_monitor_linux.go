//go:build linux

package main

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"os"
	"syscall"
	"time"
	"unsafe"
)

func lockTrafficMonitor(path string) (func(), error) {
	fd, err := syscall.Open(path, syscall.O_CREAT|syscall.O_RDWR|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), path)
	if err = executorTrustedConfig(path); err != nil {
		f.Close()
		return nil, err
	}
	if err = syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		return nil, errors.New("traffic monitor already running")
	}
	return func() { f.Close() }, nil
}
func trafficMonitorSocketDrops(fd int) (uint32, error) {
	var stats [8]byte
	length := uint32(len(stats))
	_, _, errno := syscall.Syscall6(syscall.SYS_GETSOCKOPT, uintptr(fd), syscall.SOL_PACKET, 6, uintptr(unsafe.Pointer(&stats[0])), uintptr(unsafe.Pointer(&length)), 0)
	if errno != 0 {
		return 0, errors.New("capture loss statistics unavailable")
	}
	return binary.NativeEndian.Uint32(stats[4:]), nil
}
func captureTrafficMonitor(ctx context.Context, c TrafficCaptureConfig, emit func(*TrafficSummary) error) error {
	iface, err := net.InterfaceByName(c.Interface)
	if err != nil {
		return errors.New("capture interface unavailable")
	}
	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW|syscall.SOCK_CLOEXEC, 0)
	if err != nil {
		return errors.New("traffic monitor requires authorized CAP_NET_RAW/root")
	}
	defer syscall.Close(fd)
	if err = attachTrafficMonitorFilter(fd, c); err != nil {
		return err
	}
	if err = syscall.Bind(fd, &syscall.SockaddrLinklayer{Protocol: networkShort(3), Ifindex: iface.Index}); err != nil {
		return err
	}
	if err = syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &syscall.Timeval{Usec: 100000}); err != nil {
		return err
	}
	if err = syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_RCVBUF, 256<<10); err != nil {
		return err
	}
	w := newTrafficMonitorWindow(c, time.Now())
	b := make([]byte, 65536)
	flush := func(now time.Time, stop bool) error {
		if !stop && now.Before(w.deadline) && w.summary.StopReason == "" {
			return nil
		}
		drops, e := trafficMonitorSocketDrops(fd)
		if e != nil {
			return e
		}
		w.summary.SocketDropped = drops
		return emit(w.roll(now, stop))
	}
	for {
		if ctx.Err() != nil {
			return flush(time.Now(), true)
		}
		if err = flush(time.Now(), false); err != nil {
			return err
		}
		n, from, e := syscall.Recvfrom(fd, b, 0)
		if e == syscall.EAGAIN || e == syscall.EINTR {
			continue
		}
		if e != nil {
			return e
		}
		// Settle a full window before consuming this packet into the next one.
		// The same filtered socket stays open across every boundary.
		if err = flush(time.Now(), false); err != nil {
			return err
		}
		if link, ok := from.(*syscall.SockaddrLinklayer); ok && iface.Flags&net.FlagLoopback != 0 && link.Pkttype == syscall.PACKET_OUTGOING {
			continue
		}
		w.consume(b[:n], time.Now())
	}
}
