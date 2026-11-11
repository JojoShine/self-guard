//go:build linux

package main

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
	"golang.org/x/sys/unix"
)

type CaptureConfiguration struct {
	Interface string `json:"interface"`
	Address   string `json:"address"`
	Port      int    `json:"port"`
	Output    string `json:"output"`
	Stats     string `json:"stats"`
}
type CaptureStatistics struct {
	Packets   uint64    `json:"packets"`
	Dropped   uint64    `json:"dropped"`
	UpdatedAt time.Time `json:"updatedAt"`
	Gap       string    `json:"gap"`
}

func selectedPacket(data []byte, c CaptureConfiguration) bool {
	packet := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.NoCopy)
	network := packet.NetworkLayer()
	if network == nil {
		return false
	}
	tcp, ok := packet.TransportLayer().(*layers.TCP)
	if !ok {
		return false
	}
	src, dst := network.NetworkFlow().Endpoints()
	target := net.ParseIP(c.Address)
	return net.ParseIP(src.String()).Equal(target) && int(tcp.SrcPort) == c.Port || net.ParseIP(dst.String()).Equal(target) && int(tcp.DstPort) == c.Port
}
func trustedCaptureConfiguration(path string) (CaptureConfiguration, error) {
	var c CaptureConfiguration
	info, err := os.Lstat(path)
	if err != nil {
		return c, errors.New("capture configuration unavailable")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || stat.Uid != 0 || info.Mode().Perm()&0022 != 0 || info.Size() > 8192 {
		return c, errors.New("capture configuration must be root-owned and immutable to decoder")
	}
	f, err := os.Open(path)
	if err != nil {
		return c, err
	}
	defer f.Close()
	d := json.NewDecoder(f)
	d.DisallowUnknownFields()
	if err = d.Decode(&c); err != nil {
		return c, errors.New("capture configuration invalid")
	}
	if net.ParseIP(c.Address) == nil || c.Port < 1 || c.Port > 65535 || c.Interface == "" || c.Stats == "" || c.Output == "" {
		return c, errors.New("explicit capture endpoint and private output required")
	}
	return c, nil
}
func runPacketCapture(path string) error {
	c, err := trustedCaptureConfiguration(path)
	if err != nil {
		return err
	}
	iface, err := net.InterfaceByName(c.Interface)
	if err != nil {
		return errors.New("capture interface unavailable")
	}
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW|unix.SOCK_CLOEXEC, int(htons(unix.ETH_P_ALL)))
	if err != nil {
		return errors.New("authorized capture capability unavailable")
	}
	defer unix.Close(fd)
	if err = unix.Bind(fd, &unix.SockaddrLinklayer{Protocol: htons(unix.ETH_P_ALL), Ifindex: iface.Index}); err != nil {
		return err
	}
	if err = unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &unix.Timeval{Usec: 100000}); err != nil {
		return err
	}
	if err = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUF, 8<<20); err != nil {
		return err
	}
	info, err := os.Lstat(c.Output)
	if err != nil || info.Mode()&os.ModeNamedPipe == 0 {
		return errors.New("capture output must be an operator-created private FIFO")
	}
	// A separate unprivileged decoder owns neither this socket nor the capture configuration.
	out, err := os.OpenFile(c.Output, os.O_WRONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	defer out.Close()
	writer := pcapgo.NewWriterNanos(out)
	if err = writer.WriteFileHeader(262144, layers.LinkTypeEthernet); err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	var stats CaptureStatistics
	persist := func() error {
		value, e := unix.GetsockoptTpacketStats(fd, unix.SOL_PACKET, unix.PACKET_STATISTICS)
		if e != nil {
			return errors.New("capture loss counters unavailable")
		}
		stats.Dropped += uint64(value.Drops)
		stats.UpdatedAt = time.Now().UTC()
		if stats.Dropped > 0 {
			stats.Gap = "CAPTURE_LOSS"
		}
		raw, e := json.Marshal(stats)
		if e != nil {
			return e
		}
		// Parent directory is created by the installer, root-owned and not decoder-writable.
		file, e := os.CreateTemp(filepath.Dir(c.Stats), ".capture-stats-")
		if e != nil {
			return e
		}
		defer os.Remove(file.Name())
		if e = file.Chmod(0644); e != nil {
			file.Close()
			return e
		}
		_, e = file.Write(raw)
		closeErr := file.Close()
		if e != nil {
			return e
		}
		if closeErr != nil {
			return closeErr
		}
		return os.Rename(file.Name(), c.Stats)
	}
	if err = persist(); err != nil {
		return err
	}
	last := time.Now()
	data := make([]byte, 262144)
	for ctx.Err() == nil {
		if time.Since(last) >= time.Second {
			if err = persist(); err != nil {
				return err
			}
			last = time.Now()
		}
		n, from, e := unix.Recvfrom(fd, data, unix.MSG_TRUNC)
		if e == unix.EAGAIN || e == unix.EINTR {
			continue
		}
		if e != nil {
			return e
		}
		if link, ok := from.(*unix.SockaddrLinklayer); ok && iface.Flags&net.FlagLoopback != 0 && link.Pkttype == unix.PACKET_OUTGOING {
			continue
		}
		captured := min(n, len(data))
		if !selectedPacket(data[:captured], c) {
			continue
		}
		stats.Packets++
		at := time.Now()
		if err = writer.WritePacket(gopacket.CaptureInfo{Timestamp: at, CaptureLength: captured, Length: n}, data[:captured]); err != nil {
			return errors.New("capture decoder disconnected")
		}
	}
	return persist()
}
func htons(value uint16) uint16 {
	var b [2]byte
	binary.BigEndian.PutUint16(b[:], value)
	return binary.NativeEndian.Uint16(b[:])
}
