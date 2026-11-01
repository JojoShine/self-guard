package main

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"time"
)

// Capture is an explicit, finite administrative operation, never a collector privilege.
type TrafficCaptureConfig struct {
	Interface       string   `json:"interface"`
	Protocol        string   `json:"protocol"`
	Ports           []int    `json:"ports"`
	CIDRs           []string `json:"cidrs"`
	DurationSeconds int      `json:"durationSeconds"`
	MaxPackets      int      `json:"maxPackets"`
	MaxBytes        int      `json:"maxBytes"`
	SnapLen         int      `json:"snapLen"`
	IncludePayload  bool     `json:"includePayload"`
	RetentionHours  int      `json:"retentionHours"`
}
type TrafficFlow struct {
	SourceIP        string `json:"sourceIp"`
	SourcePort      int    `json:"sourcePort"`
	DestinationIP   string `json:"destinationIp"`
	DestinationPort int    `json:"destinationPort"`
	Protocol        string `json:"protocol"`
	Packets         int    `json:"packets"`
	WireBytes       uint64 `json:"wireBytes"`
}
type TrafficSummary struct {
	Schema           string               `json:"schema"`
	StartedAt        time.Time            `json:"startedAt"`
	EndedAt          time.Time            `json:"endedAt"`
	Scope            TrafficCaptureConfig `json:"scope"`
	Flows            []TrafficFlow        `json:"flows"`
	Packets          int                  `json:"packets"`
	ExaminedPackets  int                  `json:"examinedPackets"`
	CapturedBytes    int                  `json:"capturedBytes"`
	SocketDropped    uint32               `json:"socketDropped"`
	Complete         bool                 `json:"complete"`
	StopReason       string               `json:"stopReason"`
	PayloadFile      string               `json:"payloadFile,omitempty"`
	PayloadExpiresAt *time.Time           `json:"payloadExpiresAt,omitempty"`
	Decryption       string               `json:"decryption"`
	networks         []*net.IPNet
	flowIndex        map[string]int
}

func (c TrafficCaptureConfig) validate() error {
	if !regexp.MustCompile(`^[A-Za-z0-9_.:-]{1,15}$`).MatchString(c.Interface) || (c.Protocol != "TCP" && c.Protocol != "UDP" && c.Protocol != "TCP_UDP") || len(c.Ports) < 1 || len(c.Ports) > 16 || len(c.CIDRs) > 16 || c.DurationSeconds < 1 || c.DurationSeconds > 600 || c.MaxPackets < 1 || c.MaxPackets > 100000 || c.MaxBytes < 4096 || c.MaxBytes > 64<<20 || c.SnapLen < 54 || c.SnapLen > 2048 || (c.RetentionHours < 0 || c.RetentionHours > 24) || (c.IncludePayload && c.RetentionHours < 1) {
		return errors.New("explicit interface, protocol, ports and bounded capture budgets required (1–600 seconds, 1–100000 packets, 4 KiB–64 MiB, 54–2048 snap length; payload retention 1–24 hours)")
	}
	for _, port := range c.Ports {
		if port < 1 || port > 65535 {
			return errors.New("invalid capture port")
		}
	}
	for _, cidr := range c.CIDRs {
		if _, _, err := net.ParseCIDR(cidr); err != nil {
			return errors.New("invalid capture CIDR")
		}
	}
	return nil
}
func newTrafficSummary(c TrafficCaptureConfig, now time.Time) *TrafficSummary {
	s := &TrafficSummary{Schema: "selfguard-traffic-v1", Scope: c, StartedAt: now.UTC(), Flows: []TrafficFlow{}, Decryption: "NONE: encrypted traffic remains opaque; no TLS decryption or HTTP reconstruction", flowIndex: map[string]int{}}
	for _, cidr := range c.CIDRs {
		_, network, err := net.ParseCIDR(cidr)
		if err == nil {
			s.networks = append(s.networks, network)
		}
	}
	return s
}
func decodeTrafficPacket(b []byte) (TrafficFlow, bool) {
	var f TrafficFlow
	if len(b) < 14 {
		return f, false
	}
	kind := binary.BigEndian.Uint16(b[12:14])
	off := 14
	for n := 0; (kind == 0x8100 || kind == 0x88a8) && n < 2; n++ {
		if len(b) < off+4 {
			return f, false
		}
		kind = binary.BigEndian.Uint16(b[off+2 : off+4])
		off += 4
	}
	var proto byte
	switch kind {
	case 0x0800:
		if len(b) < off+20 || b[off]>>4 != 4 {
			return f, false
		}
		ihl := int(b[off]&15) * 4
		length := int(binary.BigEndian.Uint16(b[off+2 : off+4]))
		if ihl < 20 || length < ihl || len(b) < off+length || binary.BigEndian.Uint16(b[off+6:off+8])&0x3fff != 0 {
			return f, false
		}
		b = b[:off+length]
		proto = b[off+9]
		f.SourceIP = net.IP(b[off+12 : off+16]).String()
		f.DestinationIP = net.IP(b[off+16 : off+20]).String()
		off += ihl
	case 0x86dd:
		if len(b) < off+40 || b[off]>>4 != 6 {
			return f, false
		}
		length := int(binary.BigEndian.Uint16(b[off+4 : off+6]))
		if length == 0 || len(b) < off+40+length {
			return f, false
		}
		b = b[:off+40+length]
		proto = b[off+6]
		f.SourceIP = net.IP(b[off+8 : off+24]).String()
		f.DestinationIP = net.IP(b[off+24 : off+40]).String()
		off += 40
		// Extension/fragment headers are deliberately not guessed as transport ports.
	default:
		return f, false
	}
	switch proto {
	case 6:
		if len(b) < off+20 {
			return f, false
		}
		h := int(b[off+12]>>4) * 4
		if h < 20 || len(b) < off+h {
			return f, false
		}
		f.Protocol = "TCP"
	case 17:
		if len(b) < off+8 {
			return f, false
		}
		n := int(binary.BigEndian.Uint16(b[off+4 : off+6]))
		if n < 8 || len(b) < off+n {
			return f, false
		}
		f.Protocol = "UDP"
	default:
		return f, false
	}
	f.SourcePort = int(binary.BigEndian.Uint16(b[off : off+2]))
	f.DestinationPort = int(binary.BigEndian.Uint16(b[off+2 : off+4]))
	return f, true
}
func (s *TrafficSummary) consume(b []byte, now time.Time, pcap io.Writer) bool {
	if s.Packets >= s.Scope.MaxPackets {
		return false
	}
	f, ok := decodeTrafficPacket(b)
	if !ok || (s.Scope.Protocol != "TCP_UDP" && s.Scope.Protocol != f.Protocol) {
		return false
	}
	allowed := false
	for _, port := range s.Scope.Ports {
		if port == f.SourcePort || port == f.DestinationPort {
			allowed = true
		}
	}
	if !allowed {
		return false
	}
	if len(s.networks) > 0 {
		allowed = false
		for _, n := range s.networks {
			if n.Contains(net.ParseIP(f.SourceIP)) || n.Contains(net.ParseIP(f.DestinationIP)) {
				allowed = true
			}
		}
		if !allowed {
			return false
		}
	}
	size := len(b)
	if size > s.Scope.SnapLen {
		size = s.Scope.SnapLen
	}
	if s.CapturedBytes+size > s.Scope.MaxBytes {
		return false
	}
	key := fmt.Sprintf("%s|%s|%d|%s|%d", f.Protocol, f.SourceIP, f.SourcePort, f.DestinationIP, f.DestinationPort)
	index, exists := s.flowIndex[key]
	if !exists {
		if len(s.Flows) >= 1000 {
			s.StopReason = "FLOW_LIMIT"
			return false
		}
		index = len(s.Flows)
		s.flowIndex[key] = index
		s.Flows = append(s.Flows, f)
	}
	if s.Scope.IncludePayload {
		var header [16]byte
		binary.LittleEndian.PutUint32(header[0:4], uint32(now.Unix()))
		binary.LittleEndian.PutUint32(header[4:8], uint32(now.Nanosecond()/1000))
		binary.LittleEndian.PutUint32(header[8:12], uint32(size))
		binary.LittleEndian.PutUint32(header[12:16], uint32(len(b)))
		if _, err := pcap.Write(header[:]); err != nil {
			s.StopReason = "WRITE_FAILED"
			return false
		}
		if _, err := pcap.Write(b[:size]); err != nil {
			s.StopReason = "WRITE_FAILED"
			return false
		}
	}
	s.Flows[index].Packets++
	s.Flows[index].WireBytes += uint64(len(b))
	s.Packets++
	s.CapturedBytes += size
	return true
}
func writePCAPHeader(w io.Writer, snap int) error {
	var b [24]byte
	binary.LittleEndian.PutUint32(b[0:4], 0xa1b2c3d4)
	binary.LittleEndian.PutUint16(b[4:6], 2)
	binary.LittleEndian.PutUint16(b[6:8], 4)
	binary.LittleEndian.PutUint32(b[16:20], uint32(snap))
	binary.LittleEndian.PutUint32(b[20:24], 1)
	_, err := w.Write(b[:])
	return err
}

// Persist the private cleanup manifest before any payload file can exist.
func initializeTrafficCapture(dir string, s *TrafficSummary) (*os.File, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	if len(entries) != 0 {
		return nil, errors.New("use a new empty private capture directory")
	}
	if s.Scope.IncludePayload {
		expiry := s.StartedAt.Add(time.Duration(s.Scope.RetentionHours) * time.Hour)
		s.PayloadFile = "capture.pcap"
		s.PayloadExpiresAt = &expiry
	}
	manifest, err := os.OpenFile(filepath.Join(dir, "summary.json"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return nil, err
	}
	err = json.NewEncoder(manifest).Encode(s)
	if err == nil {
		err = manifest.Sync()
	}
	err = errors.Join(err, manifest.Close())
	if err != nil {
		return nil, err
	}
	if err = syncParent(filepath.Join(dir, "summary.json")); err != nil {
		return nil, err
	}
	if !s.Scope.IncludePayload {
		return nil, nil
	}
	payload, err := os.OpenFile(filepath.Join(dir, "capture.pcap"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return nil, err
	}
	if err = writePCAPHeader(payload, s.Scope.SnapLen); err != nil {
		payload.Close()
		return nil, err
	}
	return payload, nil
}

func runTrafficCapture(configFile, outputDir string, out io.Writer) error {
	if err := executorPlatform(); err != nil {
		return err
	}
	if err := executorTrustedConfig(configFile); err != nil {
		return err
	}
	b, err := readBoundedFile(configFile, 16<<10)
	if err != nil {
		return err
	}
	var cfg TrafficCaptureConfig
	if err = decodeExecutorParameters(b, &cfg); err != nil {
		return err
	}
	if err = cfg.validate(); err != nil {
		return err
	}
	if err = executorTrustedDirectory(outputDir, true); err != nil {
		return errors.New("capture output directory must already exist, root-owned mode 0700, without symlinks")
	}
	summary := newTrafficSummary(cfg, time.Now())
	var payload io.Writer = io.Discard
	file, err := initializeTrafficCapture(outputDir, summary)
	if err != nil {
		return err
	}
	if file != nil {
		defer file.Close()
		payload = file
	}

	err = captureTraffic(cfg, summary, payload)
	summary.EndedAt = time.Now().UTC()
	if err != nil {
		summary.StopReason = "CAPTURE_FAILED"
	}
	summary.Complete = err == nil && summary.StopReason == "DURATION_ELAPSED" && summary.SocketDropped == 0
	if file != nil {
		if syncErr := file.Sync(); syncErr != nil {
			err = errors.Join(err, syncErr)
			summary.Complete = false
			summary.StopReason = "WRITE_FAILED"
		}
	}
	if writeErr := writePrivate(filepath.Join(outputDir, "summary.json"), summary); writeErr != nil {
		return errors.Join(err, writeErr)
	}
	if encodeErr := json.NewEncoder(out).Encode(summary); encodeErr != nil {
		return errors.Join(err, encodeErr)
	}
	return err
}

// Expiry is also checked by the configured host maintenance schedule. Only the
// explicitly named private capture directory is inspected; never recurse.
func expireTrafficCapture(dir string) error {
	if err := executorPlatform(); err != nil {
		return err
	}
	if err := executorTrustedDirectory(dir, true); err != nil {
		return err
	}
	path := filepath.Join(dir, "summary.json")
	if err := executorTrustedConfig(path); err != nil {
		return err
	}
	b, err := readBoundedFile(path, 1<<20)
	if err != nil {
		return err
	}
	var s TrafficSummary
	if err = decodeExecutorParameters(b, &s); err != nil {
		return err
	}
	if s.PayloadFile != "capture.pcap" || s.PayloadExpiresAt == nil || time.Now().Before(*s.PayloadExpiresAt) {
		return errors.New("no expired payload in this capture")
	}
	payload := filepath.Join(dir, "capture.pcap")
	if err = executorTrustedConfig(payload); err != nil {
		return err
	}
	return os.Remove(payload)
}
