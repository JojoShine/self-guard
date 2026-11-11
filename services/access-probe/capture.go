package main

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
	"github.com/gopacket/gopacket/reassembly"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

type ProbeConfiguration struct {
	ID            string         `json:"id"`
	AssetID       string         `json:"assetId"`
	Protocol      string         `json:"protocol"`
	Mode          string         `json:"mode"`
	Interface     string         `json:"interface"`
	Address       string         `json:"address"`
	Port          int            `json:"port"`
	Enabled       bool           `json:"enabled"`
	Version       int            `json:"version"`
	MaxQueueBytes int64          `json:"maxQueueBytes"`
	Profile       OpenSSLProfile `json:"profile"`
	onPacket      func()
	onPlaintext   func(uint64)
}
type capturedContext struct{ info gopacket.CaptureInfo }

func (c capturedContext) GetCaptureInfo() gopacket.CaptureInfo { return c.info }

type timedBytes struct {
	data []byte
	at   time.Time
}
type streamReader struct {
	mu        sync.Mutex
	condition *sync.Cond
	parts     []timedBytes
	bytes     int
	closed    bool
	err       error
	last      time.Time
}

func newStreamReader() *streamReader {
	r := &streamReader{}
	r.condition = sync.NewCond(&r.mu)
	return r
}
func (r *streamReader) push(data []byte, at time.Time) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return false
	}
	if r.bytes+len(data) > 1<<20 {
		r.closed = true
		r.err = errors.New("RESOURCE_LIMIT")
		r.condition.Broadcast()
		return false
	}
	r.parts = append(r.parts, timedBytes{data: append([]byte{}, data...), at: at})
	r.bytes += len(data)
	r.condition.Signal()
	return true
}
func (r *streamReader) Read(out []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for len(r.parts) == 0 && !r.closed {
		r.condition.Wait()
	}
	if len(r.parts) == 0 {
		if r.err != nil {
			return 0, r.err
		}
		return 0, io.EOF
	}
	p := &r.parts[0]
	n := copy(out, p.data)
	p.data = p.data[n:]
	r.last = p.at
	r.bytes -= n
	if len(p.data) == 0 {
		r.parts = r.parts[1:]
	}
	return n, nil
}
func (r *streamReader) close(err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.closed = true
	if r.err == nil {
		r.err = err
	}
	r.condition.Broadcast()
}
func (r *streamReader) closeIncomplete() {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.closed {
		r.closed = true
		r.err = io.ErrUnexpectedEOF
		r.condition.Broadcast()
	}
}
func (r *streamReader) at() time.Time { r.mu.Lock(); defer r.mu.Unlock(); return r.last }

type streamFactory struct {
	configuration ProbeConfiguration
	factory       func() *Exchange
	emit          func(*Exchange) error
	gap           func(string)
	active        atomic.Int32
	wg            sync.WaitGroup
	mu            sync.Mutex
	failure       error
}
type accessStream struct {
	owner          *streamFactory
	client, server *streamReader
	firstClient    bool
	sourceIP       string
	sourcePort     int
	session        string
	firstAt        time.Time
	ordinal        uint64
	mu             sync.Mutex
	gaps           map[string]bool
	closed         atomic.Bool
	rejected       bool
}

func (f *streamFactory) New(network, transport gopacket.Flow, tcp *layers.TCP, ac reassembly.AssemblerContext) reassembly.Stream {
	firstClient := int(tcp.DstPort) == f.configuration.Port
	s := &accessStream{owner: f, client: newStreamReader(), server: newStreamReader(), firstClient: firstClient, firstAt: ac.GetCaptureInfo().Timestamp, gaps: map[string]bool{}}
	if firstClient {
		s.sourceIP = network.Src().String()
		s.sourcePort = int(tcp.SrcPort)
	} else {
		s.sourceIP = network.Dst().String()
		s.sourcePort = int(tcp.DstPort)
	}
	s.session = sourceUUID(fmt.Sprintf("%s|%s|%d|%s|%d|%d|%d", f.configuration.ID, s.sourceIP, s.sourcePort, f.configuration.Address, f.configuration.Port, s.firstAt.UnixNano(), tcp.Seq))
	if !tcp.SYN {
		s.gaps["MIDSTREAM"] = true
	}
	s.startDecoder()
	return s
}
func (s *accessStream) startDecoder() {
	f := s.owner
	if f.active.Add(1) > 64 {
		s.rejected = true
		f.active.Add(-1)
		f.gap("RESOURCE_LIMIT")
		return
	}
	f.wg.Add(1)
	go func() {
		defer f.wg.Done()
		defer f.active.Add(-1)
		defer s.close(nil)
		err := decodeStreams(f.configuration.Protocol, s.client, s.server, func() *Exchange {
			e := f.factory()
			s.ordinal++
			e.EventID = sourceUUID(fmt.Sprintf("%s|%d", s.session, s.ordinal))
			e.SessionID = s.session
			e.StartedAt = s.firstAt.UTC().Format(time.RFC3339Nano)
			e.SourceIP = s.sourceIP
			e.SourcePort = s.sourcePort
			if f.configuration.Mode == "PLAINTEXT_EVENTS" {
				tls := true
				e.TLS = &tls
			}
			if at := s.client.at(); !at.IsZero() {
				e.StartedAt = at.UTC().Format(time.RFC3339Nano)
			}
			e.captureTime = func(direction string) time.Time {
				if direction == "REQUEST" {
					return s.client.at()
				}
				return s.server.at()
			}
			return e
		}, func(e *Exchange) error {
			s.mu.Lock()
			for code := range s.gaps {
				e.gap(code)
			}
			s.mu.Unlock()
			at := s.server.at()
			if c := s.client.at(); c.After(at) {
				at = c
			}
			if !at.IsZero() {
				e.EndedAt = at.UTC().Format(time.RFC3339Nano)
			}
			return f.emit(e)
		})
		if err != nil {
			f.mu.Lock()
			if f.failure == nil {
				f.failure = err
			}
			f.mu.Unlock()
			f.gap("PARSE_ERROR")
		}
	}()
}
func (s *accessStream) close(err error) {
	s.closed.Store(true)
	s.client.close(err)
	s.server.close(err)
}
func (s *accessStream) Accept(tcp *layers.TCP, ci gopacket.CaptureInfo, direction reassembly.TCPFlowDirection, next reassembly.Sequence, start *bool, ac reassembly.AssemblerContext) bool {
	if s.rejected || s.closed.Load() {
		return false
	}
	if ci.CaptureLength < ci.Length {
		s.mu.Lock()
		s.gaps["CAPTURE_LOSS"] = true
		s.mu.Unlock()
	}
	if !*start {
		*start = true
	}
	return true
}
func (s *accessStream) ReassembledSG(sg reassembly.ScatterGather, ac reassembly.AssemblerContext) {
	if s.rejected || s.closed.Load() {
		return
	}
	direction, _, end, skip := sg.Info()
	if skip != 0 {
		s.mu.Lock()
		code := "CAPTURE_LOSS"
		if skip < 0 {
			code = "MIDSTREAM"
		}
		s.gaps[code] = true
		s.mu.Unlock()
		s.owner.gap(code)
	}
	length, _ := sg.Lengths()
	reader := s.client
	if (direction == reassembly.TCPDirClientToServer) != s.firstClient {
		reader = s.server
	}
	if length > 0 && !reader.push(sg.Fetch(length), sg.CaptureInfo(0).Timestamp) {
		s.mu.Lock()
		s.gaps["RESOURCE_LIMIT"] = true
		s.mu.Unlock()
		s.owner.gap("RESOURCE_LIMIT")
		s.close(errors.New("RESOURCE_LIMIT"))
	}
	if end {
		reader.close(nil)
	}
}
func (s *accessStream) ReassemblyComplete(ac reassembly.AssemblerContext) bool {
	if !s.rejected {
		s.client.closeIncomplete()
		s.server.closeIncomplete()
	}
	return true
}
func observePCAP(input io.Reader, c ProbeConfiguration, factory func() *Exchange, emit func(*Exchange) error, gap func(string)) error {
	reader, err := pcapgo.NewReader(input)
	if err != nil {
		return errors.New("invalid capture stream")
	}
	target := net.ParseIP(c.Address)
	if target == nil || c.Port < 1 || c.Port > 65535 {
		return errors.New("explicit observation endpoint required")
	}
	f := &streamFactory{configuration: c, factory: factory, emit: emit, gap: gap}
	assembler := reassembly.NewAssembler(reassembly.NewStreamPool(f))
	assembler.MaxBufferedPagesPerConnection = 512
	assembler.MaxBufferedPagesTotal = 8192
	var last time.Time
	for {
		data, ci, err := reader.ReadPacketData()
		if err == io.EOF {
			break
		}
		if err != nil {
			assembler.FlushAll()
			f.wg.Wait()
			return errors.New("capture stream interrupted")
		}
		packet := gopacket.NewPacket(data, reader.LinkType(), gopacket.NoCopy)
		network := packet.NetworkLayer()
		if network == nil {
			gap("PROTOCOL_UNSUPPORTED")
			continue
		}
		tcp, ok := packet.TransportLayer().(*layers.TCP)
		if !ok {
			continue
		}
		src, dst := network.NetworkFlow().Endpoints()
		matches := func(address gopacket.Endpoint, port layers.TCPPort) bool {
			return net.ParseIP(address.String()).Equal(target) && int(port) == c.Port
		}
		if !matches(src, tcp.SrcPort) && !matches(dst, tcp.DstPort) {
			continue
		}
		if c.onPacket != nil {
			c.onPacket()
		}
		if ci.CaptureLength < ci.Length {
			gap("CAPTURE_LOSS")
		}
		assembler.AssembleWithContext(network.NetworkFlow(), tcp, capturedContext{info: ci})
		if last.IsZero() || ci.Timestamp.Sub(last) > time.Second {
			assembler.FlushWithOptions(reassembly.FlushOptions{T: ci.Timestamp.Add(-5 * time.Second), TC: ci.Timestamp.Add(-120 * time.Second)})
			last = ci.Timestamp
		}
	}
	assembler.FlushAll()
	f.wg.Wait()
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.failure
}

func sourceUUID(value string) string {
	sum := sha256.Sum256([]byte(value))
	sum[6] = sum[6]&15 | 80
	sum[8] = sum[8]&63 | 128
	return fmt.Sprintf("%x-%x-%x-%x-%x", sum[:4], sum[4:6], sum[6:8], sum[8:10], sum[10:16])
}
