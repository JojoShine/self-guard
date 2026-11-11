//go:build linux

package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"debug/elf"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"golang.org/x/sys/unix"
	"io"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
)

type OpenSSLProfile struct {
	Kind               string `json:"kind"`
	LibraryPath        string `json:"libraryPath"`
	PID                int    `json:"pid"`
	UID                uint32 `json:"uid"`
	StartTicks         string `json:"startTicks"`
	ExecutableSHA256   string `json:"executableSha256"`
	LibrarySHA256      string `json:"librarySha256"`
	ExecutableIdentity string `json:"executableIdentity"`
	LibraryIdentity    string `json:"libraryIdentity"`
}
type observationError struct{ gap string }

func (e *observationError) Error() string { return "process observation unavailable: " + e.gap }
func processStartTicks(pid int) (string, error) {
	raw, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return "", errors.New("target process identity unavailable")
	}
	end := bytes.LastIndex(raw, []byte(") "))
	if end < 0 {
		return "", errors.New("process identity invalid")
	}
	fields := strings.Fields(string(raw[end+2:]))
	if len(fields) < 20 {
		return "", errors.New("process identity incomplete")
	}
	return fields[19], nil
}
func validateObserverPeer(profile OpenSSLProfile, pid int, uid uint32) error {
	if profile.PID != pid || profile.UID != uid {
		return errors.New("observer peer not authorized")
	}
	start, err := processStartTicks(pid)
	if err != nil || start != profile.StartTicks {
		return &observationError{gap: "PROBE_PROFILE_MISMATCH"}
	}
	return nil
}
func fileIdentity(stat *syscall.Stat_t) string {
	return fmt.Sprintf("%d:%d:%d:%d:%d", stat.Dev, stat.Ino, stat.Size, stat.Mtim.Sec*1000000000+stat.Mtim.Nsec, stat.Ctim.Sec*1000000000+stat.Ctim.Nsec)
}
func fingerprintFile(path string) (string, string, *syscall.Stat_t, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", "", nil, errors.New("approved runtime file unavailable")
	}
	defer f.Close()
	before, err := f.Stat()
	if err != nil || !before.Mode().IsRegular() || before.Size() > 64<<20 {
		return "", "", nil, errors.New("approved runtime file invalid or exceeds inspection budget")
	}
	stat, ok := before.Sys().(*syscall.Stat_t)
	if !ok {
		return "", "", nil, errors.New("runtime identity unavailable")
	}
	hash := sha256.New()
	if _, err = io.Copy(hash, io.LimitReader(f, 64<<20+1)); err != nil {
		return "", "", nil, err
	}
	after, err := f.Stat()
	if err != nil {
		return "", "", nil, err
	}
	afterStat, ok := after.Sys().(*syscall.Stat_t)
	if !ok || fileIdentity(stat) != fileIdentity(afterStat) {
		return "", "", nil, errors.New("runtime file changed during inspection")
	}
	return hex.EncodeToString(hash.Sum(nil)), fileIdentity(stat), stat, nil
}
func inspectOpenSSLProcess(pid int, library string) (OpenSSLProfile, error) {
	var profile OpenSSLProfile
	start, err := processStartTicks(pid)
	if err != nil {
		return profile, err
	}
	status, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		return profile, err
	}
	var uid uint64
	found := false
	for _, line := range strings.Split(string(status), "\n") {
		if strings.HasPrefix(line, "Uid:") {
			fields := strings.Fields(line)
			if len(fields) >= 3 {
				if fields[1] != fields[2] {
					return profile, errors.New("setuid process requires a separate reviewed adapter")
				}
				uid, err = strconv.ParseUint(fields[2], 10, 32)
				found = err == nil
			}
			break
		}
	}
	if !found {
		return profile, errors.New("target process UID unavailable")
	}
	exeHash, exeIdentity, _, err := fingerprintFile(fmt.Sprintf("/proc/%d/exe", pid))
	if err != nil {
		return profile, err
	}
	libHash, libIdentity, stat, err := fingerprintFile(library)
	if err != nil {
		return profile, err
	}
	object, err := elf.Open(library)
	if err != nil {
		return profile, errors.New("approved library must be an ELF shared object")
	}
	if object.Class != elf.ELFCLASS64 || object.Data != elf.ELFDATA2LSB {
		object.Close()
		return profile, errors.New("observer supports reviewed 64-bit little-endian runtimes only")
	}
	symbols, err := object.DynamicSymbols()
	object.Close()
	if err != nil {
		return profile, err
	}
	hooks := map[string]bool{}
	for _, symbol := range symbols {
		hooks[symbol.Name] = true
	}
	if !hooks["SSL_read"] || !hooks["SSL_write"] || !hooks["SSL_free"] || !hooks["SSL_read_ex"] || !hooks["SSL_write_ex"] || !hooks["SSL_set_fd"] || !hooks["SSL_set_rfd"] || !hooks["SSL_set_wfd"] {
		return profile, errors.New("library lacks the reviewed OpenSSL entry points")
	}
	maps, err := os.ReadFile(fmt.Sprintf("/proc/%d/maps", pid))
	if err != nil {
		return profile, errors.New("target library mapping cannot be verified")
	}
	mapped := false
	for _, line := range strings.Split(string(maps), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 5 {
			continue
		}
		dev := strings.Split(fields[3], ":")
		if len(dev) != 2 {
			continue
		}
		major, e1 := strconv.ParseUint(dev[0], 16, 32)
		minor, e2 := strconv.ParseUint(dev[1], 16, 32)
		inode, e3 := strconv.ParseUint(fields[4], 10, 64)
		if e1 == nil && e2 == nil && e3 == nil && major == uint64(unix.Major(stat.Dev)) && minor == uint64(unix.Minor(stat.Dev)) && inode == stat.Ino {
			mapped = true
			break
		}
	}
	if !mapped {
		return profile, errors.New("approved library is not mapped by target process")
	}
	return OpenSSLProfile{Kind: "OPENSSL_DYNAMIC", LibraryPath: library, PID: pid, UID: uint32(uid), StartTicks: start, ExecutableSHA256: exeHash, LibrarySHA256: libHash, ExecutableIdentity: exeIdentity, LibraryIdentity: libIdentity}, nil
}

type observerFrame struct {
	Opcode, Flags                          byte
	PID                                    uint32
	CallID, SSL, Timestamp, Total, Dropped uint64
	Offset                                 uint32
	LocalIP, PeerIP                        net.IP
	LocalPort, PeerPort                    int
	ProfileTag                             [16]byte
	Data                                   []byte
}

func decodeObserverFrame(raw []byte) (observerFrame, error) {
	var f observerFrame
	if len(raw) < 120 || string(raw[:4]) != "SGO1" || raw[4] != 1 {
		return f, errors.New("observer frame version invalid")
	}
	f.Opcode = raw[5]
	f.Flags = raw[6]
	f.PID = binary.LittleEndian.Uint32(raw[8:])
	f.CallID = binary.LittleEndian.Uint64(raw[16:])
	f.SSL = binary.LittleEndian.Uint64(raw[24:])
	f.Timestamp = binary.LittleEndian.Uint64(raw[32:])
	f.Total = binary.LittleEndian.Uint64(raw[40:])
	f.Offset = binary.LittleEndian.Uint32(raw[48:])
	size := binary.LittleEndian.Uint32(raw[52:])
	f.Dropped = binary.LittleEndian.Uint64(raw[56:])
	f.LocalPort = int(binary.LittleEndian.Uint16(raw[66:]))
	f.PeerPort = int(binary.LittleEndian.Uint16(raw[68:]))
	if raw[64] == 4 {
		f.LocalIP = net.IP(append([]byte{}, raw[70:74]...))
	} else if raw[64] == 6 {
		f.LocalIP = net.IP(append([]byte{}, raw[70:86]...))
	}
	if raw[65] == 4 {
		f.PeerIP = net.IP(append([]byte{}, raw[86:90]...))
	} else if raw[65] == 6 {
		f.PeerIP = net.IP(append([]byte{}, raw[86:102]...))
	}
	copy(f.ProfileTag[:], raw[102:118])
	if f.Opcode < 1 || f.Opcode > 4 || size > 16384 || int(size) != len(raw)-120 || f.Total > 1<<40 || uint64(f.Offset)+uint64(size) > f.Total {
		return f, errors.New("observer frame bounds invalid")
	}
	if f.Flags != 0 && size != 0 {
		return f, errors.New("observer gap frame contains unexpected bytes")
	}
	f.Data = append([]byte{}, raw[120:]...)
	return f, nil
}

type observerCall struct {
	total    uint64
	parts    map[uint32][]byte
	received uint64
	frame    observerFrame
	created  time.Time
}

func newObserverCall(total uint64) *observerCall {
	return &observerCall{total: total, parts: map[uint32][]byte{}, created: time.Now()}
}
func (c *observerCall) add(offset uint32, data []byte) (bool, []byte, error) {
	if c.total > 1<<20 || uint64(offset)+uint64(len(data)) > c.total {
		return false, nil, errors.New("observer call exceeds memory budget")
	}
	if old, ok := c.parts[offset]; ok {
		if !bytes.Equal(old, data) {
			return false, nil, errors.New("observer chunk conflict")
		}
		return false, nil, nil
	}
	for start, old := range c.parts {
		if uint64(offset) < uint64(start)+uint64(len(old)) && uint64(start) < uint64(offset)+uint64(len(data)) {
			return false, nil, errors.New("observer chunks overlap")
		}
	}
	c.parts[offset] = append([]byte{}, data...)
	c.received += uint64(len(data))
	if c.received != c.total {
		return false, nil, nil
	}
	body := make([]byte, c.total)
	for start, part := range c.parts {
		copy(body[int(start):], part)
	}
	return true, body, nil
}
func profileTag(profile OpenSSLProfile) ([16]byte, error) {
	var tag [16]byte
	a, e1 := hex.DecodeString(profile.ExecutableSHA256)
	b, e2 := hex.DecodeString(profile.LibrarySHA256)
	if e1 != nil || e2 != nil || len(a) != 32 || len(b) != 32 {
		return tag, errors.New("runtime profile hash invalid")
	}
	copy(tag[:8], a[:8])
	copy(tag[8:], b[:8])
	return tag, nil
}
func observerPeer(conn *net.UnixConn) (int, uint32, error) {
	raw, err := conn.SyscallConn()
	if err != nil {
		return 0, 0, err
	}
	var credential *unix.Ucred
	var socketErr error
	if err = raw.Control(func(fd uintptr) {
		credential, socketErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	}); err != nil {
		return 0, 0, err
	}
	if socketErr != nil || credential == nil {
		return 0, 0, errors.New("observer peer credentials unavailable")
	}
	return int(credential.Pid), credential.Uid, nil
}
func observeOpenSSL(ctx context.Context, path string, c ProbeConfiguration, factory func() *Exchange, emit func(*Exchange) error, gap func(string), once bool) error {
	if c.Profile.Kind != "OPENSSL_DYNAMIC" {
		return &observationError{gap: "PROBE_PROFILE_MISMATCH"}
	}
	if err := validateObserverPeer(c.Profile, c.Profile.PID, c.Profile.UID); err != nil {
		return err
	}
	tag, err := profileTag(c.Profile)
	if err != nil {
		return err
	}
	parent := filepath.Dir(path)
	if !filepath.IsAbs(path) || len(path) > 100 {
		return errors.New("observer socket path invalid")
	}
	if err = os.MkdirAll(parent, 0755); err != nil {
		return err
	}
	info, err := os.Lstat(parent)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0022 != 0 {
		return errors.New("observer socket directory must be controlled by its operator")
	}
	if old, err := os.Lstat(path); err == nil {
		stat, ok := old.Sys().(*syscall.Stat_t)
		if !ok || old.Mode()&os.ModeSocket == 0 || stat.Uid != uint32(os.Geteuid()) {
			return errors.New("existing observer socket not owned by probe")
		}
		if err = os.Remove(path); err != nil {
			return err
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	listener, err := net.ListenUnix("unixpacket", &net.UnixAddr{Name: path, Net: "unixpacket"})
	if err != nil {
		return err
	}
	defer listener.Close()
	if err = os.Chmod(path, 0600); err != nil {
		return err
	}
	f := &streamFactory{configuration: c, factory: factory, emit: emit, gap: gap}
	sessions := map[uint64]*accessStream{}
	calls := map[uint64]*observerCall{}
	completed := map[uint64]uint64{}
	defer func() {
		for _, session := range sessions {
			session.close(nil)
		}
		f.wg.Wait()
	}()
	partial := func(call *observerCall) error {
		frame := call.frame
		e := factory()
		e.EventID = sourceUUID(fmt.Sprintf("%s|%s|fragment|%d", c.ID, c.Profile.StartTicks, frame.CallID))
		e.SessionID = sourceUUID(fmt.Sprintf("%s|%s|%d", c.ID, c.Profile.StartTicks, frame.SSL))
		e.Operation = "OBSERVATION_FRAGMENT"
		e.Completeness = "PARTIAL"
		e.gap("CAPTURE_LOSS")
		e.gap("CORRELATION_UNKNOWN")
		if frame.Total > 1<<20 {
			e.gap("RESOURCE_LIMIT")
		}
		at := time.Unix(0, int64(frame.Timestamp))
		e.StartedAt = at.UTC().Format(time.RFC3339Nano)
		e.EndedAt = e.StartedAt
		e.captureTime = func(string) time.Time { return at }
		offsets := make([]int, 0, len(call.parts))
		for offset := range call.parts {
			offsets = append(offsets, int(offset))
		}
		sort.Ints(offsets)
		target := e.request
		localTarget := frame.LocalPort == c.Port && frame.LocalIP.Equal(net.ParseIP(c.Address))
		if (frame.Opcode == 1 && !localTarget) || (frame.Opcode == 2 && localTarget) {
			target = e.response
			e.ResponseBytes = int64(frame.Total)
		} else {
			e.RequestBytes = int64(frame.Total)
		}
		for _, offset := range offsets {
			part := call.parts[uint32(offset)]
			if _, err := target.Write(part); err != nil {
				return err
			}
			e.Fragments = append(e.Fragments, Fragment{Offset: uint64(offset), Bytes: len(part), CallID: strconv.FormatUint(frame.CallID, 10)})
		}
		tls := true
		e.TLS = &tls
		return emit(e)
	}
	var lastDropped uint64
	for {
		if ctx.Err() != nil {
			return nil
		}
		listener.SetDeadline(time.Now().Add(time.Second))
		conn, err := listener.AcceptUnix()
		if err != nil {
			if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
				if start, checkErr := processStartTicks(c.Profile.PID); checkErr != nil {
					return &observationError{gap: "PROBE_STOPPED"}
				} else if start != c.Profile.StartTicks {
					return &observationError{gap: "PROBE_PROFILE_MISMATCH"}
				}
				continue
			}
			return err
		}
		_, uid, err := observerPeer(conn)
		if err != nil || uid != 0 {
			conn.Close()
			continue
		}
		if err = validateObserverPeer(c.Profile, c.Profile.PID, c.Profile.UID); err != nil {
			conn.Close()
			return err
		}
		conn.SetReadBuffer(1 << 20)
		raw := make([]byte, 120+16384)
		for {
			if ctx.Err() != nil {
				conn.Close()
				return nil
			}
			conn.SetReadDeadline(time.Now().Add(time.Second))
			n, _, flags, _, readErr := conn.ReadMsgUnix(raw, nil)
			if readErr != nil {
				if timeout, ok := readErr.(net.Error); ok && timeout.Timeout() {
					for id, call := range calls {
						if time.Since(call.created) > 2*time.Second {
							gap("CAPTURE_LOSS")
							if err = partial(call); err != nil {
								conn.Close()
								return err
							}
							if session := sessions[call.frame.SSL]; session != nil {
								session.mu.Lock()
								session.gaps["CAPTURE_LOSS"] = true
								session.mu.Unlock()
								session.close(io.ErrUnexpectedEOF)
							}
							delete(calls, id)
						}
					}
					continue
				}
				conn.Close()
				for id, call := range calls {
					gap("CAPTURE_LOSS")
					if err = partial(call); err != nil {
						return err
					}
					delete(calls, id)
				}
				for ssl, session := range sessions {
					session.mu.Lock()
					session.gaps["DISCONNECTED"] = true
					session.mu.Unlock()
					session.close(io.ErrUnexpectedEOF)
					delete(sessions, ssl)
				}
				clear(completed)
				if !once {
					gap("PROBE_STOPPED")
				}
				if once {
					return nil
				}
				break
			}
			if flags&syscall.MSG_TRUNC != 0 {
				gap("CAPTURE_LOSS")
				continue
			}
			frame, err := decodeObserverFrame(raw[:n])
			if err != nil {
				gap("PARSE_ERROR")
				continue
			}
			if int(frame.PID) != c.Profile.PID || frame.ProfileTag != tag {
				gap("PROBE_PROFILE_MISMATCH")
				conn.Close()
				return &observationError{gap: "PROBE_PROFILE_MISMATCH"}
			}
			if frame.Dropped > lastDropped {
				lastDropped = frame.Dropped
				gap("CAPTURE_LOSS")
				for _, s := range sessions {
					s.mu.Lock()
					s.gaps["CAPTURE_LOSS"] = true
					s.mu.Unlock()
				}
			}
			if frame.Opcode == 4 && frame.Flags == 16 {
				if c.onPlaintext != nil {
					c.onPlaintext(frame.Dropped)
				}
				continue
			}
			if frame.Flags&2 != 0 {
				gap("PROBE_PROFILE_MISMATCH")
				continue
			}
			if frame.Flags != 0 || frame.Opcode == 4 {
				lastDropped++
				gap("CAPTURE_LOSS")
				for _, s := range sessions {
					s.mu.Lock()
					s.gaps["CAPTURE_LOSS"] = true
					s.mu.Unlock()
				}
				if frame.Flags&32 != 0 {
					gap("CAPTURE_LOSS")
				} else if frame.Flags&(4|8) != 0 {
					gap("PROTOCOL_UNSUPPORTED")
				} else {
					gap("RESOURCE_LIMIT")
				}
				continue
			}
			if frame.Opcode == 3 {
				if session := sessions[frame.SSL]; session != nil {
					session.client.close(nil)
					session.server.close(nil)
					delete(sessions, frame.SSL)
					delete(completed, frame.SSL)
				}
				continue
			}
			localTarget := frame.LocalPort == c.Port && frame.LocalIP.Equal(net.ParseIP(c.Address))
			peerTarget := frame.PeerPort == c.Port && frame.PeerIP.Equal(net.ParseIP(c.Address))
			if !localTarget && !peerTarget {
				continue
			}
			if frame.CallID <= completed[frame.SSL] {
				continue
			}
			call := calls[frame.CallID]
			if call == nil {
				if len(calls) >= 64 {
					gap("RESOURCE_LIMIT")
					continue
				}
				call = newObserverCall(frame.Total)
				call.frame = frame
				calls[frame.CallID] = call
			}
			if call.total != frame.Total || call.frame.SSL != frame.SSL || call.frame.Opcode != frame.Opcode {
				gap("PARSE_ERROR")
				continue
			}
			complete, body, err := call.add(frame.Offset, frame.Data)
			if err != nil {
				gap("RESOURCE_LIMIT")
				call.parts[frame.Offset] = append([]byte{}, frame.Data...)
				completed[frame.SSL] = frame.CallID
				if err = partial(call); err != nil {
					conn.Close()
					return err
				}
				delete(calls, frame.CallID)
				continue
			}
			if !complete {
				continue
			}
			delete(calls, frame.CallID)
			completed[frame.SSL] = frame.CallID
			session := sessions[frame.SSL]
			if session == nil {
				if len(sessions) >= 64 {
					gap("RESOURCE_LIMIT")
					continue
				}
				ip, port := frame.PeerIP, frame.PeerPort
				if peerTarget {
					ip, port = frame.LocalIP, frame.LocalPort
				}
				session = &accessStream{owner: f, client: newStreamReader(), server: newStreamReader(), sourceIP: ip.String(), sourcePort: port, firstClient: true, firstAt: time.Unix(0, int64(frame.Timestamp)), session: sourceUUID(fmt.Sprintf("%s|%s|%d|%d|%d", c.ID, c.Profile.StartTicks, frame.SSL, frame.CallID, frame.Timestamp)), gaps: map[string]bool{}}
				if lastDropped > 0 {
					session.gaps["CAPTURE_LOSS"] = true
				}
				sessions[frame.SSL] = session
				session.startDecoder()
			}
			reader := session.client
			if (frame.Opcode == 1 && peerTarget) || (frame.Opcode == 2 && localTarget) {
				reader = session.server
			}
			if !reader.push(body, time.Unix(0, int64(frame.Timestamp))) {
				gap("RESOURCE_LIMIT")
				session.close(io.ErrUnexpectedEOF)
			}
			if c.onPlaintext != nil {
				c.onPlaintext(frame.Dropped)
			}
		}
	}
}
