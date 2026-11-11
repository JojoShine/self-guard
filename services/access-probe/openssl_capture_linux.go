//go:build linux

package main

import (
	"bufio"
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"golang.org/x/sys/unix"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
)

type OpenSSLCaptureConfiguration struct {
	ReceiverUID uint32         `json:"receiverUid"`
	Address     string         `json:"address"`
	Port        int            `json:"port"`
	Profile     OpenSSLProfile `json:"profile"`
	Socket      string         `json:"socket"`
}

var lostObserverEvents = regexp.MustCompile(`(?i)lost [1-9][0-9]* events|[1-9][0-9]* events (were )?lost|failed to probe_read`)

const observerFragmentsPerProgram = 7

func checkObserverRuntimeVersion(raw string) error {
	match := regexp.MustCompile(`^bpftrace v([0-9]+)\.([0-9]+)\.([0-9]+)$`).FindStringSubmatch(strings.TrimSpace(raw))
	if len(match) == 4 {
		major, majorErr := strconv.Atoi(match[1])
		minor, minorErr := strconv.Atoi(match[2])
		_, patchErr := strconv.Atoi(match[3])
		if majorErr == nil && minorErr == nil && patchErr == nil && (major > 0 || minor >= 17) {
			return nil
		}
	}
	return errors.New("TLS observer requires bpftrace >= 0.17.0; installing a runtime does not certify the target kernel or database")
}

func checkObserverRuntime() error {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	version, err := exec.CommandContext(ctx, "/usr/bin/bpftrace", "--version").Output()
	if err != nil {
		return errors.New("TLS observer requires an available /usr/bin/bpftrace >= 0.17.0")
	}
	return checkObserverRuntimeVersion(string(version))
}

func openSSLScript(c OpenSSLCaptureConfiguration) (string, error) {
	if c.Profile.PID < 1 || c.Port < 1 || c.Port > 65535 || net.ParseIP(c.Address) == nil {
		return "", errors.New("observer endpoint invalid")
	}
	// Only a mapped, hash-pinned ELF library can appear in the attachment expression.
	library := c.Profile.LibraryPath
	if !strings.HasPrefix(library, "/") || strings.ContainsAny(library, "\"'\n\r:;*?[]{} \\\t") {
		return "", errors.New("observer library path invalid")
	}
	prefix := "uprobe:" + library + ":"
	ret := "uretprobe:" + library + ":"
	guard := fmt.Sprintf(" /pid == %d && uid == %d/ ", c.Profile.PID, c.Profile.UID)
	script := "BEGIN { printf(\"READY\\n\"); }\n"
	for _, binding := range []struct{ name, side string }{{"SSL_set_fd", "rw"}, {"SSL_set_rfd", "r"}, {"SSL_set_wfd", "w"}} {
		script += prefix + binding.name + guard + "{ @bind_ssl[tid]=arg0; @bind_fd[tid]=arg1; }\n"
		script += ret + binding.name + guard + "{ if(retval==1){@generation[@bind_ssl[tid]]=nsecs;"
		if strings.Contains(binding.side, "r") {
			script += "@rfd[@bind_ssl[tid]]=@bind_fd[tid]+1;"
		}
		if strings.Contains(binding.side, "w") {
			script += "@wfd[@bind_ssl[tid]]=@bind_fd[tid]+1;"
		}
		script += "} delete(@bind_ssl[tid]);delete(@bind_fd[tid]);}\n"
	}
	for _, hook := range []struct {
		name, side string
		opcode     int
		extended   bool
	}{{"SSL_read", "r", 1, false}, {"SSL_write", "w", 2, false}, {"SSL_read_ex", "r", 1, true}, {"SSL_write_ex", "w", 2, true}} {
		script += prefix + hook.name + guard + fmt.Sprintf("{ @ptr%d[tid]=arg1;@ssl%d[tid]=arg0;@len%d[tid]=arg2;@out%d[tid]=arg3;@begin%d[tid]=nsecs;@bound%d[tid]=@generation[arg0];}\n", hook.opcode, hook.opcode, hook.opcode, hook.opcode, hook.opcode, hook.opcode)
		// Each verifier program remains below the signed branch-range limit. All
		// pieces share one return timestamp and one descriptor-binding generation.
		// Bound verifier branch exploration without truncating the existing 16 KiB call budget.
		const pieceBytes = observerFragmentsPerProgram * 100
		for piece := 0; piece < (16384+pieceBytes-1)/pieceBytes; piece++ {
			script += ret + hook.name + guard + "{"
			script += fmt.Sprintf("$ssl=@ssl%d[tid];$fd=@%sfd[$ssl]-1;$n=(uint64)retval;$success=(int64)retval>0;", hook.opcode, hook.side)
			if hook.extended {
				script += fmt.Sprintf("$n=(uint64)0;$success=retval==1;if($success){$n=*(uint64*)uptr(@out%d[tid]);}", hook.opcode)
			}
			script += fmt.Sprintf("$entry=@begin%d[tid];if(@returned%d[tid]!=$entry){@when%d[tid]=nsecs;@returned%d[tid]=$entry;}$at=@when%d[tid];$generation=@generation[$ssl];if($success&&($fd<0||$generation==0||@bound%d[tid]!=$generation)){printf(\"UNBOUND\\n\");$success=0;}$connection=$generation^$ssl;", hook.opcode, hook.opcode, hook.opcode, hook.opcode, hook.opcode, hook.opcode)
			// Resolve the current task's socket before any application buffer read. A missing
			// binding, non-socket descriptor or unapproved endpoint cannot expose plaintext.
			script += "if($success && $n>0 && $fd>=0 && $fd<curtask->files->fdt->max_fds){$file=(struct file*)kptr(*(uint64*)kptr((uint64)curtask->files->fdt->fd+$fd*8)); if($file!=0 && ($file->f_inode->i_mode & 61440)==49152){$sock=(struct socket*)kptr($file->private_data);$sk=$sock->sk; if($sk!=0){$family=$sk->__sk_common.skc_family;$lp=$sk->__sk_common.skc_num;$pp=$sk->__sk_common.skc_dport;"
			ip := net.ParseIP(c.Address)
			var match string
			if v4 := ip.To4(); v4 != nil {
				word := binary.NativeEndian.Uint32(v4)
				script += "$l0=$sk->__sk_common.skc_rcv_saddr;$r0=$sk->__sk_common.skc_daddr;$l1=0;$l2=0;$l3=0;$r1=0;$r2=0;$r3=0;"
				match = fmt.Sprintf("$family==2 && (($l0==%d && $lp==%d)||($r0==%d && $pp==%d))", word, c.Port, word, htons(uint16(c.Port)))
			} else {
				script += "$l0=$sk->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32[0];$l1=$sk->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32[1];$l2=$sk->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32[2];$l3=$sk->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32[3];$r0=$sk->__sk_common.skc_v6_daddr.in6_u.u6_addr32[0];$r1=$sk->__sk_common.skc_v6_daddr.in6_u.u6_addr32[1];$r2=$sk->__sk_common.skc_v6_daddr.in6_u.u6_addr32[2];$r3=$sk->__sk_common.skc_v6_daddr.in6_u.u6_addr32[3];"
				left, right := "", ""
				for i := 0; i < 4; i++ {
					word := binary.NativeEndian.Uint32(ip.To16()[i*4:])
					left += fmt.Sprintf("$l%d==%d && ", i, word)
					right += fmt.Sprintf("$r%d==%d && ", i, word)
				}
				match = fmt.Sprintf("$family==10 && ((%s$lp==%d)||(%s$pp==%d))", left, c.Port, right, htons(uint16(c.Port)))
			}

			script += "if(" + match + "){if($n<=16384){$off=(uint64)0;"
			script += fmt.Sprintf("printf(\"META %d %%llu %%llu %%llu %%llu %%u %%u %%u %%u %%u %%u %%u %%u %%u %%u %%u\\n\",$connection,$at,$n,$off,$family,$lp,$pp,$l0,$l1,$l2,$l3,$r0,$r1,$r2,$r3);$off=(uint64)%d;", hook.opcode, piece*pieceBytes)
			// LLVM removes a direct mask using bounds the 5.15 verifier cannot
			// recover. Reload the clamped length before masking to preserve the
			// helper's explicit bound; 0..100 remains unchanged. Delete promptly.
			script += fmt.Sprintf("unroll(%d){if($off<$n){$size=(uint64)($n-$off);if($size>100){$size=(uint64)100;}@fragment_size[tid]=$size;$size=@fragment_size[tid] & 127;delete(@fragment_size[tid]);", observerFragmentsPerProgram)
			script += fmt.Sprintf("printf(\"FRAG %d %%llu %%llu %%llu %%rh\\n\",$connection,$at,$off,buf(uptr(@ptr%d[tid]+$off),$size));", hook.opcode, hook.opcode)
			script += "}$off=$off+100;}}else{printf(\"LIMIT\\n\");}}}}} }\n"
		}
	}

	script += prefix + "SSL_free" + guard + "{if(@generation[arg0]){printf(\"CLOSE %llu %llu\\n\",@generation[arg0]^arg0,nsecs);}delete(@rfd[arg0]);delete(@wfd[arg0]);delete(@generation[arg0]);}\n"
	script += "END { clear(@rfd);clear(@wfd);clear(@generation);clear(@begin1);clear(@begin2);clear(@bound1);clear(@bound2);clear(@returned1);clear(@returned2);clear(@when1);clear(@when2);clear(@bind_ssl);clear(@bind_fd);clear(@ptr1);clear(@ptr2);clear(@ssl1);clear(@ssl2);clear(@len1);clear(@len2);clear(@out1);clear(@out2);}\n"
	return script, nil
}
func parseOpenSSLLine(line string, c OpenSSLCaptureConfiguration, offset int64) (observerFrame, error) {
	var f observerFrame
	fields := strings.Fields(line)
	if (len(fields) < 18 || len(fields) > 217) || fields[0] != "SG" {
		return f, errors.New("observer output invalid")
	}
	values := make([]uint64, 16)
	for i := range values {
		v, e := strconv.ParseUint(fields[i+1], 10, 64)
		if e != nil {
			return f, e
		}
		values[i] = v
	}
	body, e := hex.DecodeString(strings.Join(fields[17:], ""))
	if e != nil || len(body) > 200 {
		return f, errors.New("observer output bounds invalid")
	}
	f.Opcode = byte(values[0])
	f.PID = uint32(c.Profile.PID)
	f.SSL = values[1]
	f.Timestamp = uint64(int64(values[2]) + offset)
	f.Total = values[3]
	f.Offset = uint32(values[4])
	f.LocalPort = int(values[6])
	f.PeerPort = int(htons(uint16(values[7])))
	f.Data = body
	makeIP := func(words []uint64) net.IP {
		data := make([]byte, 16)
		for i, word := range words {
			binary.NativeEndian.PutUint32(data[i*4:], uint32(word))
		}
		if values[5] == 2 {
			return net.IP(data[:4])
		}
		return net.IP(data)
	}
	f.LocalIP = makeIP(values[8:12])
	f.PeerIP = makeIP(values[12:16])
	return f, nil
}
func parseOpenSSLFragment(line string, offset int64) (observerFrame, error) {
	var f observerFrame
	fields := strings.Fields(line)
	if len(fields) < 6 || len(fields) > 205 || fields[0] != "FRAG" {
		return f, errors.New("observer fragment invalid")
	}
	op, e1 := strconv.ParseUint(fields[1], 10, 8)
	ssl, e2 := strconv.ParseUint(fields[2], 10, 64)
	at, e3 := strconv.ParseUint(fields[3], 10, 63)
	position, e4 := strconv.ParseUint(fields[4], 10, 32)
	if e1 != nil || e2 != nil || e3 != nil || e4 != nil || op < 1 || op > 2 || ssl == 0 {
		return f, errors.New("observer fragment identity invalid")
	}
	body, e := hex.DecodeString(strings.Join(fields[5:], ""))
	if e != nil || len(body) == 0 || len(body) > 200 {
		return f, errors.New("observer fragment bytes invalid")
	}
	f.Opcode = byte(op)
	f.SSL = ssl
	f.Timestamp = uint64(int64(at) + offset)
	f.Offset = uint32(position)
	f.Data = body
	return f, nil
}

func encodeObserverFrame(f observerFrame) []byte {
	raw := make([]byte, 120+len(f.Data))
	copy(raw, "SGO1")
	raw[4] = 1
	raw[5] = f.Opcode
	raw[6] = f.Flags
	binary.LittleEndian.PutUint32(raw[8:], f.PID)
	binary.LittleEndian.PutUint64(raw[16:], f.CallID)
	binary.LittleEndian.PutUint64(raw[24:], f.SSL)
	binary.LittleEndian.PutUint64(raw[32:], f.Timestamp)
	binary.LittleEndian.PutUint64(raw[40:], f.Total)
	binary.LittleEndian.PutUint32(raw[48:], f.Offset)
	binary.LittleEndian.PutUint32(raw[52:], uint32(len(f.Data)))
	binary.LittleEndian.PutUint64(raw[56:], f.Dropped)
	binary.LittleEndian.PutUint16(raw[66:], uint16(f.LocalPort))
	binary.LittleEndian.PutUint16(raw[68:], uint16(f.PeerPort))
	put := func(at, marker int, ip net.IP) {
		if v4 := ip.To4(); v4 != nil {
			raw[marker] = 4
			copy(raw[at:], v4)
		} else if v6 := ip.To16(); v6 != nil {
			raw[marker] = 6
			copy(raw[at:], v6)
		}
	}
	put(70, 64, f.LocalIP)
	put(86, 65, f.PeerIP)
	copy(raw[102:], f.ProfileTag[:])
	copy(raw[120:], f.Data)
	return raw
}
func observerFramesComplete(frames []observerFrame) bool {
	if len(frames) == 0 || frames[0].Total == 0 {
		return false
	}
	call := newObserverCall(frames[0].Total)
	for _, f := range frames {
		if f.Total != call.total || f.SSL != frames[0].SSL || f.Opcode != frames[0].Opcode {
			return false
		}
		if _, _, e := call.add(f.Offset, f.Data); e != nil {
			return false
		}
	}
	return call.received == call.total
}

func runOpenSSLCapture(path string, review bool) error {
	if os.Geteuid() != 0 {
		return errors.New("separate reviewed observer requires root capability boundary")
	}
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 || !info.Mode().IsRegular() || info.Mode().Perm()&0022 != 0 || info.Size() > 8192 {
		return errors.New("observer configuration must be root-owned")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var c OpenSSLCaptureConfiguration
	if err = json.Unmarshal(raw, &c); err != nil {
		return err
	}
	actual, err := inspectOpenSSLProcess(c.Profile.PID, c.Profile.LibraryPath)
	if err != nil || !reflect.DeepEqual(actual, c.Profile) {
		return &observationError{gap: "PROBE_PROFILE_MISMATCH"}
	}
	script, err := openSSLScript(c)
	if err != nil {
		return err
	}
	if review {
		_, e := os.Stdout.WriteString(script)
		return e
	}
	// %rh buffer output was introduced in 0.17; older compilers can abort before attaching.
	if err = checkObserverRuntime(); err != nil {
		return err
	}
	tag, err := profileTag(c.Profile)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	var conn *net.UnixConn
	for attempt := 0; attempt < 50; attempt++ {
		conn, err = net.DialUnix("unixpacket", nil, &net.UnixAddr{Name: c.Socket, Net: "unixpacket"})
		if err == nil {
			break
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(100 * time.Millisecond):
		}
	}
	if err != nil {
		return errors.New("unprivileged observer receiver unavailable")
	}
	defer conn.Close()
	if _, peerUID, e := observerPeer(conn); e != nil || peerUID != c.ReceiverUID {
		return errors.New("observer receiver identity mismatch")
	}
	send := func(f observerFrame) error {
		f.PID = uint32(c.Profile.PID)
		f.ProfileTag = tag
		conn.SetWriteDeadline(time.Now().Add(100 * time.Millisecond))
		_, e := conn.Write(encodeObserverFrame(f))
		return e
	}
	// The bounded programs together exceed Linux's per-argument size limit. This file
	// contains only generated code, never application bytes, and is private to root.
	program, err := os.CreateTemp("", "selfguard-openssl-*.bt")
	if err != nil {
		return errors.New("observer private program unavailable")
	}
	programPath := program.Name()
	defer os.Remove(programPath)
	if _, err = program.WriteString(script); err != nil {
		program.Close()
		return errors.New("observer private program write failed")
	}
	if err = program.Close(); err != nil {
		return errors.New("observer private program close failed")
	}
	cmd := exec.CommandContext(ctx, "/usr/bin/bpftrace", "-q", "-B", "none", "-kk", "-p", strconv.Itoa(c.Profile.PID), programPath)
	cmd.Env = []string{"PATH=/usr/bin:/bin", "BPFTRACE_PERF_RB_PAGES=256", "BPFTRACE_MAX_STRLEN=127", "BPFTRACE_STRLEN=127"}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return err
	}
	if err = cmd.Start(); err != nil {
		return errors.New("reviewed BTF/uprobe runtime unavailable")
	}
	// Raw trace output stays inside this private pipe. Tool diagnostics are reduced
	// to a loss flag; neither raw buffers nor paths are forwarded to the journal.
	lines := make(chan string, 512)
	done := make(chan error, 1)
	go func() {
		scanner := bufio.NewScanner(stdout)
		scanner.Buffer(make([]byte, 2048), 4096)
		for scanner.Scan() {
			select {
			case lines <- scanner.Text():
			case <-ctx.Done():
				return
			}
		}
		close(lines)
		done <- scanner.Err()
	}()
	lost := make(chan struct{}, 1)
	go func() {
		scanner := bufio.NewScanner(stderr)
		for scanner.Scan() {
			if !lostObserverEvents.MatchString(scanner.Text()) {
				continue
			}
			select {
			case lost <- struct{}{}:
			default:
			}
		}
	}()
	var ts unix.Timespec
	if err = unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts); err != nil {
		stop()
		cmd.Wait()
		return err
	}
	clockOffset := time.Now().UnixNano() - ts.Nano()

	type callKey struct {
		at, ssl uint64
		opcode  byte
	}
	pending := map[callKey][]observerFrame{}
	metadata := map[callKey]observerFrame{}
	started := map[callKey]time.Time{}
	lastAt := map[uint64]uint64{}
	// Keep only bounded late-fragment watermarks; connection keys include binding generation.
	history := make([]uint64, 0, 8192)
	historyNext := 0
	remember := func(ssl, at uint64) {
		if _, exists := lastAt[ssl]; !exists {
			if len(history) == cap(history) {
				delete(lastAt, history[historyNext])
				history[historyNext] = ssl
				historyNext = (historyNext + 1) % cap(history)
			} else {
				history = append(history, ssl)
			}
		}
		lastAt[ssl] = at
	}
	var callID uint64
	flush := func(force bool, onlySSL uint64) error {
		keys := make([]callKey, 0, len(pending))
		for key := range pending {
			if onlySSL == 0 || key.ssl == onlySSL {
				keys = append(keys, key)
			}
		}
		sort.Slice(keys, func(i, j int) bool {
			if keys[i].at != keys[j].at {
				return keys[i].at < keys[j].at
			}
			if keys[i].ssl != keys[j].ssl {
				return keys[i].ssl < keys[j].ssl
			}
			return keys[i].opcode < keys[j].opcode
		})
		blocked := map[uint64]bool{}
		for _, key := range keys {
			frames := pending[key]
			age := time.Since(started[key])
			complete := observerFramesComplete(frames)
			if !force && (blocked[key.ssl] || age < 30*time.Millisecond || !complete && age < 2*time.Second) {
				blocked[key.ssl] = true
				continue
			}
			if !complete {
				if err := send(observerFrame{Opcode: 4, Flags: 32}); err != nil {
					return err
				}
			}
			callID++
			for _, f := range frames {
				if f.Timestamp < lastAt[f.SSL] {
					if err := send(observerFrame{Opcode: 4, Flags: 32}); err != nil {
						return err
					}
				}
				remember(f.SSL, f.Timestamp)
				f.CallID = callID
				if err := send(f); err != nil {
					return err
				}
			}
			delete(metadata, key)
			delete(pending, key)
			delete(started, key)
		}
		return nil
	}

	tick := time.NewTicker(10 * time.Millisecond)
	defer tick.Stop()
	check := time.NewTicker(time.Second)
	defer check.Stop()
	defer func() { stop(); cmd.Wait() }()
	for {
		select {
		case <-ctx.Done():
			return flush(true, 0)
		case <-lost:
			if err = send(observerFrame{Opcode: 4, Flags: 32}); err != nil {
				return err
			}
		case <-check.C:
			current, e := inspectOpenSSLProcess(c.Profile.PID, c.Profile.LibraryPath)
			if e != nil || !reflect.DeepEqual(current, c.Profile) {
				send(observerFrame{Opcode: 4, Flags: 2})
				return &observationError{gap: "PROBE_PROFILE_MISMATCH"}
			}
		case <-tick.C:
			if err = flush(false, 0); err != nil {
				return err
			}
		case line, open := <-lines:
			if !open {
				if e := <-done; e != nil {
					return errors.New("observer private stream interrupted")
				}
				if err = flush(true, 0); err != nil {
					return err
				}
				return errors.New("read-only observer stopped; business process untouched")
			}
			if line == "READY" {
				if err = send(observerFrame{Opcode: 4, Flags: 16}); err != nil {
					return err
				}
				continue
			}
			if line == "UNBOUND" {
				if err = send(observerFrame{Opcode: 4, Flags: 8}); err != nil {
					return err
				}
				continue
			}
			if line == "LIMIT" {
				if err = send(observerFrame{Opcode: 4, Flags: 1}); err != nil {
					return err
				}
				continue
			}
			if strings.HasPrefix(line, "CLOSE ") {
				parts := strings.Fields(line)
				if len(parts) != 3 {
					continue
				}
				ssl, e := strconv.ParseUint(parts[1], 10, 64)
				if e != nil {
					continue
				}
				if err = flush(true, ssl); err != nil {
					return err
				}
				closeAt, parseErr := strconv.ParseUint(parts[2], 10, 63)
				if parseErr != nil {
					return errors.New("observer close time invalid")
				}
				remember(ssl, uint64(int64(closeAt)+clockOffset))
				if err = send(observerFrame{Opcode: 3, SSL: ssl}); err != nil {
					return err
				}
				continue
			}

			if strings.HasPrefix(line, "META ") {
				frame, e := parseOpenSSLLine("SG "+strings.TrimPrefix(line, "META ")+" 00", c, clockOffset)
				if e != nil {
					return errors.New("observer call metadata invalid")
				}
				frame.Data = nil
				key := callKey{at: frame.Timestamp, ssl: frame.SSL, opcode: frame.Opcode}
				if len(pending) >= 64 {
					if err = send(observerFrame{Opcode: 4, Flags: 1}); err != nil {
						return err
					}
					continue
				}
				if _, exists := metadata[key]; exists {
					continue
				}
				if frame.Timestamp <= lastAt[frame.SSL] {
					continue
				}
				metadata[key] = frame
				pending[key] = nil
				started[key] = time.Now()
				continue
			}
			if !strings.HasPrefix(line, "FRAG ") {
				continue
			}
			part, e := parseOpenSSLFragment(line, clockOffset)
			if e != nil {
				return e
			}
			key := callKey{at: part.Timestamp, ssl: part.SSL, opcode: part.Opcode}
			frame, ok := metadata[key]
			if !ok {
				if part.Timestamp <= lastAt[part.SSL] {
					continue
				}
				if err = send(observerFrame{Opcode: 4, Flags: 32}); err != nil {
					return err
				}
				continue
			}
			frame.Offset = part.Offset
			frame.Data = part.Data
			if uint64(frame.Offset)+uint64(len(frame.Data)) > frame.Total {
				return errors.New("observer fragment exceeds call")
			}
			pending[key] = append(pending[key], frame)

		}
	}
}
