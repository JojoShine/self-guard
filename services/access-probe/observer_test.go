package main

import (
	"bytes"
	"encoding/binary"
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

func TestObserverBoundsEachVerifierProgramWithoutReducingCallCoverage(t *testing.T) {
	script, err := openSSLScript(OpenSSLCaptureConfiguration{Address: "127.0.0.1", Port: 5432, Profile: OpenSSLProfile{PID: 1234, UID: 65534, LibraryPath: "/usr/lib/libssl.so.3"}})
	if err != nil {
		t.Fatal(err)
	}
	pieces := regexp.MustCompile(`\$off=\(uint64\)([0-9]+);unroll\(([0-9]+)\)`).FindAllStringSubmatch(script, -1)
	covered, hooks := 0, 0
	for _, piece := range pieces {
		offset, _ := strconv.Atoi(piece[1])
		fragments, _ := strconv.Atoi(piece[2])
		if fragments < 1 || fragments > 7 {
			t.Fatal("one program can exceed the verified branch budget", fragments)
		}
		if offset == 0 {
			if hooks > 0 && covered < 16384 {
				t.Fatal("previous hook truncated the original call budget", covered)
			}
			covered = 0
			hooks++
		}
		if offset != covered {
			t.Fatal("fragment coverage has a hole or overlap", offset, covered)
		}
		covered += fragments * 100
	}
	if hooks != 4 || covered < 16384 {
		t.Fatal("all four OpenSSL APIs must cover the original 16 KiB call budget", hooks, covered)
	}
}

func TestObserverFragmentLengthHasExplicitNonnegativeVerifierBound(t *testing.T) {
	script, err := openSSLScript(OpenSSLCaptureConfiguration{Address: "127.0.0.1", Port: 5432, Profile: OpenSSLProfile{PID: 1234, UID: 65534, LibraryPath: "/usr/lib/libssl.so.3"}})
	if err != nil {
		t.Fatal(err)
	}
	reads := strings.Count(script, "buf(uptr(")
	bounds := strings.Count(script, "@fragment_size[tid]=$size;$size=@fragment_size[tid] & 127;delete(@fragment_size[tid]);")
	if reads == 0 || reads != bounds {
		t.Fatal("each variable-length user read needs a verifier-visible nonnegative bound", reads, bounds)
	}
}

func TestObserverRejectsUnsupportedOrAmbiguousRuntimeBeforeAttachment(t *testing.T) {
	for _, version := range []string{"bpftrace v0.14.0", "bpftrace v0.16.9", "", "other v0.17.0", "bpftrace v0.17", "bpftrace v0.17.0-+", "bpftrace v0.17.0-rc1", "bpftrace v999999999999999999999.17.0"} {
		if err := checkObserverRuntimeVersion(version); err == nil {
			t.Fatalf("unsupported runtime accepted: %q", version)
		}
	}
	for _, version := range []string{"bpftrace v0.17.0\n", "bpftrace v0.17.1", "bpftrace v0.18.0"} {
		if err := checkObserverRuntimeVersion(version); err != nil {
			t.Fatalf("supported version floor rejected: %q: %v", version, err)
		}
	}
}

func TestObserverFramesValidateLengthAndAssembleOutOfOrderChunks(t *testing.T) {
	frame := make([]byte, 123)
	copy(frame, "SGO1")
	frame[4] = 1
	frame[5] = 1
	binary.LittleEndian.PutUint32(frame[8:], 1234)
	binary.LittleEndian.PutUint64(frame[40:], 3)
	binary.LittleEndian.PutUint32(frame[52:], 3)
	copy(frame[120:], []byte{0, 255, 1})
	decoded, err := decodeObserverFrame(frame)
	if err != nil || !bytes.Equal(decoded.Data, []byte{0, 255, 1}) {
		t.Fatal("binary observer frame", err)
	}
	binary.LittleEndian.PutUint32(frame[48:], 2)
	if _, err = decodeObserverFrame(frame); err == nil {
		t.Fatal("out-of-range chunk accepted")
	}
	call := newObserverCall(6)
	if complete, _, err := call.add(3, []byte("def")); err != nil || complete {
		t.Fatal("early complete", err)
	}
	complete, body, err := call.add(0, []byte("abc"))
	if err != nil || !complete || string(body) != "abcdef" {
		t.Fatal("fragment assembly", err)
	}
	if _, _, err = call.add(0, []byte("xyz")); err == nil {
		t.Fatal("conflicting observer chunk accepted")
	}
}
func TestObserverPeerRequiresPinnedPIDUIDAndProcessStart(t *testing.T) {
	start, err := processStartTicks(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	profile := OpenSSLProfile{PID: os.Getpid(), UID: uint32(os.Getuid()), StartTicks: start}
	if err = validateObserverPeer(profile, os.Getpid(), uint32(os.Getuid())); err != nil {
		t.Fatal(err)
	}
	profile.StartTicks = "1"
	if err = validateObserverPeer(profile, os.Getpid(), uint32(os.Getuid())); err == nil {
		t.Fatal("reused pid accepted")
	}
	if err = validateObserverPeer(profile, os.Getpid()+1, uint32(os.Getuid())); err == nil {
		t.Fatal("another process accepted")
	}
}
func TestExternalObserverParsesBoundedFramesWithoutTrustingApplicationPeer(t *testing.T) {
	c := OpenSSLCaptureConfiguration{Address: "127.0.0.1", Port: 443, Profile: OpenSSLProfile{PID: 1234, UID: 1001, LibraryPath: "/usr/lib/libssl.so.3"}}
	f, err := parseOpenSSLLine("SG 1 123 10000 3 0 2 443 20480 16777343 0 0 0 16777343 0 0 0 00ff01", c, 100000)
	if err != nil || f.LocalPort != 443 || f.PeerPort != 80 || f.Timestamp != 110000 || !bytes.Equal(f.Data, []byte{0, 255, 1}) {
		t.Fatal("external frame", err, f)
	}
	spaced, spaceErr := parseOpenSSLLine("SG 1 123 10000 3 0 2 443 20480 16777343 0 0 0 16777343 0 0 0 00 ff 01", c, 100000)
	if spaceErr != nil || !bytes.Equal(spaced.Data, f.Data) {
		t.Fatal("runtime spaced buffer encoding", spaceErr)
	}
	roundtrip, err := decodeObserverFrame(encodeObserverFrame(f))
	if err != nil || !bytes.Equal(roundtrip.Data, f.Data) {
		t.Fatal("external IPC frame", err)
	}
	script, err := openSSLScript(c)
	if err != nil || len(script) == 0 {
		t.Fatal("script", err)
	}
	if !strings.Contains(script, "kptr((uint64)curtask->files->fdt->fd") {
		t.Fatal("kernel file table must retain its kernel address space")
	}
	c.Profile.LibraryPath = "/tmp/untrusted\";exit();"
	if _, err = openSSLScript(c); err == nil {
		t.Fatal("untrusted attachment expression accepted")
	}
}

func TestObserverBatchWaitsForEveryFragmentBeforeAssigningCallIdentity(t *testing.T) {
	frames := []observerFrame{{Total: 6, Offset: 0, Data: []byte("abc")}}
	if observerFramesComplete(frames) {
		t.Fatal("first fragment was treated as a complete call")
	}
	frames = append(frames, observerFrame{Total: 6, Offset: 3, Data: []byte("def")})
	if !observerFramesComplete(frames) {
		t.Fatal("complete call not released")
	}
}

func TestOpenSSLFragmentRequiresBoundedNumericIdentity(t *testing.T) {
	frame, err := parseOpenSSLFragment("FRAG 1 123 10000 100 00 ff 01", 100000)
	if err != nil || frame.Timestamp != 110000 || frame.SSL != 123 || frame.Offset != 100 || !bytes.Equal(frame.Data, []byte{0, 255, 1}) {
		t.Fatal("bounded fragment", err)
	}
	if _, err = parseOpenSSLFragment("FRAG 1 123 10000 4294967296 00", 0); err == nil {
		t.Fatal("fragment offset overflow accepted")
	}
}
