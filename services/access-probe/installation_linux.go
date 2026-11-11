//go:build linux

package main

import (
	"bytes"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/user"
	"regexp"
	"strconv"
	"strings"
	"syscall"
)

type ProbeInstallation struct {
	AssetID   string          `json:"assetId"`
	Mode      string          `json:"mode"`
	Interface string          `json:"interface"`
	Address   string          `json:"address"`
	Port      int             `json:"port"`
	Profile   *OpenSSLProfile `json:"profile,omitempty"`
}

var sourceIDPattern = regexp.MustCompile(`^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$`)

const installedProbe = "/usr/local/libexec/selfguard-access-probe-" + probeVersion

func probeUnits(c ProbeLocalConfig, account string, tls bool) (decoder, capture, expiry, timer string) {
	budget := c.MaxQueueBytes
	if budget < 1 {
		budget = 1 << 30
	}
	id := c.SourceID
	dir := "/etc/selfguard-probe/" + id
	runtime := "/run/selfguard-probe/" + id
	unit := "selfguard-access-" + id
	decoder = "[Unit]\nDescription=SelfGuard independent effective access decoder\nAfter=network-online.target\nWants=network-online.target selfguard-access-" + id + "-capture.service\n\n[Service]\nUser=" + account + "\nGroup=" + account + "\nUMask=0077\nExecStart=" + installedProbe + " --config " + dir + "/probe.json --pcap " + runtime + "/capture.pcap\nRestart=on-failure\nRestartSec=5\nNoNewPrivileges=true\nCapabilityBoundingSet=\nPrivateTmp=true\nProtectSystem=full\nProtectHome=true\nMemoryLimit=512M\nCPUQuota=100%\n\n[Install]\nWantedBy=multi-user.target\n"
	capability := "CAP_NET_RAW"
	flag := "--capture-config"
	if tls {
		capability = "CAP_BPF CAP_PERFMON CAP_SYS_PTRACE CAP_SYS_ADMIN CAP_SYS_RESOURCE"
		flag = "--openssl-capture-config"
	}
	capture = "[Unit]\nDescription=SelfGuard separate read-only capture\nAfter=" + unit + ".service\nRequires=" + unit + ".service\n\n[Service]\nUser=root\nUMask=0077\nExecStart=" + installedProbe + " " + flag + " " + dir + "/capture.json\nRestart=on-failure\nRestartSec=5\nNoNewPrivileges=true\nCapabilityBoundingSet=" + capability + "\nPrivateTmp=false\nProtectSystem=full\nProtectHome=true\nMemoryLimit=512M\nCPUQuota=100%\nLimitMEMLOCK=268435456\n\n[Install]\nWantedBy=multi-user.target\n"
	expiry = "[Unit]\nDescription=Expire offline SelfGuard request and response evidence\n\n[Service]\nType=oneshot\nUser=" + account + "\nGroup=" + account + "\nExecStart=" + installedProbe + " --expire-queue " + c.StateDir + " --queue-limit " + strconv.FormatInt(budget, 10) + "\nNoNewPrivileges=true\nCapabilityBoundingSet=\nProtectSystem=full\nProtectHome=true\n"
	timer = "[Unit]\nDescription=SelfGuard offline evidence expiry\n\n[Timer]\nOnBootSec=5min\nOnUnitActiveSec=1h\nUnit=" + unit + "-expire.service\n\n[Install]\nWantedBy=timers.target\n"
	return
}
func installationSnapshotMatches(c ProbeLocalConfig, source ProbeConfiguration) bool {
	i := c.Installation
	if i == nil {
		return true
	}
	if i.AssetID != source.AssetID || i.Mode != source.Mode || i.Interface != source.Interface || i.Address != source.Address || i.Port != source.Port {
		return false
	}
	if source.Mode == "PLAINTEXT_EVENTS" {
		return i.Profile != nil && *i.Profile == source.Profile
	}
	return i.Profile == nil
}
func writeInstallationFile(path string, data []byte, mode os.FileMode, uid, gid int) error {
	// Existing target must be a regular operator-owned file. Never follow links.
	if old, err := os.Lstat(path); err == nil {
		stat, ok := old.Sys().(*syscall.Stat_t)
		if !ok || !old.Mode().IsRegular() || stat.Uid != 0 {
			return errors.New("installation target is not operator-owned")
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY|syscall.O_NOFOLLOW, mode)
	if err != nil {
		return err
	}
	if _, err = file.Write(data); err == nil {
		err = file.Sync()
	}
	closeErr := file.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	if err = os.Chmod(path, mode); err != nil {
		return err
	}
	return os.Chown(path, uid, gid)
}
func publicCACertificates(raw []byte) ([]byte, error) {
	var out []byte
	for len(bytes.TrimSpace(raw)) > 0 {
		block, rest := pem.Decode(raw)
		if block == nil || block.Type != "CERTIFICATE" {
			return nil, errors.New("CA file must contain public certificates only")
		}
		if _, err := x509.ParseCertificate(block.Bytes); err != nil {
			return nil, errors.New("CA certificate invalid")
		}
		out = append(out, pem.EncodeToMemory(block)...)
		raw = rest
	}
	if len(out) == 0 {
		return nil, errors.New("CA certificate missing")
	}
	return out, nil
}

func runProbeInstallation(path string) error {
	if os.Geteuid() != 0 {
		return errors.New("installation requires root")
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() > 65536 || info.Mode().Perm()&0077 != 0 {
		return errors.New("installation requires a private downloaded source configuration")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var c ProbeLocalConfig
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err = d.Decode(&c); err != nil {
		return errors.New("installation configuration invalid")
	}
	if !sourceIDPattern.MatchString(c.SourceID) || c.Installation == nil || !sourceIDPattern.MatchString(c.Installation.AssetID) {
		return errors.New("installation needs a host-bound configuration downloaded from source management")
	}
	identityRaw, err := os.ReadFile("/var/lib/selfguard-agent/identity.json")
	if err != nil {
		return errors.New("existing base Agent identity required; do not enroll another host for the probe")
	}
	var identity struct {
		AssetID string `json:"assetId"`
	}
	if err = json.Unmarshal(identityRaw, &identity); err != nil || identity.AssetID != c.Installation.AssetID {
		return errors.New("probe source belongs to another host identity")
	}
	c.AllowHTTP = false
	client, err := newProbeClient(c)
	if err != nil {
		return err
	}
	var source ProbeConfiguration
	if err = client.request("/configuration", nil, &source); err != nil {
		return err
	}
	if source.ID != c.SourceID || !source.Enabled || !installationSnapshotMatches(c, source) {
		return errors.New("source snapshot differs from approved platform configuration")
	}
	tls := source.Mode == "PLAINTEXT_EVENTS"
	if source.Mode != "NETWORK" && !tls {
		return errors.New("capture mode unsupported")
	}
	if tls {
		current, e := inspectOpenSSLProcess(source.Profile.PID, source.Profile.LibraryPath)
		if e != nil || current != source.Profile {
			return &observationError{gap: "PROBE_PROFILE_MISMATCH"}
		}
		if _, e = os.Stat("/sys/kernel/btf/vmlinux"); e != nil {
			return errors.New("reviewed TLS observer requires kernel BTF")
		}
		if e = checkObserverRuntime(); e != nil {
			return e
		}
	}
	account := "sgp" + strings.ReplaceAll(c.SourceID, "-", "")[:20]
	member, err := user.Lookup(account)
	if err != nil {
		if _, ok := err.(user.UnknownUserError); !ok {
			return err
		}
		command := exec.Command("/usr/sbin/useradd", "--system", "--no-create-home", "--shell", "/sbin/nologin", account)
		if err = command.Run(); err != nil {
			return errors.New("dedicated probe account could not be created")
		}
		member, err = user.Lookup(account)
		if err != nil {
			return err
		}
	}
	uid, err := strconv.Atoi(member.Uid)
	if err != nil || uid == 0 {
		return errors.New("probe account invalid")
	}
	gid, err := strconv.Atoi(member.Gid)
	if err != nil {
		return err
	}
	state := "/var/lib/selfguard/access-probe/" + c.SourceID
	dir := "/etc/selfguard-probe/" + c.SourceID
	runtime := "/run/selfguard-probe/" + c.SourceID
	for _, parent := range []string{"/usr/local/libexec", "/var/lib/selfguard/access-probe", "/etc/selfguard-probe", "/run/selfguard-probe"} {
		if err = os.MkdirAll(parent, 0755); err != nil {
			return err
		}
	}
	for _, entry := range []struct {
		path string
		mode os.FileMode
		uid  int
	}{{state, 0700, uid}, {dir, 0750, 0}, {runtime, 0750, 0}, {runtime + "/decoder", 0700, uid}} {
		if old, e := os.Lstat(entry.path); e == nil && (!old.IsDir() || old.Mode()&os.ModeSymlink != 0) {
			return errors.New("probe installation directory invalid")
		}
		if err = os.MkdirAll(entry.path, entry.mode); err != nil {
			return err
		}
		if err = os.Chmod(entry.path, entry.mode); err != nil {
			return err
		}
		if err = os.Chown(entry.path, entry.uid, gid); err != nil {
			return err
		}
	}
	if existing, e := os.ReadFile(installedProbe); e == nil {
		current, e := os.ReadFile("/proc/self/exe")
		if e != nil || !bytes.Equal(existing, current) {
			return errors.New("same version binary differs; use a new reviewed release version")
		}
	} else if !os.IsNotExist(e) {
		return e
	} else {
		file, e := os.Open("/proc/self/exe")
		if e != nil {
			return e
		}
		candidate, e := io.ReadAll(io.LimitReader(file, 64<<20))
		file.Close()
		if e != nil {
			return e
		}
		if err = writeInstallationFile(installedProbe, candidate, 0755, 0, 0); err != nil {
			return err
		}
	}
	c.MaxQueueBytes = source.MaxQueueBytes
	c.StateDir = state
	c.AllowHTTP = false
	c.CaptureStatsPath = ""
	c.PlaintextSocket = ""
	if c.CACertificate != "" {
		cert, e := os.ReadFile(c.CACertificate)
		if e != nil {
			return errors.New("approved CA file unavailable")
		}
		cert, e = publicCACertificates(cert)
		if e != nil {
			return e
		}
		if err = writeInstallationFile(dir+"/ca.pem", cert, 0444, 0, gid); err != nil {
			return err
		}
		c.CACertificate = dir + "/ca.pem"
	}
	var capture any
	if tls {
		c.PlaintextSocket = runtime + "/decoder/observer.sock"
		capture = OpenSSLCaptureConfiguration{Address: source.Address, Port: source.Port, Profile: source.Profile, Socket: c.PlaintextSocket, ReceiverUID: uint32(uid)}
	} else {
		c.CaptureStatsPath = runtime + "/capture-stats.json"
		capture = CaptureConfiguration{Interface: source.Interface, Address: source.Address, Port: source.Port, Output: runtime + "/capture.pcap", Stats: c.CaptureStatsPath}
		if old, e := os.Lstat(runtime + "/capture.pcap"); e == nil {
			if old.Mode()&os.ModeNamedPipe == 0 {
				return errors.New("capture FIFO path occupied")
			}
		} else if os.IsNotExist(e) {
			if err = syscall.Mkfifo(runtime+"/capture.pcap", 0640); err != nil {
				return err
			}
		} else {
			return e
		}
		if err = os.Chown(runtime+"/capture.pcap", 0, gid); err != nil {
			return err
		}
	}
	// Decoder reads a root-owned, group-readable credential; it cannot replace it.
	config, _ := json.MarshalIndent(c, "", "  ")
	if err = writeInstallationFile(dir+"/probe.json", config, 0440, 0, gid); err != nil {
		return err
	}
	captureRaw, _ := json.Marshal(capture)
	if err = writeInstallationFile(dir+"/capture.json", captureRaw, 0600, 0, 0); err != nil {
		return err
	}
	units := []string{"selfguard-access-" + c.SourceID + ".service", "selfguard-access-" + c.SourceID + "-capture.service", "selfguard-access-" + c.SourceID + "-expire.service", "selfguard-access-" + c.SourceID + "-expire.timer"}
	decoder, collector, expiry, timer := probeUnits(c, account, tls)
	for i, content := range []string{decoder, collector, expiry, timer} {
		if err = writeInstallationFile("/etc/systemd/system/"+units[i], []byte(content), 0644, 0, 0); err != nil {
			return err
		}
	}
	// /run is recreated on boot. tmpfiles recreates source-specific ownership and FIFO.
	tmpfiles := fmt.Sprintf("d %s 0750 root %s -\nd %s/decoder 0700 %s %s -\n", runtime, account, runtime, account, account)
	if !tls {
		tmpfiles += fmt.Sprintf("p %s/capture.pcap 0640 root %s -\n", runtime, account)
	}
	if err = writeInstallationFile("/etc/tmpfiles.d/selfguard-access-"+c.SourceID+".conf", []byte(tmpfiles), 0644, 0, 0); err != nil {
		return err
	}
	if err = exec.Command("/bin/systemctl", "daemon-reload").Run(); err != nil {
		return errors.New("systemd reload failed; private installation files retained")
	}
	if err = exec.Command("/bin/systemctl", "enable", "--now", units[0], units[1], units[3]).Run(); err != nil {
		return errors.New("probe services did not start; inspect source health and service status")
	}
	fmt.Println("Independent source probe installed; base Agent identity retained")
	return nil
}
