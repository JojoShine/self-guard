package main

import (
	"bufio"
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

type Port struct {
	Protocol       string        `json:"protocol"`
	Address        string        `json:"address"`
	Port           int           `json:"port"`
	State          string        `json:"state"`
	Software       string        `json:"software,omitempty"`
	Identification string        `json:"identification,omitempty"`
	ServiceHint    string        `json:"serviceHint,omitempty"`
	Processes      []PortProcess `json:"processes,omitempty"`
	socketInode    string
}
type Service struct {
	Name  string `json:"name"`
	State string `json:"state"`
}

func portInventory(root string) ([]Port, PackageCollection) {
	out := []Port{}
	status := PackageCollection{Complete: true, Reason: "collected"}
	for _, protocol := range []string{"tcp", "tcp6", "udp", "udp6"} {
		f, err := os.Open(filepath.Join(root, protocol))
		if err != nil {
			status = PackageCollection{Reason: "proc socket table unavailable"}
			continue
		}
		limited := &io.LimitedReader{R: f, N: (1 << 20) + 1}
		scan := bufio.NewScanner(limited)
		scan.Scan() // header
		for scan.Scan() {
			fields := strings.Fields(scan.Text())
			if len(fields) < 4 {
				status = PackageCollection{Reason: "malformed socket table"}
				continue
			}
			// TCP listening and unconnected UDP sockets are exposed as listening inventory.
			if (strings.HasPrefix(protocol, "tcp") && fields[3] != "0A") || (strings.HasPrefix(protocol, "udp") && fields[3] != "07") {
				continue
			}
			address, port, err := procAddress(fields[1])
			if err != nil {
				status = PackageCollection{Reason: "malformed socket address"}
				continue
			}
			if len(out) >= 2000 {
				status = PackageCollection{Reason: "socket count limit exceeded"}
				break
			}
			inode := ""
			if len(fields) > 9 {
				inode = fields[9]
			}
			out = append(out, Port{Protocol: protocol, Address: address, Port: port, State: "LISTEN", socketInode: inode})
		}
		if scan.Err() != nil {
			status = PackageCollection{Reason: "socket table read failed"}
		}
		if limited.N == 0 {
			status = PackageCollection{Reason: "socket table size limit exceeded"}
		}
		f.Close()
	}
	identifyPortSoftware(filepath.Dir(root), out)
	return out, status
}
func procAddress(raw string) (string, int, error) {
	addr, port, ok := strings.Cut(raw, ":")
	if !ok {
		return "", 0, fmt.Errorf("missing port")
	}
	b, err := hex.DecodeString(addr)
	if err != nil || (len(b) != 4 && len(b) != 16) {
		return "", 0, fmt.Errorf("invalid address")
	}
	for i := 0; i < len(b); i += 4 {
		b[i], b[i+3] = b[i+3], b[i]
		b[i+1], b[i+2] = b[i+2], b[i+1]
	}
	p, err := strconv.ParseUint(port, 16, 16)
	return net.IP(b).String(), int(p), err
}

var serviceName = regexp.MustCompile(`^(?:[A-Za-z0-9_]|\\x[0-9a-fA-F]{2})(?:[A-Za-z0-9_.@:-]|\\x[0-9a-fA-F]{2})*$`)

func validService(name string) bool { return len(name) <= 255 && serviceName.MatchString(name) }
func serviceInventory() ([]Service, PackageCollection) {
	if manager, err := currentInstallationInit(); err == nil && manager == "openrc" {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		c := exec.CommandContext(ctx, "/bin/rc-status", "--nocolor", "--format", "ini", "--servicelist")
		c.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C"}
		output := &cappedOutput{}
		c.Stdout = output
		if c.Run() != nil {
			return []Service{}, PackageCollection{Reason: "OpenRC service collection failed"}
		}
		return openRCServiceLines(output)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	c := exec.CommandContext(ctx, "systemctl", "list-units", "--type=service", "--all", "--no-legend", "--no-pager", "--plain")
	output := &cappedOutput{}
	c.Stdout = output
	if c.Run() != nil {
		return []Service{}, PackageCollection{Reason: "systemd unavailable or service collection failed"}
	}
	return serviceLines(output)
}
func openRCServiceLines(output *cappedOutput) ([]Service, PackageCollection) {
	status := PackageCollection{Complete: !output.truncated, Reason: "collected"}
	if output.truncated {
		status.Reason = "service output limit exceeded"
	}
	states := map[string]string{"started": "active", "stopped": "inactive", "crashed": "failed", "starting": "activating", "stopping": "deactivating", "inactive": "inactive", "scheduled": "activating"}
	out, seen := []Service{}, map[string]bool{}
	for _, line := range strings.Split(string(output.b), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		name, raw, found := strings.Cut(line, "=")
		name = strings.TrimSpace(name)
		fields := strings.Fields(raw)
		if !found || !validService(name) || len(fields) == 0 || states[fields[0]] == "" || seen[name] {
			status = PackageCollection{Reason: "malformed or unknown OpenRC service state"}
			continue
		}
		if len(out) >= 2000 {
			status = PackageCollection{Reason: "service count limit exceeded"}
			break
		}
		seen[name] = true
		out = append(out, Service{name, states[fields[0]]})
	}
	if len(out) == 0 {
		status = PackageCollection{Reason: "empty OpenRC service inventory"}
	}
	return out, status
}
func serviceLines(output *cappedOutput) ([]Service, PackageCollection) {
	status := PackageCollection{Complete: !output.truncated, Reason: "collected"}
	if output.truncated {
		status.Reason = "service output limit exceeded"
	}
	out := []Service{}
	for _, line := range strings.Split(string(output.b), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		if !validService(fields[0]) {
			status = PackageCollection{Reason: "malformed service name"}
			continue
		}
		if len(out) >= 2000 {
			status = PackageCollection{Reason: "service count limit exceeded"}
			break
		}
		out = append(out, Service{fields[0], fields[2]})
	}
	return out, status
}
func serviceState(name string) (string, error) {
	if !validService(name) {
		return "", fmt.Errorf("invalid service")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	c := exec.CommandContext(ctx, "systemctl", "show", "--property=ActiveState", "--value", "--", name)
	output := &cappedOutput{}
	c.Stdout = output
	if err := c.Run(); err != nil {
		return "", err
	}
	if output.truncated {
		return "", fmt.Errorf("oversize service state")
	}
	state := strings.TrimSpace(string(output.b))
	if state == "" {
		return "", fmt.Errorf("empty service state")
	}
	return state, nil
}
func (a *Agent) collectBaselines() []map[string]any {
	out := []map[string]any{}
	for i, c := range append(append([]Check{}, a.Config.Checks...), a.RemoteChecks...) {
		if i >= 100 {
			break
		}
		actual, expected, status := "", c.Mode, "checked"
		kind := c.Type
		if kind == "" {
			kind = "FILE_PERMISSION"
		}
		switch kind {
		case "SERVICE_STATE":
			expected = c.State
			value, err := serviceState(c.Service)
			actual = value
			if err != nil {
				status = "unreadable"
			}
		case "DATABASE_SECURITY", "CONFIG_VALUE", "FILE_PERMISSION":
			if safePath(a.Config.AllowedRoot, c.Path) != nil {
				status = "unreadable"
				break
			}
			f, err := openTarget(c.Path)
			if err != nil {
				status = "unreadable"
				break
			}
			s, err := f.Stat()
			if err != nil || !s.Mode().IsRegular() {
				status = "unreadable"
				f.Close()
				break
			}
			if kind == "DATABASE_SECURITY" {
				if c.Key == "CREDENTIAL_FILE_MODE" {
					actual, expected, status = databaseBaseline(c, "", fmt.Sprintf("%04o", s.Mode().Perm()))
				} else if s.Size() > 64<<10 {
					status = "unreadable"
				} else {
					b, e := io.ReadAll(io.LimitReader(f, (64<<10)+1))
					if e != nil || len(b) > 64<<10 {
						status = "unreadable"
					} else {
						actual, expected, status = databaseBaseline(c, string(b), fmt.Sprintf("%04o", s.Mode().Perm()))
					}
				}
			} else if kind == "FILE_PERMISSION" {
				actual = fmt.Sprintf("%04o", s.Mode().Perm())
			} else {
				expected = c.Value
				if !configKey.MatchString(c.Key) || s.Size() > 64<<10 {
					status = "unreadable"
				} else {
					b, e := io.ReadAll(io.LimitReader(f, (64<<10)+1))
					count := 0
					if e != nil || len(b) > 64<<10 {
						status = "unreadable"
					} else {
						actual, count = observedConfigValue(string(b), c.Key)
						if count != 1 {
							status = "missing or duplicate key"
						}
					}
				}
			}
			f.Close()
		default:
			continue
		}
		if finding := baselineFinding(c, kind, actual, expected, status); finding != nil {
			out = append(out, finding)
		}
	}
	return out
}

// Established peers do not prove connection direction, service type or ownership.
func connectionInventory(root string) ([]Port, PackageCollection) {
	out := []Port{}
	status := PackageCollection{Complete: true, Reason: "collected"}
	seen := map[string]bool{}
	for _, protocol := range []string{"tcp", "tcp6"} {
		f, err := os.Open(filepath.Join(root, protocol))
		if err != nil {
			status = PackageCollection{Reason: "proc connection table unavailable"}
			continue
		}
		limited := &io.LimitedReader{R: f, N: (1 << 20) + 1}
		scan := bufio.NewScanner(limited)
		scan.Scan()
		for scan.Scan() {
			fields := strings.Fields(scan.Text())
			if len(fields) < 4 {
				status = PackageCollection{Reason: "malformed connection table"}
				continue
			}
			if fields[3] != "01" {
				continue
			}
			address, port, err := procAddress(fields[2])
			ip := net.ParseIP(address)
			if err != nil || ip == nil {
				status = PackageCollection{Reason: "invalid peer address"}
				continue
			}
			if ip.IsLoopback() || ip.IsUnspecified() || port == 0 {
				continue
			}
			key := fmt.Sprintf("%s:%d", address, port)
			if seen[key] {
				continue
			}
			if len(out) >= 500 {
				status = PackageCollection{Reason: "connection count limit exceeded"}
				break
			}
			seen[key] = true
			out = append(out, Port{Protocol: protocol, Address: address, Port: port, State: "ESTABLISHED"})
		}
		if scan.Err() != nil || limited.N == 0 {
			status = PackageCollection{Reason: "connection read limit or error"}
		}
		f.Close()
	}
	return out, status
}
