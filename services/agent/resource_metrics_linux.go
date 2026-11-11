//go:build linux

package main

import (
	"bufio"
	"fmt"
	"io"
	"math"
	"os"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"
)

func readResourceFile(path string, limit int64) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil || int64(len(b)) > limit {
		return "", fmt.Errorf("resource file unreadable or oversized")
	}
	return string(b), nil
}
func resourceNetwork(body string) (uint64, uint64, error) {
	var receive, transmit uint64
	count := 0
	for _, line := range strings.Split(body, "\n") {
		name, rest, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		if strings.TrimSpace(name) == "lo" {
			continue
		}
		fields := strings.Fields(rest)
		if len(fields) < 16 {
			return 0, 0, fmt.Errorf("network counters malformed")
		}
		rx, e := strconv.ParseUint(fields[0], 10, 64)
		tx, e2 := strconv.ParseUint(fields[8], 10, 64)
		if e != nil || e2 != nil || rx > 9007199254740991 || tx > 9007199254740991 || receive > 9007199254740991-rx || transmit > 9007199254740991-tx {
			return 0, 0, fmt.Errorf("network counters invalid")
		}
		receive += rx
		transmit += tx
		count++
	}
	if count == 0 {
		return 0, 0, fmt.Errorf("network interfaces unavailable")
	}
	return receive, transmit, nil
}
func resourceFilesystems(body string) ([]resourceFilesystem, bool) {
	out := []resourceFilesystem{}
	complete := true
	seen := map[string]bool{}
	unescape := strings.NewReplacer(`\040`, " ", `\011`, "\t", `\012`, "\n", `\134`, `\`)
	allowed := map[string]bool{"ext2": true, "ext3": true, "ext4": true, "xfs": true, "btrfs": true, "zfs": true, "f2fs": true, "overlay": true, "vfat": true}
	for _, line := range strings.Split(body, "\n") {
		left, right, ok := strings.Cut(line, " - ")
		if !ok {
			continue
		}
		f, r := strings.Fields(left), strings.Fields(right)
		if len(f) < 5 || len(r) < 1 {
			complete = false
			continue
		}
		if r[0] == "nfs" || r[0] == "nfs4" || r[0] == "cifs" || strings.HasPrefix(r[0], "fuse") {
			complete = false
			continue
		}
		if !allowed[r[0]] || seen[f[2]] {
			continue
		}
		seen[f[2]] = true
		if len(out) >= 16 {
			complete = false
			continue
		}
		mount := unescape.Replace(f[4])
		if info, e := os.Stat(mount); e != nil || !info.IsDir() {
			continue
		}
		var s syscall.Statfs_t
		if syscall.Statfs(mount, &s) != nil || s.Blocks == 0 || s.Bsize <= 0 {
			complete = false
			continue
		}
		if s.Blocks > 9007199254740991/uint64(s.Bsize) || s.Bavail > s.Blocks || s.Bfree > s.Blocks || s.Ffree > s.Files || s.Files > 9007199254740991 {
			complete = false
			continue
		}
		total, available := s.Blocks*uint64(s.Bsize), s.Bavail*uint64(s.Bsize)
		used := s.Blocks - s.Bfree
		denom := used + s.Bavail
		percent := float64(0)
		if denom > 0 {
			percent = 100 * float64(used) / float64(denom)
		}
		var inode *float64
		if s.Files > 0 {
			v := 100 * float64(s.Files-s.Ffree) / float64(s.Files)
			inode = &v
		}
		out = append(out, resourceFilesystem{mount, r[0], total, available, percent, s.Files, s.Ffree, inode})
	}
	if len(out) == 0 {
		complete = false
	}
	return out, complete
}
func (a *Agent) collectResourceMetrics() resourceMetric {
	now := time.Now()
	metric := resourceMetric{Schema: "selfguard-host-metrics-v1", CapturedAt: now.UTC().Format(time.RFC3339Nano), Status: "OK", Issues: []string{}, CPU: map[string]any{"logicalCpus": runtime.NumCPU()}, Network: map[string]any{}, Filesystems: []resourceFilesystem{}}
	issue := func(code string) { metric.Issues = append(metric.Issues, code); metric.Status = "PARTIAL" }
	if _, e := os.Stat("/.dockerenv"); e == nil {
		issue("CONTAINER_NAMESPACE")
	} else if _, e := os.Stat("/run/.containerenv"); e == nil {
		issue("CONTAINER_NAMESPACE")
	}
	counters := resourceCounters{at: now}
	body, err := readResourceCPU()
	if err == nil {
		counters.cpuTotal, counters.cpuIdle, err = resourceCPU(body)
	}
	cpuOK := err == nil
	counters.cpuKnown = cpuOK
	if !cpuOK {
		issue("CPU_UNAVAILABLE")
	}
	body, err = readResourceFile("/proc/meminfo", 64<<10)
	if err == nil {
		metric.Memory, err = resourceMemory(body)
	}
	if err != nil {
		issue("MEMORY_UNAVAILABLE")
	}
	body, err = readResourceFile("/proc/loadavg", 4096)
	fields := strings.Fields(body)
	if err == nil && len(fields) >= 3 {
		for i, key := range []string{"load1", "load5", "load15"} {
			n, e := strconv.ParseFloat(fields[i], 64)
			if e != nil || math.IsNaN(n) || math.IsInf(n, 0) || n < 0 {
				issue("LOAD_UNAVAILABLE")
				break
			}
			metric.CPU[key] = n
		}
	} else {
		issue("LOAD_UNAVAILABLE")
	}
	body, err = readResourceFile("/proc/uptime", 4096)
	fields = strings.Fields(body)
	if err == nil && len(fields) > 0 {
		n, e := strconv.ParseFloat(fields[0], 64)
		if e == nil && !math.IsNaN(n) && !math.IsInf(n, 0) && n >= 0 {
			metric.UptimeSeconds = &n
		} else {
			issue("UPTIME_UNAVAILABLE")
		}
	} else {
		issue("UPTIME_UNAVAILABLE")
	}
	body, err = readResourceFile("/proc/net/dev", 256<<10)
	if err == nil {
		counters.networkReceive, counters.networkTransmit, err = resourceNetwork(body)
	}
	networkOK := err == nil
	counters.networkKnown = networkOK
	if !networkOK {
		issue("NETWORK_UNAVAILABLE")
	} else {
		metric.Network["receiveBytes"], metric.Network["transmitBytes"] = counters.networkReceive, counters.networkTransmit
	}
	cpu, rx, tx := resourceRates(a.ResourcePrevious, counters)
	if cpuOK && cpu != nil {
		metric.CPU["usedPercent"] = *cpu
	}
	if networkOK && rx != nil {
		metric.Network["receiveBytesPerSecond"] = *rx
	}
	if networkOK && tx != nil {
		metric.Network["transmitBytesPerSecond"] = *tx
	}
	a.ResourcePrevious = &counters
	body, err = readResourceFile("/proc/self/mountinfo", 1<<20)
	if err == nil {
		var complete bool
		metric.Filesystems, complete = resourceFilesystems(body)
		if !complete {
			issue("FILESYSTEMS_PARTIAL")
		}
	} else {
		issue("FILESYSTEMS_UNAVAILABLE")
	}
	if !cpuOK && metric.Memory == nil && len(metric.Filesystems) == 0 {
		metric.Status = "UNAVAILABLE"
	}
	return metric
}

func readResourceCPU() (string, error) {
	f, err := os.Open("/proc/stat")
	if err != nil {
		return "", err
	}
	defer f.Close()
	return bufio.NewReader(io.LimitReader(f, 4096)).ReadString('\n')
}
