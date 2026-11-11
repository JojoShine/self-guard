package main

import (
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"
)

type resourceCounters struct {
	at                                                 time.Time
	cpuKnown, networkKnown                             bool
	cpuTotal, cpuIdle, networkReceive, networkTransmit uint64
}
type resourceMemoryValue struct {
	TotalBytes     uint64  `json:"totalBytes"`
	AvailableBytes uint64  `json:"availableBytes"`
	UsedPercent    float64 `json:"usedPercent"`
}
type resourceFilesystem struct {
	Mount            string   `json:"mount"`
	Type             string   `json:"type"`
	TotalBytes       uint64   `json:"totalBytes"`
	AvailableBytes   uint64   `json:"availableBytes"`
	UsedPercent      float64  `json:"usedPercent"`
	InodesTotal      uint64   `json:"inodesTotal"`
	InodesAvailable  uint64   `json:"inodesAvailable"`
	InodeUsedPercent *float64 `json:"inodeUsedPercent,omitempty"`
}
type resourceMetric struct {
	Schema        string               `json:"schema"`
	CapturedAt    string               `json:"capturedAt"`
	Status        string               `json:"status"`
	Issues        []string             `json:"issues"`
	CPU           map[string]any       `json:"cpu"`
	Memory        *resourceMemoryValue `json:"memory,omitempty"`
	UptimeSeconds *float64             `json:"uptimeSeconds,omitempty"`
	Network       map[string]any       `json:"network"`
	Filesystems   []resourceFilesystem `json:"filesystems"`
}

func resourceRates(old *resourceCounters, now resourceCounters) (cpu, receive, transmit *float64) {
	if old == nil {
		return
	}
	seconds := now.at.Sub(old.at).Seconds()
	if seconds <= 0 || seconds > 180 {
		return
	}
	if old.cpuKnown && now.cpuKnown && now.cpuTotal > old.cpuTotal && now.cpuIdle >= old.cpuIdle {
		total, idle := now.cpuTotal-old.cpuTotal, now.cpuIdle-old.cpuIdle
		if idle <= total {
			v := 100 * float64(total-idle) / float64(total)
			cpu = &v
		}
	}
	if old.networkKnown && now.networkKnown && now.networkReceive >= old.networkReceive {
		v := float64(now.networkReceive-old.networkReceive) / seconds
		receive = &v
	}
	if old.networkKnown && now.networkKnown && now.networkTransmit >= old.networkTransmit {
		v := float64(now.networkTransmit-old.networkTransmit) / seconds
		transmit = &v
	}
	return
}
func resourceCPU(body string) (uint64, uint64, error) {
	fields := strings.Fields(strings.SplitN(body, "\n", 2)[0])
	if len(fields) < 5 || fields[0] != "cpu" {
		return 0, 0, fmt.Errorf("CPU aggregate unavailable")
	}
	var total, idle uint64
	// guest and guest_nice are already counted in user and nice.
	for i := 1; i < len(fields) && i <= 8; i++ {
		v, err := strconv.ParseUint(fields[i], 10, 64)
		if err != nil || math.MaxUint64-total < v {
			return 0, 0, fmt.Errorf("invalid CPU aggregate")
		}
		total += v
		if i == 4 || i == 5 {
			idle += v
		}
	}
	return total, idle, nil
}
func resourceMemory(body string) (*resourceMemoryValue, error) {
	values := map[string]uint64{}
	for _, line := range strings.Split(body, "\n") {
		f := strings.Fields(line)
		if len(f) != 3 || f[2] != "kB" {
			continue
		}
		if f[0] != "MemTotal:" && f[0] != "MemAvailable:" {
			continue
		}
		n, err := strconv.ParseUint(f[1], 10, 64)
		if err != nil || n > 9007199254740991/1024 {
			return nil, fmt.Errorf("invalid memory counter")
		}
		values[f[0]] = n * 1024
	}
	total, hasTotal := values["MemTotal:"]
	available, hasAvailable := values["MemAvailable:"]
	if !hasTotal || !hasAvailable || total == 0 || available > total {
		return nil, fmt.Errorf("memory availability missing")
	}
	return &resourceMemoryValue{total, available, 100 * float64(total-available) / float64(total)}, nil
}
