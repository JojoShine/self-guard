package main

import (
	"testing"
	"time"
)

func TestResourceCounterRatesAndReset(t *testing.T) {
	old := resourceCounters{cpuKnown: true, networkKnown: true, at: time.Unix(1000, 0), cpuTotal: 100, cpuIdle: 50, networkReceive: 100, networkTransmit: 200}
	now := resourceCounters{cpuKnown: true, networkKnown: true, at: time.Unix(1010, 0), cpuTotal: 200, cpuIdle: 75, networkReceive: 300, networkTransmit: 500}
	cpu, receive, transmit := resourceRates(&old, now)
	if cpu == nil || *cpu != 75 || receive == nil || *receive != 20 || transmit == nil || *transmit != 30 {
		t.Fatal("wrong rates")
	}
	partial := now
	partial.networkKnown = false
	if cpu, rx, _ := resourceRates(&old, partial); cpu == nil || rx != nil {
		t.Fatal("network failure hid valid CPU measurement")
	}
	if cpu, receive, _ := resourceRates(nil, now); cpu != nil || receive != nil {
		t.Fatal("first sample must remain unknown")
	}
	if cpu, receive, _ := resourceRates(&now, old); cpu != nil || receive != nil {
		t.Fatal("reset must remain unknown")
	}
}
func TestResourceProcParsing(t *testing.T) {
	total, idle, err := resourceCPU("cpu  10 2 3 40 5 1 1 0 7 2\ncpu0 0 0 0 0\n")
	if err != nil || total != 62 || idle != 45 {
		t.Fatal("guest time double counted", total, idle, err)
	}
	if _, _, err := resourceCPU("cpu 1 bad 3"); err == nil {
		t.Fatal("malformed CPU accepted")
	}
	memory, err := resourceMemory("MemTotal: 1000 kB\nMemFree: 100 kB\nMemAvailable: 400 kB\n")
	if err != nil || memory.TotalBytes != 1024000 || memory.AvailableBytes != 409600 || memory.UsedPercent != 60 {
		t.Fatal("wrong available memory", memory, err)
	}
	if _, err := resourceMemory("MemTotal: 1000 kB\nMemFree: 100 kB\n"); err == nil {
		t.Fatal("missing available memory must not invent a value")
	}
}
