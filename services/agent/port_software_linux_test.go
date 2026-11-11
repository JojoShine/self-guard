//go:build linux

package main

import (
	"net"
	"os"
	"testing"
)

func TestPortSoftwareAssociatesActualListeningSocket(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	port := listener.Addr().(*net.TCPAddr).Port
	rows, _ := portInventory("/proc/net")
	for _, row := range rows {
		if row.Protocol != "tcp" || row.Port != port {
			continue
		}
		for _, process := range row.Processes {
			if process.PID == os.Getpid() && row.Identification == "PROCESS_SOCKET" {
				return
			}
		}
		t.Fatalf("live socket owner missing: %+v", row)
	}
	t.Fatal("live listening socket missing")
}
