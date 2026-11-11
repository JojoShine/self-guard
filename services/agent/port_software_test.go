package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPortSoftwareUsesSocketOwnershipRatherThanPortNumber(t *testing.T) {
	root := t.TempDir()
	netRoot := filepath.Join(root, "net")
	os.Mkdir(netRoot, 0700)
	header := "sl local_address rem_address st tx rx tr tm retr uid inode\n"
	for _, name := range []string{"tcp", "tcp6", "udp", "udp6"} {
		os.WriteFile(filepath.Join(netRoot, name), []byte(header), 0600)
	}
	os.WriteFile(filepath.Join(netRoot, "tcp"), []byte(header+"0: 00000000:0CEA 00000000:0000 0A 0:0 0:0 0 100 0 456\n1: 00000000:18EB 00000000:0000 0A 0:0 0:0 0 100 0 999\n"), 0600)
	pid := filepath.Join(root, "42")
	os.MkdirAll(filepath.Join(pid, "fd"), 0700)
	os.WriteFile(filepath.Join(pid, "comm"), []byte("nginx\n"), 0600)
	os.WriteFile(filepath.Join(pid, "stat"), []byte("42 (nginx) S "+strings.Repeat("0 ", 18)+"1234 0"), 0600)
	os.Symlink("/usr/sbin/nginx", filepath.Join(pid, "exe"))
	os.Symlink("socket:[456]", filepath.Join(pid, "fd", "3"))
	ports, status := portInventory(netRoot)
	if !status.Complete || len(ports) != 2 {
		t.Fatalf("inventory: %+v %+v", ports, status)
	}
	if ports[0].Software != "Nginx" || ports[0].Identification != "PROCESS_SOCKET" || len(ports[0].Processes) != 1 || ports[0].Processes[0].PID != 42 {
		t.Fatalf("3306 must be identified from actual nginx process: %+v", ports[0])
	}
	if ports[1].Software != "" || ports[1].Identification != "UNKNOWN" || ports[1].ServiceHint != "Redis" {
		t.Fatalf("unowned 6379 is only a hint: %+v", ports[1])
	}
}
func TestPortSoftwareDoesNotNeedProcessAccessOrReadArguments(t *testing.T) {
	ports := []Port{{Protocol: "tcp", Address: "0.0.0.0", Port: 5432, State: "LISTEN"}}
	identifyPortSoftware(filepath.Join(t.TempDir(), "absent"), ports)
	if ports[0].Software != "" || ports[0].Identification != "UNKNOWN" || ports[0].ServiceHint != "PostgreSQL" {
		t.Fatalf("missing proc must remain unknown: %+v", ports[0])
	}
}
