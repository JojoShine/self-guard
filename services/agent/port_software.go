package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

type PortProcess struct {
	PID  int    `json:"pid"`
	Name string `json:"name"`
}

func portServiceHint(port int) string {
	return map[int]string{22: "SSH", 25: "SMTP", 53: "DNS", 80: "HTTP", 443: "HTTPS", 1433: "SQL Server", 1521: "Oracle", 3306: "MySQL / MariaDB", 5432: "PostgreSQL", 6379: "Redis", 8080: "HTTP", 8443: "HTTPS", 27017: "MongoDB", 5236: "达梦", 54321: "金仓"}[port]
}
func processSoftware(name string) string {
	return map[string]string{"nginx": "Nginx", "mysqld": "MySQL", "mariadbd": "MariaDB", "postgres": "PostgreSQL", "postmaster": "PostgreSQL", "redis-server": "Redis", "mongod": "MongoDB", "sqlservr": "SQL Server", "oracle": "Oracle", "tnslsnr": "Oracle Listener", "dmserver": "达梦", "kingbase": "金仓", "httpd": "Apache HTTP Server", "apache2": "Apache HTTP Server", "sshd": "OpenSSH"}[name]
}
func processStart(root string) (string, error) {
	body, err := os.ReadFile(filepath.Join(root, "stat"))
	if err != nil {
		return "", err
	}
	end := strings.LastIndexByte(string(body), ')')
	if end < 0 {
		return "", fmt.Errorf("invalid process stat")
	}
	fields := strings.Fields(string(body[end+1:]))
	if len(fields) < 20 {
		return "", fmt.Errorf("missing process start")
	}
	return fields[19], nil
}

func identifyPortSoftware(root string, ports []Port) {
	byInode := map[string][]int{}
	for i := range ports {
		ports[i].Identification = "UNKNOWN"
		ports[i].ServiceHint = portServiceHint(ports[i].Port)
		if ports[i].socketInode != "" && ports[i].socketInode != "0" {
			byInode[ports[i].socketInode] = append(byInode[ports[i].socketInode], i)
		}
	}
	if len(byInode) == 0 {
		return
	}
	dir, err := os.Open(root)
	if err != nil {
		return
	}
	defer dir.Close()
	deadline := time.Now().Add(time.Second)
	examinedFDs, examinedPIDs := 0, 0
	for time.Now().Before(deadline) && examinedPIDs < 4096 && examinedFDs < 32768 {
		names, err := dir.Readdirnames(128)
		for _, name := range names {
			pid, e := strconv.Atoi(name)
			if e != nil || pid <= 0 {
				continue
			}
			examinedPIDs++
			if examinedPIDs > 4096 || !time.Now().Before(deadline) {
				return
			}
			base := filepath.Join(root, name)
			before, e := processStart(base)
			if e != nil {
				continue
			}
			// Read only executable identity, never arguments or environment values.
			executable, e := os.Readlink(filepath.Join(base, "exe"))
			if e != nil {
				continue
			}
			program := filepath.Base(strings.TrimSuffix(executable, " (deleted)"))
			if len(program) > 128 {
				continue
			}
			fdDir, e := os.Open(filepath.Join(base, "fd"))
			if e != nil {
				continue
			}
			matched := map[int]bool{}
			for examinedFDs < 32768 && time.Now().Before(deadline) {
				fds, readErr := fdDir.Readdirnames(128)
				for _, fd := range fds {
					examinedFDs++
					link, e := os.Readlink(filepath.Join(base, "fd", fd))
					if e != nil || !strings.HasPrefix(link, "socket:[") || !strings.HasSuffix(link, "]") {
						continue
					}
					for _, i := range byInode[strings.TrimSuffix(strings.TrimPrefix(link, "socket:["), "]")] {
						matched[i] = true
					}
				}
				if readErr != nil {
					break
				}
			}
			fdDir.Close()
			after, e := processStart(base)
			if e != nil || before != after {
				continue
			}
			for i := range matched {
				p := &ports[i]
				if len(p.Processes) >= 8 {
					continue
				}
				p.Processes = append(p.Processes, PortProcess{PID: pid, Name: program})
				p.Identification = "PROCESS_SOCKET"
				software := processSoftware(program)
				if software != "" {
					if p.Software == "" {
						p.Software = software
					} else if !strings.Contains(p.Software, software) {
						p.Software += " / " + software
					}
				}
			}
		}
		if err != nil {
			return
		}
	}
}
