//go:build linux

package main

import (
	"fmt"
	"os"
	"syscall"
)

func fileIdentity(s os.FileInfo) string {
	if stat, ok := s.Sys().(*syscall.Stat_t); ok {
		return fmt.Sprintf("%d:%d", stat.Dev, stat.Ino)
	}
	return ""
}
