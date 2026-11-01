//go:build linux

package main

import (
	"os"
	"syscall"
)

func multipleLinks(s os.FileInfo) bool { v, ok := s.Sys().(*syscall.Stat_t); return !ok || v.Nlink > 1 }
