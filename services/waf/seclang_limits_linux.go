//go:build linux

package main

import (
	"runtime/debug"
	"syscall"
)

func applySecLangWorkerLimits() error {
	debug.SetMemoryLimit(128 << 20)
	return syscall.Setrlimit(syscall.RLIMIT_CPU, &syscall.Rlimit{Cur: 2, Max: 2})
}
