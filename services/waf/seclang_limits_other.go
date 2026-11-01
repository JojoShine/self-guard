//go:build !linux

package main

import "runtime/debug"

func applySecLangWorkerLimits() error { debug.SetMemoryLimit(128 << 20); return nil }
