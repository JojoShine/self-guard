//go:build !linux

package main

import "os"

func fileIdentity(s os.FileInfo) string { return "" }
