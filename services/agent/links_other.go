//go:build !linux

package main

import "os"

func multipleLinks(s os.FileInfo) bool { return true }
