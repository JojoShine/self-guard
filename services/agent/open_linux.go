//go:build linux

package main

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

func openTarget(path string) (*os.File, error)   { return openSecure(path, false) }
func openWritable(path string) (*os.File, error) { return openSecure(path, true) }
func openSecure(path string, writable bool) (*os.File, error) {
	path, e := filepath.Abs(path)
	if e != nil {
		return nil, e
	}
	fd, e := syscall.Open("/", syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_CLOEXEC, 0)
	if e != nil {
		return nil, e
	}
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	for i, part := range parts {
		flags := syscall.O_RDONLY | syscall.O_NOFOLLOW | syscall.O_CLOEXEC | syscall.O_NONBLOCK
		if i == len(parts)-1 && writable {
			flags = (flags &^ syscall.O_RDONLY) | syscall.O_RDWR
		}
		if i < len(parts)-1 {
			flags |= syscall.O_DIRECTORY
		}
		next, err := syscall.Openat(fd, part, flags, 0)
		syscall.Close(fd)
		if err != nil {
			return nil, err
		}
		fd = next
	}
	return os.NewFile(uintptr(fd), path), nil
}
