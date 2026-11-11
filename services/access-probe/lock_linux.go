//go:build linux

package main

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
)

var errQueueOwned = errors.New("probe queue already owned by another worker")

func lockQueue(dir string) (func(), error) {
	fd, err := syscall.Open(filepath.Join(dir, "worker.lock"), syscall.O_CREAT|syscall.O_RDWR|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), "worker.lock")
	if err = syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		return nil, errQueueOwned
	}
	return func() { f.Close() }, nil
}
