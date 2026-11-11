//go:build linux

package main

import (
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"syscall"
)

type Batch struct {
	BatchID string  `json:"batchId"`
	Mode    string  `json:"mode"`
	Events  []Event `json:"events"`
	Health  Health  `json:"health"`
}
type Pending struct {
	Batch Batch  `json:"batch"`
	Next  Cursor `json:"next"`
}
type State struct {
	Cursor  Cursor   `json:"cursor"`
	Pending *Pending `json:"pending,omitempty"`
	Invalid uint64   `json:"invalid"`
	Skipped uint64   `json:"skipped"`
	Gaps    uint64   `json:"gaps"`
}

func lockState(dir string) (func(), error) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	if err := os.Chmod(dir, 0700); err != nil {
		return nil, err
	}
	fd, e := syscall.Open(filepath.Join(dir, "writer.lock"), syscall.O_CREAT|syscall.O_RDWR|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0600)
	if e != nil {
		return nil, e
	}
	f := os.NewFile(uintptr(fd), "writer.lock")
	if e = syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB); e != nil {
		f.Close()
		return nil, errors.New("state already owned")
	}
	return func() { f.Close() }, nil
}
func loadState(dir string) (State, error) {
	var st State
	f, e := os.Open(filepath.Join(dir, "state.json"))
	if os.IsNotExist(e) {
		return st, nil
	}
	if e != nil {
		return st, e
	}
	defer f.Close()
	b, e := io.ReadAll(io.LimitReader(f, 2*1024*1024+1))
	if e != nil {
		return st, e
	}
	if len(b) > 2*1024*1024 {
		return st, errors.New("state too large")
	}
	e = json.Unmarshal(b, &st)
	return st, e
}
func saveState(dir string, st State) error {
	b, e := json.Marshal(st)
	if e != nil {
		return e
	}
	f, e := os.CreateTemp(dir, ".state-")
	if e != nil {
		return e
	}
	name := f.Name()
	defer os.Remove(name)
	if _, e = f.Write(b); e == nil {
		e = f.Sync()
	}
	ce := f.Close()
	if e != nil {
		return e
	}
	if ce != nil {
		return ce
	}
	if e = os.Rename(name, filepath.Join(dir, "state.json")); e != nil {
		return e
	}
	d, e := os.Open(dir)
	if e != nil {
		return e
	}
	defer d.Close()
	return d.Sync()
}
