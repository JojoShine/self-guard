package main

import (
	"os"
	"path/filepath"
)

func syncParent(path string) error {
	d, e := os.Open(filepath.Dir(path))
	if e != nil {
		return e
	}
	defer d.Close()
	return d.Sync()
}
func removeDurable(path string) error {
	if e := os.Remove(path); e != nil {
		return e
	}
	return syncParent(path)
}
