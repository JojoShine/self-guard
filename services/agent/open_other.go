//go:build !linux

package main

import (
	"errors"
	"os"
)

func openTarget(path string) (*os.File, error) {
	return nil, errors.New("permission remediation requires Linux secure descriptor traversal")
}

func openWritable(path string) (*os.File, error) { return openTarget(path) }
