//go:build !linux

package main

import "errors"

func requireNoNewPrivileges() error { return errors.New("OpenRC service requires Linux") }
