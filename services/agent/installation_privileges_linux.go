package main

import (
	"errors"
	"syscall"
)

func requireNoNewPrivileges() error {
	value, _, err := syscall.RawSyscall6(syscall.SYS_PRCTL, 39, 0, 0, 0, 0, 0)
	if err != 0 {
		return err
	}
	if value != 1 {
		return errors.New("OpenRC supervisor must apply NoNewPrivileges before exec")
	}
	return nil
}
