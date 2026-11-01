//go:build !linux

package main

import (
	"errors"
	"net"
)

func executorPlatform() error                     { return errors.New("privileged executor requires Linux") }
func executorTrustedDirectory(string, bool) error { return executorPlatform() }
func executorPeer(net.Conn, uint32) error         { return executorPlatform() }

func executorTrustedConfig(string) error { return executorPlatform() }

func executorPrivateKeyFile(string) error { return executorPlatform() }
