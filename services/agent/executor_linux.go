package main

import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"syscall"
)

func executorPlatform() error {
	if os.Geteuid() != 0 {
		return errors.New("privileged executor requires root")
	}
	return nil
}
func executorTrustedDirectory(path string, private bool) error {
	if err := executorProtectedParents(filepath.Dir(path)); err != nil {
		return err
	}
	if err := safePath(path, path); err != nil {
		return err
	}
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 || !info.IsDir() || info.Mode().Perm()&0022 != 0 || (private && info.Mode().Perm()&0077 != 0) {
		return errors.New("executor directory must be root-owned and protected")
	}
	return nil
}
func executorPeer(connection net.Conn, uid uint32) error {
	unix, ok := connection.(*net.UnixConn)
	if !ok {
		return errors.New("Unix peer required")
	}
	raw, err := unix.SyscallConn()
	if err != nil {
		return err
	}
	var credential *syscall.Ucred
	var credentialErr error
	if err = raw.Control(func(fd uintptr) {
		credential, credentialErr = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	}); err != nil {
		return err
	}
	if credentialErr != nil {
		return credentialErr
	}
	if credential == nil || credential.Uid != uid {
		return errors.New("peer UID mismatch")
	}
	return nil
}

func executorTrustedConfig(path string) error {
	if err := executorProtectedParents(filepath.Dir(path)); err != nil {
		return err
	}
	if path == "" {
		return errors.New("executor requires root-owned AGENT_CONFIG")
	}
	if err := safePath(path, path); err != nil {
		return err
	}
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 || !info.Mode().IsRegular() || multipleLinks(info) || info.Mode().Perm()&0022 != 0 {
		return errors.New("executor config must be root-owned and protected")
	}
	return nil
}

func executorProtectedParents(path string) error {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	for current := absolute; ; current = filepath.Dir(current) {
		info, err := os.Lstat(current)
		if err != nil {
			return err
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || stat.Uid != 0 || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || (info.Mode().Perm()&0022 != 0 && info.Mode()&os.ModeSticky == 0) {
			return errors.New("executor path ancestors must be root-owned and protected")
		}
		if current == filepath.Dir(current) {
			return nil
		}
	}
}

func executorPrivateKeyFile(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 || !info.Mode().IsRegular() || multipleLinks(info) || info.Mode().Perm() != 0600 {
		return errors.New("executor result key must be root-owned private0600 regular file")
	}
	return nil
}
