package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"syscall"
)

type nginxTransaction struct {
	Path         string `json:"path"`
	BeforeSHA256 string `json:"beforeSha256"`
	AfterSHA256  string `json:"afterSha256"`
	UID          int    `json:"uid"`
	GID          int    `json:"gid"`
	Mode         uint32 `json:"mode"`
	Status       string `json:"status"`
}

func contentDigest(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }
func replaceNginxFile(path string, b []byte, mode os.FileMode, uid, gid int) error {
	if err := safePath(filepath.Dir(path), path); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".selfguard-nginx-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
	if err = tmp.Chown(uid, gid); err != nil {
		tmp.Close()
		return err
	}
	if err = tmp.Chmod(mode); err == nil {
		_, err = tmp.Write(b)
	}
	if err == nil {
		err = tmp.Sync()
	}
	err = errors.Join(err, tmp.Close())
	if err != nil {
		return err
	}
	if err = os.Rename(name, path); err != nil {
		return err
	}
	return syncParent(path)
}
func applyNginxTransaction(path, state string, after []byte, expectedBefore string, verify func() error, run func(...string) error) (resultErr error) {
	before, err := readBoundedFile(path, 256<<10)
	if err != nil {
		return err
	}
	if contentDigest(before) != expectedBefore {
		return errors.New("nginx source changed since plan; unchanged")
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || multipleLinks(info) {
		return errors.New("single regular nginx file required")
	}
	owner, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return errors.New("nginx file owner unavailable")
	}
	if err = run("-t"); err != nil {
		return errors.New("existing nginx configuration is invalid; unchanged")
	}
	if err = os.Mkdir(state, 0700); err != nil {
		return err
	}
	tx := nginxTransaction{Path: path, BeforeSHA256: contentDigest(before), AfterSHA256: contentDigest(after), Mode: uint32(info.Mode().Perm()), UID: int(owner.Uid), GID: int(owner.Gid), Status: "PREPARED"}
	if err = writePrivate(filepath.Join(state, "original.json"), before); err != nil {
		return err
	}
	if err = writePrivate(filepath.Join(state, "journal.json"), tx); err != nil {
		return err
	}
	now, err := os.ReadFile(path)
	current, statErr := os.Lstat(path)
	if err != nil || statErr != nil || !os.SameFile(info, current) || contentDigest(now) != tx.BeforeSHA256 {
		return errors.New("nginx configuration changed during preflight")
	}
	defer func() {
		if resultErr != nil {
			resultErr = errors.Join(resultErr, rollbackNginxTransaction(state, run))
		}
	}()
	if err = replaceNginxFile(path, after, info.Mode().Perm(), tx.UID, tx.GID); err != nil {
		return err
	}
	if err = run("-t"); err != nil {
		return err
	}
	if err = run("-s", "reload"); err != nil {
		return err
	}
	if err = verify(); err != nil {
		return err
	}
	tx.Status = "VERIFIED"
	return writePrivate(filepath.Join(state, "journal.json"), tx)
}
func rollbackNginxTransaction(state string, run func(...string) error) error {
	var tx nginxTransaction
	var before []byte
	if err := read(filepath.Join(state, "journal.json"), &tx); err != nil {
		return err
	}
	if err := read(filepath.Join(state, "original.json"), &before); err != nil {
		return err
	}
	if tx.Path == "" || contentDigest(before) != tx.BeforeSHA256 {
		return errors.New("rollback journal or original backup invalid")
	}
	current, err := readBoundedFile(tx.Path, 256<<10)
	if err != nil {
		return err
	}
	digest := contentDigest(current)
	if digest != tx.AfterSHA256 && digest != tx.BeforeSHA256 {
		return errors.New("nginx changed after onboarding; refusing to overwrite newer configuration")
	}
	if err = replaceNginxFile(tx.Path, before, os.FileMode(tx.Mode), tx.UID, tx.GID); err != nil {
		return err
	}
	if err = run("-t"); err != nil {
		return err
	}
	if err = run("-s", "reload"); err != nil {
		return err
	}
	tx.Status = "ROLLED_BACK"
	return writePrivate(filepath.Join(state, "journal.json"), tx)
}
