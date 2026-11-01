package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"time"
)

type UpgradeManifest struct {
	Version      string    `json:"version"`
	Sequence     uint64    `json:"sequence"`
	SHA256       string    `json:"sha256"`
	Size         int64     `json:"size"`
	OS           string    `json:"os"`
	Architecture string    `json:"architecture"`
	ExpiresAt    time.Time `json:"expiresAt"`
}
type SignedUpgrade struct {
	Manifest  json.RawMessage `json:"manifest"`
	Signature string          `json:"signature"`
}
type upgradeBackup struct {
	Content  []byte
	Mode     os.FileMode
	Previous UpgradeManifest
}

// Installation is explicitly configured; replacing an on-disk slot requires a supervisor restart.
func upgradeRoot(c Config) (string, error) {
	configured := c.UpgradeInstallRoot
	if configured == "" {
		configured = c.UpgradeFixtureRoot
	}
	root, err := filepath.Abs(configured)
	if configured == "" || err != nil {
		return "", errors.New("upgrade installation root required")
	}
	if err = safePath(root, root); err != nil {
		return "", err
	}
	info, err := os.Stat(root)
	if err != nil || !info.IsDir() || info.Mode().Perm()&0022 != 0 {
		return "", errors.New("upgrade installation root must be a trusted private directory")
	}
	if c.UpgradeInstallRoot == "" {
		marker, err := os.ReadFile(filepath.Join(root, ".selfguard-upgrade-fixture"))
		if err != nil || string(marker) != "offline fixture only\n" {
			return "", errors.New("offline fixture marker required")
		}
	}
	target := filepath.Join(root, "current")
	s, err := os.Lstat(target)
	if err != nil || !s.Mode().IsRegular() || multipleLinks(s) {
		return "", errors.New("installation current must be a regular single-link file")
	}
	running, err := os.Executable()
	if err != nil {
		return "", err
	}
	actual, err := os.Stat(running)
	if err != nil || (os.SameFile(s, actual) && !c.remoteUpgrade) {
		return "", errors.New("run the updater from a separate trusted executable; running updater cannot replace itself")
	}
	return root, nil
}
func readBoundedFile(path string, limit int64) ([]byte, error) {
	f, err := openTarget(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	s, err := f.Stat()
	if err != nil || !s.Mode().IsRegular() || s.Size() > limit {
		return nil, errors.New("invalid or oversized file")
	}
	b, err := io.ReadAll(io.LimitReader(f, limit+1))
	if len(b) > int(limit) {
		return nil, errors.New("file size limit exceeded")
	}
	return b, err
}
func replaceFixture(path string, b []byte, mode os.FileMode) error {
	f, err := os.CreateTemp(filepath.Dir(path), ".selfguard-write-*")
	if err != nil {
		return err
	}
	temporary := f.Name()
	defer os.Remove(temporary)
	if err = f.Chmod(mode.Perm()); err != nil {
		f.Close()
		return err
	}
	_, err = f.Write(b)
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	if err = os.Rename(temporary, path); err != nil {
		return err
	}
	return syncParent(path)
}
func stageUpgrade(c Config, envelope SignedUpgrade, candidate []byte, health func(string) error) error {
	root, err := upgradeRoot(c)
	if err != nil {
		return err
	}
	marker := filepath.Join(root, "upgrade-recovery.json")
	if _, err = os.Stat(marker); !os.IsNotExist(err) {
		return errors.New("upgrade recovery pending; explicitly roll back fixture first")
	}
	key, err := base64.StdEncoding.DecodeString(c.UpgradePublicKey)
	if err != nil || len(key) != ed25519.PublicKeySize {
		return errors.New("configured Ed25519 trust key required")
	}
	sig, err := base64.StdEncoding.DecodeString(envelope.Signature)
	if err != nil || !ed25519.Verify(ed25519.PublicKey(key), envelope.Manifest, sig) {
		return errors.New("upgrade signature invalid")
	}
	var m UpgradeManifest
	if err = json.Unmarshal(envelope.Manifest, &m); err != nil {
		return err
	}
	if m.Version == "" || m.Sequence == 0 || m.Size < 1 || m.Size > 64<<20 || int64(len(candidate)) != m.Size || m.OS != runtime.GOOS || m.Architecture != runtime.GOARCH || !m.ExpiresAt.After(time.Now()) {
		return errors.New("invalid upgrade manifest or target")
	}
	sum := sha256.Sum256(candidate)
	if m.SHA256 != hex.EncodeToString(sum[:]) {
		return errors.New("upgrade content checksum mismatch")
	}
	var previous UpgradeManifest
	if err = read(filepath.Join(root, "installed.json"), &previous); err != nil {
		return err
	}
	var highest UpgradeManifest
	if err = read(filepath.Join(root, "highest-sequence.json"), &highest); err != nil {
		return err
	}
	if m.Sequence <= previous.Sequence || m.Sequence <= highest.Sequence {
		return errors.New("upgrade replay or downgrade refused")
	}
	target := filepath.Join(root, "current")
	before, err := readBoundedFile(target, 64<<20)
	if err != nil {
		return err
	}
	s, err := os.Stat(target)
	if err != nil {
		return err
	}
	if err = writePrivate(filepath.Join(root, "upgrade-backup.json"), upgradeBackup{before, s.Mode().Perm(), previous}); err != nil {
		return err
	}
	if err = writePrivate(marker, map[string]string{"status": "rollback required if interrupted", "version": m.Version}); err != nil {
		return err
	}
	candidateMode := os.FileMode(0700)
	if c.upgradePublicExecutable {
		candidateMode = 0755
	}
	if err = replaceFixture(target, candidate, candidateMode); err == nil {
		actual, e := readBoundedFile(target, 64<<20)
		if e != nil || !bytes.Equal(actual, candidate) {
			err = errors.New("installed content mismatch")
		}
	}
	if err == nil {
		err = health(target)
	}
	if err == nil {
		err = writePrivate(filepath.Join(root, "highest-sequence.json"), m)
		if err == nil {
			err = writePrivate(filepath.Join(root, "installed.json"), m)
		}
	}
	if err != nil {
		rollbackErr := rollbackUpgrade(c)
		return fmt.Errorf("upgrade failed: %v; rollback: %v", err, rollbackErr)
	}
	if err = writeUpgradeStatus(filepath.Join(root, "upgrade-status.json"), map[string]any{"status": "STAGED_PENDING_RESTART", "version": m.Version, "sequence": m.Sequence, "path": target, "at": time.Now().UTC()}); err != nil {
		return err
	}
	return removeDurable(marker)
}
func rollbackUpgrade(c Config) error {
	root, err := upgradeRoot(c)
	if err != nil {
		return err
	}
	var backup upgradeBackup
	backupPath := filepath.Join(root, "upgrade-backup.json")
	if _, err = os.Stat(backupPath); err != nil {
		return err
	}
	if err = read(backupPath, &backup); err != nil {
		return err
	}
	if len(backup.Content) > 64<<20 {
		return errors.New("invalid backup")
	}
	if err = replaceFixture(filepath.Join(root, "current"), backup.Content, backup.Mode); err != nil {
		return err
	}
	if err = writePrivate(filepath.Join(root, "installed.json"), backup.Previous); err != nil {
		return err
	}
	if err = writeUpgradeStatus(filepath.Join(root, "upgrade-status.json"), map[string]any{"status": "ROLLED_BACK_PENDING_RESTART", "version": backup.Previous.Version, "path": filepath.Join(root, "current"), "at": time.Now().UTC()}); err != nil {
		return err
	}
	marker := filepath.Join(root, "upgrade-recovery.json")
	if _, err = os.Stat(marker); os.IsNotExist(err) {
		return nil
	}
	return removeDurable(marker)
}
func candidateHealth(path string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c := exec.CommandContext(ctx, path, "--self-test")
	out := &cappedOutput{}
	c.Stdout = out
	c.Stderr = out
	if err := c.Run(); err != nil {
		return errors.New("candidate self-test failed")
	}
	if string(out.b) != "selfguard-agent: healthy\n" || out.truncated {
		return errors.New("candidate self-test response invalid")
	}
	return nil
}

func (a *Agent) upgradeStatus() any {
	root := a.Config.UpgradeInstallRoot
	if root == "" {
		return map[string]string{"status": "DISABLED"}
	}
	if _, err := os.Stat(filepath.Join(root, "upgrade-recovery.json")); err == nil {
		return map[string]string{"status": "RECOVERY_REQUIRED"}
	}
	var status map[string]any
	if err := read(filepath.Join(root, "upgrade-status.json"), &status); err != nil {
		return map[string]string{"status": "UNREADABLE"}
	}
	if status == nil {
		return map[string]string{"status": "NO_STAGED_UPGRADE"}
	}
	if _, err := os.Stat(filepath.Join(root, "upgrade-recovery.json")); err == nil {
		status["status"] = "RECOVERY_REQUIRED"
	}
	return status
}

// Status contains no credentials or executable contents and must be readable by the unprivileged service.
func writeUpgradeStatus(path string, status any) error {
	if err := writePrivate(path, status); err != nil {
		return err
	}
	if err := os.Chmod(path, 0644); err != nil {
		return err
	}
	f, err := openTarget(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}
