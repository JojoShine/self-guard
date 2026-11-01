package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"syscall"
	"time"
)

type installationFileSnapshot struct {
	Path       string
	Existed    bool
	BeforeHash string
	AfterHash  string
	Mode       uint32
	UID        int
	GID        int
}
type installationServiceSnapshot struct {
	Name                    string
	Exists, Active, Enabled bool
}
type installationTransaction struct {
	Status              string
	InstallationID      string
	Version             string
	Connection          Config
	AcceptanceAttempted bool
	Files               []installationFileSnapshot
	Services            []installationServiceSnapshot
	ServiceManager      string
	directory           string
}

func installationHash(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }
func (t *installationTransaction) save() error {
	return writePrivate(filepath.Join(t.directory, "journal.json"), t)
}
func beginInstallationTransaction(parent, id string, paths []string) (*installationTransaction, error) {
	if id == "" || filepath.Base(id) != id || id == "." || id == ".." {
		return nil, errors.New("invalid installation transaction ID")
	}
	if err := os.MkdirAll(parent, 0700); err != nil {
		return nil, err
	}
	if err := executorTrustedDirectory(parent, true); err != nil {
		return nil, err
	}
	directory := filepath.Join(parent, id)
	if err := os.Mkdir(directory, 0700); err != nil {
		return nil, errors.New("installation transaction already exists; recover it before another attempt")
	}
	prepared := false
	defer func() {
		if !prepared {
			_ = os.RemoveAll(directory)
		}
	}()
	t := &installationTransaction{Status: "OPEN", directory: directory}
	seen := map[string]bool{}
	for i, path := range paths {
		if !filepath.IsAbs(path) || seen[path] {
			return nil, errors.New("invalid or duplicate managed installation path")
		}
		seen[path] = true
		entry := installationFileSnapshot{Path: path}
		info, err := os.Lstat(path)
		if err == nil {
			if err = executorTrustedConfig(path); err != nil {
				return nil, err
			}
			body, e := readBoundedFile(path, 64<<20)
			if e != nil {
				return nil, e
			}
			entry.Existed = true
			entry.BeforeHash = installationHash(body)
			entry.Mode = uint32(info.Mode().Perm())
			stat := info.Sys().(*syscall.Stat_t)
			entry.UID = int(stat.Uid)
			entry.GID = int(stat.Gid)
			if err = replaceFixture(filepath.Join(directory, strconv.Itoa(i)+".before"), body, 0600); err != nil {
				return nil, err
			}
		} else if !os.IsNotExist(err) {
			return nil, err
		}
		t.Files = append(t.Files, entry)
	}
	if err := t.save(); err != nil {
		return nil, err
	}
	prepared = true
	return t, nil
}
func loadInstallationTransaction(directory string, allowed []string) (*installationTransaction, error) {
	if err := executorTrustedDirectory(directory, true); err != nil {
		return nil, err
	}
	file := filepath.Join(directory, "journal.json")
	if err := executorTrustedConfig(file); err != nil {
		return nil, err
	}
	body, err := readBoundedFile(file, 1<<20)
	if err != nil {
		return nil, err
	}
	t := &installationTransaction{directory: directory}
	if err = json.Unmarshal(body, t); err != nil {
		return nil, err
	}
	if t.Status != "OPEN" && t.Status != "RECOVERY_REQUIRED" {
		return nil, errors.New("installation transaction is already finished")
	}
	if t.ServiceManager != "" && t.ServiceManager != "systemd" && t.ServiceManager != "openrc" {
		return nil, errors.New("unlisted installation service manager")
	}
	paths := map[string]bool{}
	for _, path := range allowed {
		paths[path] = true
	}
	seen := map[string]bool{}
	if len(t.Files) != len(paths) {
		return nil, errors.New("installation journal path set changed")
	}
	for _, entry := range t.Files {
		if !paths[entry.Path] || seen[entry.Path] || entry.Existed && len(entry.BeforeHash) != 64 || entry.AfterHash != "" && len(entry.AfterHash) != 64 {
			return nil, errors.New("installation journal contains unlisted or invalid paths")
		}
		seen[entry.Path] = true
	}
	for _, service := range t.Services {
		if service.Name != "selfguard-collector.service" && service.Name != "selfguard-executor.service" {
			return nil, errors.New("unlisted installation service")
		}
	}
	return t, nil
}
func (t *installationTransaction) write(path string, body []byte, mode os.FileMode) error {
	if t.Status != "OPEN" {
		return errors.New("installation transaction is not open")
	}
	for i := range t.Files {
		entry := &t.Files[i]
		if entry.Path != path {
			continue
		}
		current, err := readBoundedFile(path, 64<<20)
		if err == nil {
			digest := installationHash(current)
			if digest != entry.BeforeHash && digest != entry.AfterHash {
				return errors.New("managed file changed during installation")
			}
		} else if !os.IsNotExist(err) || entry.Existed {
			return errors.New("managed file changed during installation")
		}
		entry.AfterHash = installationHash(body)
		if err = t.save(); err != nil {
			return err
		}
		return replaceFixture(path, body, mode)
	}
	return errors.New("unlisted installation path")
}
func (t *installationTransaction) writePrivate(path string, value any) error {
	body, err := json.Marshal(value)
	if err != nil {
		return err
	}
	return t.write(path, body, 0600)
}
func (t *installationTransaction) commit() error { t.Status = "COMMITTED"; return t.save() }
func (t *installationTransaction) rollback() error {
	var failures []error
	for i := len(t.Files) - 1; i >= 0; i-- {
		entry := t.Files[i]
		if entry.AfterHash == "" {
			continue
		}
		current, err := readBoundedFile(entry.Path, 64<<20)
		if os.IsNotExist(err) && !entry.Existed {
			continue
		}
		if err != nil {
			failures = append(failures, fmt.Errorf("managed file changed or unavailable: %s", entry.Path))
			continue
		}
		digest := installationHash(current)
		if digest == entry.BeforeHash {
			continue
		}
		if digest != entry.AfterHash {
			failures = append(failures, fmt.Errorf("managed file changed; recovery did not overwrite it: %s", entry.Path))
			continue
		}
		if entry.Existed {
			before, e := readBoundedFile(filepath.Join(t.directory, strconv.Itoa(i)+".before"), 64<<20)
			if e != nil || installationHash(before) != entry.BeforeHash {
				failures = append(failures, fmt.Errorf("installation backup invalid: %s", entry.Path))
				continue
			}
			err = replaceFixture(entry.Path, before, os.FileMode(entry.Mode))
			if err == nil {
				err = os.Chown(entry.Path, entry.UID, entry.GID)
			}
		} else {
			err = removeDurable(entry.Path)
		}
		if err != nil {
			failures = append(failures, err)
		}
	}
	t.Status = "ROLLED_BACK"
	if len(failures) > 0 {
		t.Status = "RECOVERY_REQUIRED"
	}
	if err := t.save(); err != nil {
		failures = append(failures, err)
	}
	return errors.Join(failures...)
}
func installationWrite(path string, body []byte, mode os.FileMode, transactions ...*installationTransaction) error {
	if len(transactions) > 0 && transactions[0] != nil {
		return transactions[0].write(path, body, mode)
	}
	return replaceFixture(path, body, mode)
}
func installationPrivate(path string, value any, transactions ...*installationTransaction) error {
	if len(transactions) > 0 && transactions[0] != nil {
		return transactions[0].writePrivate(path, value)
	}
	return writePrivate(path, value)
}
func installationManagedPaths() []string {
	paths := []string{"/opt/selfguard-agent/current", "/opt/selfguard-agent/current.install-backup", "/opt/selfguard-agent/installation-slot.json", "/opt/selfguard-agent/installed.json", "/opt/selfguard-agent/offline-installation.json"}
	for _, file := range managedInstallationConfigFiles() {
		paths = append(paths, file, file+".selfguard-sha256")
	}
	return paths
}
func (t *installationTransaction) captureServices() error {
	manager, err := currentInstallationInit()
	if err != nil {
		return err
	}
	t.ServiceManager = manager
	for _, name := range []string{"selfguard-executor.service", "selfguard-collector.service"} {
		_, err := os.Stat(installationServicePath(name))
		entry := installationServiceSnapshot{Name: name, Exists: err == nil}
		if err != nil && !os.IsNotExist(err) {
			return err
		}
		entry.Active = installationServiceCommand("is-active", "--quiet", name) == nil
		entry.Enabled = installationServiceCommand("is-enabled", "--quiet", name) == nil
		t.Services = append(t.Services, entry)
	}
	return t.save()
}
func (t *installationTransaction) restoreServices() error {
	hasWrites := false
	for _, entry := range t.Files {
		if entry.AfterHash != "" {
			hasWrites = true
			break
		}
	}
	if !hasWrites {
		return t.rollback()
	}
	manager, err := currentInstallationInit()
	expected := t.ServiceManager
	if expected == "" {
		expected = "systemd"
	}
	if err != nil || expected != manager {
		return t.recoveryRequired(errors.New("installation service manager changed; manual recovery required"))
	}
	var failures []error
	for i := len(t.Services) - 1; i >= 0; i-- {
		s := t.Services[i]
		if err := installationServiceCommand("stop", s.Name); err != nil && s.Exists {
			failures = append(failures, err)
		}
	}
	for _, s := range t.Services {
		if !s.Exists {
			_ = installationServiceCommand("disable", s.Name)
		}
	}
	if err := t.rollback(); err != nil {
		return errors.Join(append(failures, err)...)
	}
	for _, file := range managedInstallationConfigFiles() {
		if _, _, err := readManagedInstallationFile(file); err != nil {
			return t.recoveryRequired(err)
		}
	}
	if err := installationServiceCommand("daemon-reload"); err != nil {
		failures = append(failures, err)
	}
	for _, s := range t.Services {
		if !s.Exists {
			_ = installationServiceCommand("disable", s.Name)
			continue
		}
		state := "disable"
		if s.Enabled {
			state = "enable"
		}
		if err := installationServiceCommand(state, s.Name); err != nil {
			failures = append(failures, err)
		}
		if s.Active {
			if err := installationServiceCommand("start", s.Name); err != nil {
				failures = append(failures, err)
			}
		}
	}
	if len(failures) > 0 {
		t.Status = "RECOVERY_REQUIRED"
		_ = t.save()
	}
	return errors.Join(failures...)
}

func unfinishedInstallationTransactions() error {
	const parent = "/opt/selfguard-agent/install-transactions"
	entries, err := os.ReadDir(parent)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if !entry.IsDir() {
			return errors.New("unexpected installation transaction entry")
		}
		var journal installationTransaction
		if err = read(filepath.Join(parent, entry.Name(), "journal.json"), &journal); err != nil {
			return err
		}
		if journal.Status != "COMMITTED" && journal.Status != "ROLLED_BACK" {
			return fmt.Errorf("unfinished installation %s; run --recover-installation before retrying", entry.Name())
		}
	}
	return nil
}
func recoverInstallation(id string, output io.Writer) error {
	if err := executorPlatform(); err != nil {
		return err
	}
	if err := requireInstallationHost(); err != nil {
		return err
	}
	if id == "" || filepath.Base(id) != id || id == "." || id == ".." {
		return errors.New("invalid installation recovery ID")
	}
	unlock, err := installationLock()
	if err != nil {
		return err
	}
	defer unlock()
	tx, err := loadInstallationTransaction(filepath.Join("/opt/selfguard-agent/install-transactions", id), installationManagedPaths())
	if err != nil {
		return err
	}
	accepted, recoveryErr := tx.recoverInstallation()
	if recoveryErr != nil {
		return recoveryErr
	}
	if accepted {
		fmt.Fprintln(output, "平台已验收此安装，保留当前版本并完成本地日志；未执行覆盖回退。")
		return nil
	}
	fmt.Fprintln(output, "本次受管文件和原服务状态已恢复；身份、密钥、任务收据、最高序列与平台历史保留。")
	return nil
}

func (t *installationTransaction) platformRecovery(phase string) (bool, error) {
	if t.InstallationID == "" {
		return false, nil
	}
	c := t.Connection
	if !managedStatePath.MatchString(c.StateDir) {
		return false, errors.New("invalid recovery identity directory")
	}
	var identity Identity
	if err := read(filepath.Join(c.StateDir, "identity.json"), &identity); err != nil {
		return false, err
	}
	if identity.Token == "" {
		return false, errors.New("recovery identity credential missing")
	}
	client, err := clientForConfig(c)
	if err != nil {
		return false, err
	}
	var response struct {
		Accepted bool `json:"accepted"`
	}
	err = installationRequest(client, c.Server, t.InstallationID, "recovery", identity.Token, map[string]string{"phase": phase}, &response)
	return response.Accepted, err
}
func (t *installationTransaction) recoveryRequired(err error) error {
	t.Status = "RECOVERY_REQUIRED"
	return errors.Join(err, t.save())
}
func (t *installationTransaction) recoverInstallation() (bool, error) {
	accepted, prepareErr := t.platformRecovery("PREPARE")
	if prepareErr != nil && t.AcceptanceAttempted {
		return false, t.recoveryRequired(errors.New("platform acceptance is uncertain; reconnect and reconcile before overwriting local files"))
	}
	if accepted {
		return true, t.commit()
	}
	if err := t.restoreServices(); err != nil {
		return false, err
	}
	if t.InstallationID != "" {
		if prepareErr != nil {
			accepted, err := t.platformRecovery("PREPARE")
			if err != nil {
				return false, t.recoveryRequired(errors.New("local deployment restored; platform recovery report is pending"))
			}
			if accepted {
				return false, t.recoveryRequired(errors.New("platform accepted during local recovery; explicit reconciliation required"))
			}
		}
		if _, err := t.platformRecovery("COMPLETE"); err != nil {
			return false, t.recoveryRequired(errors.New("local deployment restored; platform recovery report is pending"))
		}
	}
	return false, nil
}

func waitInstallationFile(path string, timeout time.Duration) (func(), error) {
	deadline := time.Now().Add(timeout)
	for {
		unlock, err := lockInstallationFile(path)
		if err == nil {
			return unlock, nil
		}
		if (!errors.Is(err, syscall.EWOULDBLOCK) && !errors.Is(err, syscall.EAGAIN)) || !time.Now().Before(deadline) {
			return nil, err
		}
		delay := 50 * time.Millisecond
		if remaining := time.Until(deadline); remaining < delay {
			delay = remaining
		}
		time.Sleep(delay)
	}
}
