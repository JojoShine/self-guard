package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestInstallationRollbackOnlyRestoresItsOwnExactWritesAndRetainsIdentity(t *testing.T) {
	root := t.TempDir()
	program := filepath.Join(root, "current")
	config := filepath.Join(root, "collector.json")
	identity := filepath.Join(root, "identity.json")
	os.WriteFile(program, []byte("old signed executable"), 0755)
	os.WriteFile(identity, []byte("persistent identity"), 0600)
	journal, err := beginInstallationTransaction(filepath.Join(root, "transactions"), "fixture", []string{program, config})
	if err != nil {
		t.Fatal(err)
	}
	if err = journal.write(program, []byte("new signed executable"), 0755); err != nil {
		t.Fatal(err)
	}
	if err = journal.write(config, []byte("new config"), 0640); err != nil {
		t.Fatal(err)
	}
	if err = journal.rollback(); err != nil {
		t.Fatal(err)
	}
	body, _ := os.ReadFile(program)
	if string(body) != "old signed executable" {
		t.Fatal("old program lost")
	}
	if _, err = os.Stat(config); !os.IsNotExist(err) {
		t.Fatal("new config not removed")
	}
	body, _ = os.ReadFile(identity)
	if string(body) != "persistent identity" {
		t.Fatal("identity changed")
	}
	next, err := beginInstallationTransaction(filepath.Join(root, "transactions"), "conflict", []string{program})
	if err != nil {
		t.Fatal(err)
	}
	next.write(program, []byte("our candidate"), 0755)
	os.WriteFile(program, []byte("administrator change"), 0755)
	if err = next.rollback(); err == nil || !strings.Contains(err.Error(), "changed") {
		t.Fatal("concurrent edit overwritten", err)
	}
	body, _ = os.ReadFile(program)
	if string(body) != "administrator change" {
		t.Fatal("administrator file lost")
	}
}
func TestInstallationJournalSurvivesRestartAndRejectsUnlistedPaths(t *testing.T) {
	root := t.TempDir()
	file := filepath.Join(root, "current")
	os.WriteFile(file, []byte("before"), 0755)
	tx, err := beginInstallationTransaction(filepath.Join(root, "transactions"), "crash", []string{file})
	if err != nil {
		t.Fatal(err)
	}
	if err = tx.write(filepath.Join(root, "identity.json"), []byte("bad"), 0600); err == nil {
		t.Fatal("identity was writable through transaction")
	}
	tx.write(file, []byte("after"), 0755)
	recovered, err := loadInstallationTransaction(tx.directory, []string{file})
	if err != nil {
		t.Fatal(err)
	}
	if err = recovered.rollback(); err != nil {
		t.Fatal(err)
	}
	body, _ := os.ReadFile(file)
	if string(body) != "before" {
		t.Fatal("restart rollback failed")
	}
	if _, err = loadInstallationTransaction(tx.directory, []string{filepath.Join(root, "unrelated")}); err == nil {
		t.Fatal("journal expanded allowed files")
	}
}

func TestInstallationLockDoesNotStayStaleAfterRelease(t *testing.T) {
	path := filepath.Join(t.TempDir(), "install.lock")
	unlock, err := lockInstallationFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if other, err := lockInstallationFile(path); err == nil {
		other()
		t.Fatal("concurrent installer obtained lock")
	}
	unlock()
	next, err := lockInstallationFile(path)
	if err != nil {
		t.Fatal("released installer left a stale lock", err)
	}
	next()
	if _, err = os.Stat(path); err != nil {
		t.Fatal("persistent lock inode removed", err)
	}
}

func TestInstallationJournalDoesNotReuseOrDeleteUntrackedTemporaryFiles(t *testing.T) {
	root := t.TempDir()
	file := filepath.Join(root, "current")
	os.WriteFile(file, []byte("old"), 0755)
	os.WriteFile(file+".staged", []byte("untracked interrupted or administrator file"), 0600)
	tx, err := beginInstallationTransaction(filepath.Join(root, "transactions"), "temporary", []string{file})
	if err != nil {
		t.Fatal(err)
	}
	if err = tx.write(file, []byte("candidate"), 0755); err != nil {
		t.Fatal("untracked temporary file blocked recoverable atomic write", err)
	}
	if err = tx.rollback(); err != nil {
		t.Fatal(err)
	}
	body, _ := os.ReadFile(file + ".staged")
	if string(body) != "untracked interrupted or administrator file" {
		t.Fatal("untracked file removed")
	}
}

func TestInstallationPreflightRejectsUnknownProgramOrConfigurationWithoutMutation(t *testing.T) {
	root := t.TempDir()
	config := filepath.Join(root, "collector.json")
	if err := installManagedBinary(root, []byte("trusted old"), 1); err != nil {
		t.Fatal(err)
	}
	writeInstallationManagedFile(config, []byte("managed config"), 0600)
	if err := preflightInstallationFiles(root, []byte("trusted candidate"), 2, []string{config}); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(config, []byte("administrator edit"), 0600)
	if err := preflightInstallationFiles(root, []byte("trusted candidate"), 2, []string{config}); err == nil {
		t.Fatal("unknown configuration accepted")
	}
	body, _ := os.ReadFile(filepath.Join(root, "current"))
	if string(body) != "trusted old" {
		t.Fatal("preflight changed executable")
	}
	os.WriteFile(filepath.Join(root, "current"), []byte("unknown executable"), 0755)
	if err := preflightInstallationFiles(root, []byte("trusted candidate"), 2, nil); err == nil {
		t.Fatal("unknown executable accepted")
	}
}
func TestInstallationRecoveryDoesNotRestartServicesWhenNothingWasWritten(t *testing.T) {
	root := t.TempDir()
	file := filepath.Join(root, "current")
	os.WriteFile(file, []byte("before"), 0755)
	tx, err := beginInstallationTransaction(filepath.Join(root, "transactions"), "untouched", []string{file})
	if err != nil {
		t.Fatal(err)
	}
	tx.Services = []installationServiceSnapshot{{Name: "selfguard-collector.service", Exists: true, Active: true, Enabled: true}}
	if err = tx.restoreServices(); err != nil {
		t.Fatal("untouched installation attempted service operations", err)
	}
}
