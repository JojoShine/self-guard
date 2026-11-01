package main

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
)

func managedInstallationConfigFiles() []string {
	return []string{"/etc/selfguard-agent/collector.json", "/etc/selfguard-agent/executor.json", installationServicePath("selfguard-collector.service"), installationServicePath("selfguard-executor.service")}
}
func preflightInstallationFiles(root string, candidate []byte, sequence uint64, managed []string) error {
	var slot installationSlot
	if _, err := os.Lstat(filepath.Join(root, "installation-slot.json")); err == nil {
		if err = executorTrustedConfig(filepath.Join(root, "installation-slot.json")); err != nil {
			return err
		}
		if err = read(filepath.Join(root, "installation-slot.json"), &slot); err != nil {
			return err
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	digest := installationHash(candidate)
	if slot.Sequence > sequence || slot.Sequence == sequence && slot.SHA256 != digest {
		return errors.New("installation sequence or content conflict")
	}
	path := filepath.Join(root, "current")
	if _, err := os.Lstat(path); err == nil {
		if slot.Sequence == 0 {
			return errors.New("existing executable is unmanaged")
		}
		if err = executorTrustedConfig(path); err != nil {
			return err
		}
		before, e := readBoundedFile(path, 64<<20)
		if e != nil {
			return e
		}
		actual := installationHash(before)
		if actual != slot.SHA256 && actual != digest && !trustedInstalledExecutable(root, actual, slot.Sequence, int64(len(before))) {
			return errors.New("existing executable changed; no service restart or file replacement performed")
		}
	} else if !os.IsNotExist(err) {
		return err
	} else if slot.Sequence > 0 {
		return errors.New("managed executable missing; explicit recovery required")
	}
	for _, file := range managed {
		if _, _, err := readManagedInstallationFile(file); err != nil {
			return err
		}
	}
	return nil
}
func readManagedInstallationFile(path string) ([]byte, bool, error) {
	marker := path + ".selfguard-sha256"
	if _, err := os.Lstat(path); os.IsNotExist(err) {
		if _, e := os.Lstat(marker); e == nil {
			return nil, false, errors.New("managed file missing; recovery required")
		} else if !os.IsNotExist(e) {
			return nil, false, e
		}
		return nil, false, nil
	} else if err != nil {
		return nil, false, err
	}
	if err := executorTrustedConfig(path); err != nil {
		return nil, false, err
	}
	if err := executorTrustedConfig(marker); err != nil {
		return nil, false, err
	}
	before, err := readBoundedFile(path, 1<<20)
	if err != nil {
		return nil, false, err
	}
	expected, err := readBoundedFile(marker, 128)
	if err != nil || string(expected) != installationHash(before) {
		return nil, false, errors.New("existing managed file changed or was not installed by this installer")
	}
	return before, true, nil
}

// Upgrade metadata and installer slots are both root-owned integrity receipts.
// A completed upgrade may advance installed/highest before an older installer slot.
func trustedInstalledExecutable(root, digest string, slotSequence uint64, size int64) bool {
	for _, name := range []string{"installed.json", "highest-sequence.json"} {
		if executorTrustedConfig(filepath.Join(root, name)) != nil {
			return false
		}
	}
	var installed, highest UpgradeManifest
	if read(filepath.Join(root, "installed.json"), &installed) != nil || read(filepath.Join(root, "highest-sequence.json"), &highest) != nil {
		return false
	}
	return installed.SHA256 == digest && installed.Size == size && installed.Sequence > slotSequence && installed.Sequence <= highest.Sequence && installed.OS == runtime.GOOS && installed.Architecture == runtime.GOARCH
}
