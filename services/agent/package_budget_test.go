package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestPackageCollectionAllowsSlowQuotaLimitedPackageManager(t *testing.T) {
	directory := t.TempDir()
	script := "#!/bin/sh\n/bin/sleep 3.2\nprintf 'sample\\t1.2.3\\n'\n"
	if err := os.WriteFile(filepath.Join(directory, "dpkg-query"), []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", directory)
	packages, coverage := packageInventory()
	if !coverage.Complete || len(packages) != 1 {
		t.Fatalf("quota-limited package collection rejected: %v %+v", packages, coverage)
	}
}
func TestPackageCollectionTimeoutNeverClaimsComplete(t *testing.T) {
	directory := t.TempDir()
	for _, name := range []string{"dpkg-query", "rpm"} {
		if err := os.WriteFile(filepath.Join(directory, name), []byte("#!/bin/sh\nprintf 'partial\\t1\\n'\nexec /bin/sleep 1\n"), 0700); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", directory)
	packages, coverage := packageInventoryWithin(30 * time.Millisecond)
	if coverage.Complete || len(packages) != 0 {
		t.Fatalf("timeout marked complete: %v %+v", packages, coverage)
	}
}
