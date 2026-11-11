package main

import (
	"strings"
	"testing"
)

func TestPackageMetadataRetainsSourceAndEpoch(t *testing.T) {
	packages, status := parsePackageMetadata([]string{"libssl3\t3.0.17-1~deb12u2\topenssl\t3.0.17-1~deb12u2\tamd64\tdpkg\tinstalled", "openssl-libs\t1:3.5.1-2.el9\topenssl-3.5.1-2.el9.src.rpm\t\tx86_64\trpm"}, PackageCollection{Complete: true})
	if !status.Complete || len(packages) != 2 {
		t.Fatalf("metadata rejected: %+v %+v", packages, status)
	}
	if packages[0].Origin != "openssl" || packages[0].SourceVersion != "3.0.17-1~deb12u2" || packages[0].Architecture != "amd64" {
		t.Fatalf("Debian source lost: %+v", packages[0])
	}
	if packages[1].Epoch != "1" || packages[1].Version != "1:3.5.1-2.el9" || packages[1].SourceVersion != "" {
		t.Fatalf("RPM epoch inferred or lost: %+v", packages[1])
	}
	_, bad := parsePackageMetadata([]string{"bad\tversion\torigin\tversion\tarch\trpm"}, PackageCollection{Complete: true})
	if bad.Complete {
		t.Fatal("RPM output without explicit epoch accepted as complete")
	}
}
func TestAlpineInstalledMetadataIsReadOnlyBoundedAndPreservesOrigin(t *testing.T) {
	data := "P:libcrypto3\nV:3.5.1-r0\nA:aarch64\no:openssl\nF:usr/lib\nR:libcrypto.so.3\n\nP:busybox\nV:1.37.0-r1\nA:aarch64\no:busybox\n\n"
	packages, status := parseApkInstalled(strings.NewReader(data))
	if !status.Complete || len(packages) != 2 || packages[0].Origin != "openssl" || packages[0].Manager != "apk" {
		t.Fatalf("APK source metadata missing: %+v %+v", packages, status)
	}
	for _, bad := range []string{"P:a\nV:1\nV:2\n\n", "P:a\no:a\n\n", "P:a\nV:1\no:a\n\nP:a\nV:2\no:a\n\n"} {
		_, coverage := parseApkInstalled(strings.NewReader(bad))
		if coverage.Complete {
			t.Fatal("malformed APK database marked complete")
		}
	}
}

func TestRpmSigningKeyEntryDoesNotInvalidateCentOSInventory(t *testing.T) {
	key := "gpg-pubkey\t0:f4a80eb5-53a7ff4b\t(none)\t\t(none)\trpm"
	software := "bash\t0:4.2.46-35.el7\tbash-4.2.46-35.el7.src.rpm\t\tx86_64\trpm"
	packages, status := parsePackageMetadata([]string{key, software}, PackageCollection{Complete: true, Reason: "collected"})
	if !status.Complete || len(packages) != 1 || packages[0].Name != "bash" {
		t.Fatalf("RPM signing key treated as broken software: %+v %+v", packages, status)
	}
	for _, invalid := range []string{
		"bash\t0:4.2.46-35.el7\t(none)\t\t(none)\trpm",
		"gpg-pubkey\tinvalid\t(none)\t\t(none)\trpm",
		key + "\textra",
	} {
		_, coverage := parsePackageMetadata([]string{invalid}, PackageCollection{Complete: true})
		if coverage.Complete {
			t.Fatalf("malformed entry accepted: %q", invalid)
		}
	}
}
