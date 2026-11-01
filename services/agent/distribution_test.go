package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDistributionParsing(t *testing.T) {
	for _, body := range []string{"ID=Ubuntu\nVERSION_ID=24.04\n", "# release\nID=\"Ubuntu\"\nVERSION_ID=\"24.04\"\nNAME=ignored\n", "ID='Ubuntu'\nVERSION_ID='24.04'\n"} {
		d, s := parseDistribution(strings.NewReader(body))
		if !s.Complete || d.ID != "ubuntu" || d.VersionID != "24.04" {
			t.Fatal(d, s)
		}
	}
	for _, body := range []string{"", "ID=ubuntu\n", "VERSION_ID=24.04\n", "ID=ubuntu\nID=debian\nVERSION_ID=12\n", "ID=\"ubuntu\nVERSION_ID=24.04\n", "ID=$(touch /tmp/no)\nVERSION_ID=24.04\n", strings.Repeat("x", (64<<10)+1)} {
		d, s := parseDistribution(strings.NewReader(body))
		if s.Complete || d.ID != "" || d.VersionID != "" {
			t.Fatal("invalid distribution accepted", d, s)
		}
	}
	exact := "ID=ubuntu\nVERSION_ID=24.04\n"
	exact += strings.Repeat("#", (64<<10)-len(exact))
	if _, s := parseDistribution(strings.NewReader(exact)); !s.Complete {
		t.Fatal("exact read bound rejected", s)
	}
	if _, s := distributionInventory(filepath.Join(t.TempDir(), "missing")); s.Complete {
		t.Fatal("missing release accepted")
	}
	p := filepath.Join(t.TempDir(), "os-release")
	os.WriteFile(p, []byte("ID=debian\nVERSION_ID=12\n"), 0600)
	d, s := distributionInventory(p)
	if !s.Complete || d.ID != "debian" || d.VersionID != "12" {
		t.Fatal(d, s)
	}
}
