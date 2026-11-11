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

func TestKylinMilestoneCollection(t *testing.T) {
	root := t.TempDir()
	release := filepath.Join(root, "os-release")
	os.WriteFile(release, []byte("ID=kylin\nVERSION_ID=V10\nNAME=\"Kylin Linux Advanced Server\"\n"), 0600)
	for milestone, want := range map[string]string{"10-SP1-Release-Build09-20210524": "V10SP1", "10-SP2-Release-Build09-20210524": "V10SP2", "10-SP3-Release-Build09-20230524": "V10SP3", "10-SP3-2403-Release-Build01": "V10SP3-2403"} {
		os.WriteFile(filepath.Join(root, ".kyinfo"), []byte("[dist]\nname=Kylin-Server\nmilestone="+milestone+"\n[servicekey]\nkey=private-key-never-reported\n"), 0600)
		d, s := distributionInventory(release)
		if !s.Complete || d.KylinRelease != want || d.Name != "Kylin Linux Advanced Server" {
			t.Fatalf("%s: %#v %#v", milestone, d, s)
		}
	}
	for _, body := range []string{"[dist]\nname=Kylin-Desktop\nmilestone=10-SP3-Release\n", "[dist]\nname=Kylin-Server\nmilestone=10-SP3.1-Release\n", "[dist]\nname=Kylin-Server\nmilestone=10-SP1\nmilestone=10-SP3\n"} {
		os.WriteFile(filepath.Join(root, ".kyinfo"), []byte(body), 0600)
		d, s := distributionInventory(release)
		if s.Complete || d.KylinRelease != "" {
			t.Fatalf("ambiguous Kylin branch accepted: %#v", d)
		}
	}
	os.Remove(filepath.Join(root, ".kyinfo"))
	d, s := distributionInventory(release)
	if s.Complete || d.KylinRelease != "" {
		t.Fatal("missing SP accepted")
	}
}
