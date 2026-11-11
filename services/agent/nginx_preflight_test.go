package main

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func TestNewNginxSiteUsesSupportedExplicitOrigin(t *testing.T) {
	p := HostWafPlan{Hostname: "new.example", Upstream: "http://127.0.0.1:3000", ListenPort: 80, EntryURL: "http://127.0.0.1/", BusinessMode: "NEW"}
	source, err := newNginxSite(p)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(source, []byte("server_name new.example;")) {
		t.Fatal("missing exact hostname")
	}
	if _, err = planNginxOnboarding(source, p.Hostname, p.Upstream, "127.0.0.1:18081"); err != nil {
		t.Fatal(err)
	}
	p.ListenPort = 443
	p.EntryURL = "https://127.0.0.1:443/"
	p.CertificateFile = "/etc/nginx/tls/new.crt"
	p.CertificateKeyFile = "/etc/nginx/tls/new.key"
	source, err = newNginxSite(p)
	if err != nil || !bytes.Contains(source, []byte("listen 443 ssl;")) {
		t.Fatal(err, string(source))
	}
	for _, bad := range []HostWafPlan{{Hostname: "new.example;include x", Upstream: "http://127.0.0.1:3000", ListenPort: 80, EntryURL: "http://127.0.0.1/"}, {Hostname: "new.example", Upstream: "http://127.0.0.1:3000;bad", ListenPort: 80, EntryURL: "http://127.0.0.1/"}, {Hostname: "new.example", Upstream: "http://127.0.0.1:3000", ListenPort: 443, EntryURL: "https://127.0.0.1:443/"}} {
		if _, err := newNginxSite(bad); err == nil {
			t.Fatal("invalid new configuration accepted")
		}
	}
}
func TestNewNginxTransactionRollbackPreservesOtherBusiness(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "new.conf")
	other := filepath.Join(root, "other.conf")
	os.WriteFile(other, []byte("other-business"), 0600)
	after := []byte("server {listen 8080;}")
	state := filepath.Join(root, "tx")
	calls := 0
	run := func(args ...string) error { calls++; return nil }
	if err := applyNewNginxTransaction(target, state, after, func() error { return nil }, run); err != nil {
		t.Fatal(err)
	}
	if calls != 3 {
		t.Fatal("expected original check, new check and graceful reload", calls)
	}
	if err := rollbackNginxTransaction(state, run); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(target); !os.IsNotExist(err) {
		t.Fatal("new vhost retained after rollback", err)
	}
	if b, _ := os.ReadFile(other); string(b) != "other-business" {
		t.Fatal("other business modified")
	}
	if err := rollbackNginxTransaction(state, run); err != nil {
		t.Fatal("repeat rollback must converge", err)
	}
}
func TestNewNginxTransactionRejectsOverwriteAndRestoresOnFailure(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "new.conf")
	os.WriteFile(target, []byte("original"), 0600)
	if err := applyNewNginxTransaction(target, filepath.Join(root, "exists"), []byte("new"), func() error { return nil }, func(...string) error { return nil }); err == nil {
		t.Fatal("existing file overwritten")
	}
	b, _ := os.ReadFile(target)
	if string(b) != "original" {
		t.Fatal("original changed")
	}
	os.Remove(target)
	if err := applyNewNginxTransaction(target, filepath.Join(root, "failed"), []byte("candidate"), func() error { return errors.New("health mismatch") }, func(...string) error { return nil }); err == nil {
		t.Fatal("health failure ignored")
	}
	if _, err := os.Stat(target); !os.IsNotExist(err) {
		t.Fatal("failed new configuration remains")
	}
	state := filepath.Join(root, "changed")
	if err := applyNewNginxTransaction(target, state, []byte("candidate"), func() error { return nil }, func(...string) error { return nil }); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(target, []byte("later operator change"), 0600)
	if err := rollbackNginxTransaction(state, func(...string) error { return nil }); err == nil || !strings.Contains(err.Error(), "changed") {
		t.Fatal("newer operator configuration overwritten", err)
	}
}

func TestNginxPreflightBindsIncludedFileAndAllConfiguration(t *testing.T) {
	p := HostWafPlan{Schema: "selfguard-nginx-v1", AssetID: "asset-owned", SiteID: "site-owned", Hostname: "app.example", Upstream: "http://127.0.0.1:3000", Image: "sha256:" + strings.Repeat("a", 64), NginxConfig: "/etc/nginx/conf.d/app.conf", EntryURL: "http://127.0.0.1/", WafPort: 18081, HealthPath: "/", Mode: "OBSERVE"}
	source := []byte("server {listen 80;server_name app.example;location / {proxy_pass http://127.0.0.1:3000;}}")
	dump := []byte("# configuration file /etc/nginx/nginx.conf:\nevents {} http {include /etc/nginx/conf.d/*.conf;}\n# configuration file /etc/nginx/conf.d/app.conf:\n" + string(source))
	preview, err := describeNginxPreflight(p, source, dump)
	if err != nil {
		t.Fatal(err)
	}
	if preview.ConfigSHA256 != contentDigest(source) || preview.NginxSHA256 != contentDigest(dump) || preview.PlannedConfigSHA256 == "" {
		t.Fatal("preflight missing frozen hashes", preview)
	}
	if _, err = describeNginxPreflight(p, source, append(dump, []byte("\nserver {server_name app.example;}")...)); err == nil {
		t.Fatal("duplicate hostname accepted")
	}
	p.BusinessMode = "NEW"
	p.ListenPort = 80
	p.NginxConfig = "/etc/nginx/conf.d/new.conf"
	p.Hostname = "new.example"
	if preview, err = describeNginxPreflight(p, nil, dump); err != nil || preview.ConfigSHA256 != "ABSENT" {
		t.Fatal(err, preview)
	}
	p.NginxConfig = "/opt/not-loaded/new.conf"
	if _, err = describeNginxPreflight(p, nil, dump); err == nil {
		t.Fatal("unloaded new file accepted")
	}
}

func TestNewNginxSiteDoesNotReplaceImplicitDefault(t *testing.T) {
	p := HostWafPlan{Schema: "selfguard-nginx-v1", AssetID: "asset-owned", SiteID: "site-owned", Hostname: "new.example", Upstream: "http://127.0.0.1:3000", Image: "sha256:" + strings.Repeat("a", 64), NginxConfig: "/etc/nginx/conf.d/aaa.conf", EntryURL: "http://127.0.0.1/", WafPort: 18081, HealthPath: "/", Mode: "OBSERVE", BusinessMode: "NEW", ListenPort: 80}
	dump := []byte("# configuration file /etc/nginx/nginx.conf:\nevents {} http {include /etc/nginx/conf.d/*.conf;}\n# configuration file /etc/nginx/conf.d/business.conf:\nserver {listen 80;server_name business.example;location / {proxy_pass http://127.0.0.1:3000;}}")
	if _, err := describeNginxPreflight(p, nil, dump); err == nil {
		t.Fatal("new file would replace existing implicit default server")
	}
	p.NginxConfig = "/etc/nginx/conf.d/zz-new.conf"
	if _, err := describeNginxPreflight(p, nil, dump); err != nil {
		t.Fatal(err)
	}
	p.NginxConfig = "/etc/nginx/conf.d/aaa.conf"
	dump = bytes.Replace(dump, []byte("listen 80;"), []byte("listen 80 default_server;"), 1)
	if _, err := describeNginxPreflight(p, nil, dump); err != nil {
		t.Fatal(err)
	}
}

func TestInterruptedNginxOnboardingRecoversWithoutFinalReport(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "app.conf")
	state := filepath.Join(root, "state")
	os.Mkdir(state, 0700)
	p := HostWafPlan{Schema: "selfguard-nginx-v1", AssetID: "asset-owned", SiteID: "site-owned", Hostname: "app.example", NginxConfig: target, Mode: "OBSERVE", ExpectedConfigSHA256: contentDigest([]byte("original")), ExpectedPlannedConfigSHA256: contentDigest([]byte("protected"))}
	if err := writePrivate(filepath.Join(state, "plan.json"), p); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(target, []byte("original"), 0644)
	if err := applyNginxTransaction(target, filepath.Join(state, "nginx"), []byte("protected"), p.ExpectedConfigSHA256, func() error { return nil }, func(...string) error { return nil }); err != nil {
		t.Fatal(err)
	}
	report, err := rollbackBoundNginxState(state, p, func(...string) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	if report["status"] != "ROLLED_BACK" || report["siteId"] != p.SiteID {
		t.Fatal(report)
	}
	body, _ := os.ReadFile(target)
	if string(body) != "original" {
		t.Fatal("interrupted transaction not restored")
	}
	p.SiteID = "other-site"
	if _, err := rollbackBoundNginxState(state, p, func(...string) error { return nil }); err == nil {
		t.Fatal("another site could recover this transaction")
	}
}
func TestBootstrapFailureWithNoNginxTransactionCanBeRecovered(t *testing.T) {
	root := t.TempDir()
	os.Chmod(root, 0700)
	target := filepath.Join(root, "new.conf")
	p := HostWafPlan{Schema: "selfguard-nginx-v1", AssetID: "owned", SiteID: "site", Hostname: "new.example", NginxConfig: target, Mode: "OBSERVE", BusinessMode: "NEW", ExpectedConfigSHA256: "ABSENT"}
	writePrivate(filepath.Join(root, "plan.json"), p)
	report, err := rollbackBoundNginxState(root, p, func(...string) error { t.Fatal("unchanged nginx must not reload"); return nil })
	if err != nil || report["status"] != "ROLLED_BACK" {
		t.Fatal(err, report)
	}
	os.WriteFile(target, []byte("operator-config"), 0644)
	if _, err = rollbackBoundNginxState(root, p, func(...string) error { return nil }); err == nil {
		t.Fatal("new operator file was treated as unchanged")
	}
}
func TestTransactionRechecksReviewImmediatelyBeforePublishing(t *testing.T) {
	for _, newSite := range []bool{false, true} {
		t.Run(fmt.Sprint(newSite), func(t *testing.T) {
			root := t.TempDir()
			target := filepath.Join(root, "app.conf")
			if !newSite {
				os.WriteFile(target, []byte("before"), 0644)
			}
			called := false
			review := func() error {
				called = true
				return errors.New("full nginx configuration changed during image delivery")
			}
			run := func(args ...string) error {
				if len(args) > 1 {
					t.Fatal("unexpected reload after rejected final review")
				}
				return nil
			}
			var err error
			if newSite {
				err = applyNewNginxTransaction(target, filepath.Join(root, "state"), []byte("after"), func() error { return nil }, run, review)
			} else {
				err = applyNginxTransaction(target, filepath.Join(root, "state"), []byte("after"), contentDigest([]byte("before")), func() error { return nil }, run, review)
			}
			if err == nil || !called {
				t.Fatal("final reviewed state not checked")
			}
			body, e := os.ReadFile(target)
			if newSite && !os.IsNotExist(e) || !newSite && (e != nil || string(body) != "before") {
				t.Fatal("configuration changed before final approval check")
			}
		})
	}
}

func TestHostWafPublicTrustFilesRemainReadableWithPrivateSshUmask(t *testing.T) {
	previous := syscall.Umask(0077)
	defer syscall.Umask(previous)
	file := filepath.Join(t.TempDir(), "public-key")
	if err := writeHostWafTrustFile(file, []byte("public-only")); err != nil {
		t.Fatal(err)
	}
	body, e := os.ReadFile(file)
	if e != nil || string(body) != "public-only" {
		t.Fatal("public trust bytes were encoded or changed", e)
	}
	info, err := os.Stat(file)
	if err != nil || info.Mode().Perm() != 0644 {
		t.Fatal("non-root WAF cannot read public trust file", err, info.Mode())
	}
}

func TestNewNginxFileMatchingMultipleIncludesRequiresManualReview(t *testing.T) {
	p := HostWafPlan{Schema: "selfguard-nginx-v1", AssetID: "asset-owned", SiteID: "site-owned", Hostname: "new.example", Upstream: "http://127.0.0.1:3000", Image: "sha256:" + strings.Repeat("a", 64), NginxConfig: "/etc/nginx/conf.d/zz-new.conf", EntryURL: "http://127.0.0.1/", WafPort: 18081, HealthPath: "/", Mode: "OBSERVE", BusinessMode: "NEW", ListenPort: 80}
	dump := []byte("# configuration file /etc/nginx/nginx.conf:\nevents {} http {include /etc/nginx/conf.d/z*.conf;include /etc/nginx/conf.d/*.conf;}\n# configuration file /etc/nginx/conf.d/business.conf:\nserver {listen 80;server_name business.example;location / {proxy_pass http://127.0.0.1:3000;}}")
	if _, err := describeNginxPreflight(p, nil, dump); err == nil {
		t.Fatal("new file is loaded by an earlier glob before the original implicit default")
	}
}
