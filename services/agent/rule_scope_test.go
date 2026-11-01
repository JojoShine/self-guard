package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestPolicyApplicabilityAndBaselineExceptionExpiry(t *testing.T) {
	root, _ := filepath.EvalSymlinks(t.TempDir())
	p := filepath.Join(root, "mode")
	if err := os.WriteFile(p, []byte("x"), 0644); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	a := &Agent{Config: Config{AllowedRoot: root}, Identity: Identity{AssetID: "a"}}
	rule := PolicyRule{ID: "one", Kind: "BASELINE", Config: PolicyConfig{Path: p, Mode: "0600", Applicability: RuleApplicability{AssetIDs: []string{"a"}, Tags: []string{"prod"}, Businesses: []string{"billing"}}, Exceptions: []RuleException{{AssetID: "a", Path: p, ExpiresAt: now.Add(time.Hour).Format(time.RFC3339Nano), Reason: "fixture"}}}}
	asset := PolicyAsset{ID: "a", Tags: []string{"prod"}, Business: "billing"}
	a.applyPolicyForAssetAt([]PolicyRule{rule}, asset, now)
	if len(a.RemoteChecks) != 0 || len(a.collectBaselines()) != 0 {
		t.Fatal("active exception failed")
	}
	a.applyPolicyForAssetAt([]PolicyRule{rule}, asset, now.Add(2*time.Hour))
	if len(a.RemoteChecks) != 1 || len(a.collectBaselines()) != 1 {
		t.Fatal("expired exception suppressed detection")
	}
	asset.ID = "b"
	rule.Config.Applicability.AssetIDs = nil
	a.Identity.AssetID = "b"
	a.applyPolicyForAssetAt([]PolicyRule{rule}, asset, now)
	if len(a.RemoteChecks) != 1 || len(a.collectBaselines()) != 1 {
		t.Fatal("exception leaked to another asset")
	}
	asset.Tags = []string{"dev"}
	a.applyPolicyForAssetAt([]PolicyRule{rule}, asset, now)
	if len(a.RemoteChecks) != 0 {
		t.Fatal("tag applicability ignored")
	}
}
