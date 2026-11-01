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
	"io"
	"os"
	"reflect"
	"strings"
	"time"
)

type secSignedRelease struct {
	Payload   string `json:"payload"`
	Signature string `json:"signature"`
}
type secRuntimeRelease struct {
	SchemaVersion int             `json:"schemaVersion"`
	Engine        string          `json:"engine"`
	BundleID      string          `json:"bundleId"`
	BundleSHA256  string          `json:"bundleSha256"`
	Threshold     int             `json:"threshold"`
	Site          Site            `json:"site"`
	Files         json.RawMessage `json:"files"`
	Builtin       bool            `json:"builtin,omitempty"`
}
type secRuntimePolicy struct {
	policy                 *secPoolPolicy
	bundleID, bundleSHA256 string
	threshold              int
}

func loadSecRulePublicKey(path string) (ed25519.PublicKey, error) {
	if path == "" {
		return nil, nil
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, errors.New("cannot read WAF rule trust root")
	}
	defer file.Close()
	raw, err := io.ReadAll(io.LimitReader(file, 1025))
	if err != nil || len(raw) > 1024 {
		return nil, errors.New("invalid WAF rule trust root size")
	}
	encoded := strings.TrimSpace(string(raw))
	key, err := base64.StdEncoding.Strict().DecodeString(encoded)
	if err != nil || len(key) != ed25519.PublicKeySize || base64.StdEncoding.EncodeToString(key) != encoded {
		return nil, errors.New("invalid WAF rule Ed25519 trust root")
	}
	return ed25519.PublicKey(key), nil
}

func (e *engine) prepareRuntimePolicy(site Site) (*secRuntimePolicy, error) {
	if site.RuleRelease == nil {
		return nil, nil
	}
	if e.rulePool == nil || len(e.rulePublicKey) != ed25519.PublicKeySize {
		return nil, errors.New("signed rules require a pinned trust root and isolated executor")
	}
	if len(site.RuleRelease.Payload) > 3<<20 {
		return nil, errors.New("signed rules exceed envelope budget")
	}
	raw, err := base64.StdEncoding.Strict().DecodeString(site.RuleRelease.Payload)
	if err != nil || base64.StdEncoding.EncodeToString(raw) != site.RuleRelease.Payload {
		return nil, errors.New("invalid rule release payload encoding")
	}
	signature, err := base64.StdEncoding.Strict().DecodeString(site.RuleRelease.Signature)
	if err != nil || !ed25519.Verify(e.rulePublicKey, raw, signature) {
		return nil, errors.New("rule release signature rejected")
	}
	var release secRuntimeRelease
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&release) != nil || decoder.Decode(new(any)) != io.EOF {
		return nil, errors.New("invalid signed rule release")
	}
	unsignedSite := site
	unsignedSite.RuleRelease = nil
	if release.SchemaVersion != 1 || release.Engine != "selfguard-seclang-v1" || (!release.Builtin && release.BundleID == "") || release.Threshold < 1 || release.Threshold > 100 || release.Site.RuleRelease != nil || !reflect.DeepEqual(release.Site, unsignedSite) {
		return nil, errors.New("signed rule site binding or engine rejected")
	}
	sum := sha256.Sum256(release.Files)
	if release.BundleSHA256 != hex.EncodeToString(sum[:]) {
		return nil, errors.New("signed rule bundle digest rejected")
	}
	var files []secLangFile
	decoder = json.NewDecoder(bytes.NewReader(release.Files))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&files) != nil || decoder.Decode(new(any)) != io.EOF {
		return nil, errors.New("invalid signed rule source files")
	}
	if release.Builtin {
		if release.BundleID != "" || len(files) != 0 {
			return nil, errors.New("builtin rollback cannot carry external rules")
		}
		return nil, nil
	}
	if site.Config.MaxBodyBytes > 1<<20 || len(site.Config.Exceptions) > 0 {
		return nil, errors.New("signed rule profile requires body limit at most 1 MiB and bundle-scoped exclusions")
	}
	policy, err := prepareSecPoolPolicy(files)
	if err != nil {
		return nil, err
	}
	// A verified refresh of an already active plan must not borrow the live
	// spares while a retired worker is being replenished. Signature, site
	// binding, source digest and profile limits were checked above.
	for _, active := range e.sites.Load().(map[string]runtimeSite) {
		if active.ID == site.ID && active.rulePolicy != nil && active.rulePolicy.policy.digest == policy.digest {
			return &secRuntimePolicy{active.rulePolicy.policy, release.BundleID, release.BundleSHA256, release.Threshold}, nil
		}
	}
	// Loading the exact immutable plan in a bounded worker is an activation gate.
	// Syntax/compatibility failures retain the entire previously active config.
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := e.rulePool.warmPolicy(ctx, policy); err != nil {
		return nil, err
	}
	return &secRuntimePolicy{policy, release.BundleID, release.BundleSHA256, release.Threshold}, nil
}
