package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestIdenticalSignedRefreshDoesNotBorrowLiveSparesDuringReplenishment(t *testing.T) {
	binary, directory := poolTestBinary(t), t.TempDir()
	gate, wrapper := filepath.Join(directory, "hold-replacement"), filepath.Join(directory, "worker")
	quote := func(value string) string { return "'" + strings.ReplaceAll(value, "'", "'\\''") + "'" }
	command := "#!/bin/sh\nwhile [ -e " + quote(gate) + " ]; do sleep 0.01; done\nexec " + quote(binary) + " \"$@\"\n"
	if err := os.WriteFile(wrapper, []byte(command), 0700); err != nil {
		t.Fatal(err)
	}
	public, private, _ := ed25519.GenerateKey(rand.Reader)
	e := newEngine()
	e.rulePublicKey, e.rulePool = public, newSecLangPool(wrapper, 3)
	defer e.rulePool.close()
	defer os.Remove(gate)
	site := signedRuntimeSite(t, private, Site{ID: "refresh", Hostname: "refresh.fixture.test", Upstream: "http://127.0.0.1:1", Mode: "BLOCK", Enabled: true, Version: 1}, `SecRule ARGS:q "@contains attack" "id:42123,phase:2,deny"`)
	config, _ := json.Marshal(Config{Sites: []Site{site}})
	cache := filepath.Join(directory, "config.json")
	if err := e.applyRemoteConfig(cache, config); err != nil {
		t.Fatal(err)
	}
	policy := e.sites.Load().(map[string]runtimeSite)[site.Hostname].rulePolicy.policy
	if err := os.WriteFile(gate, []byte("replacement waits for this fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	for index := 0; index < secStreamRequestLimit; index++ {
		if _, err := e.rulePool.evaluatePolicy(context.Background(), policy, secLangFixture{Variables: map[string][]string{"ARGS:q": {"safe"}}}); err != nil {
			t.Fatal(err)
		}
	}
	refreshed := make(chan error, 1)
	go func() { refreshed <- e.applyRemoteConfig(cache, config) }()
	blocked := false
	select {
	case err := <-refreshed:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(200 * time.Millisecond):
		blocked = true
	}
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	_, requestError := e.rulePool.evaluatePolicy(ctx, policy, secLangFixture{Variables: map[string][]string{"ARGS:q": {"safe"}}})
	cancel()
	if err := os.Remove(gate); err != nil {
		t.Fatal(err)
	}
	if blocked {
		select {
		case <-refreshed:
		case <-time.After(3 * time.Second):
			t.Fatal("refresh did not finish after replacement was released")
		}
	}
	if blocked || requestError != nil {
		t.Fatalf("unchanged signed refresh borrowed serving spares while replacement was blocked: refreshBlocked=%v requestError=%v", blocked, requestError)
	}
	committed, _ := os.ReadFile(cache)
	tampered := site
	tampered.RuleRelease = &secSignedRelease{Payload: site.RuleRelease.Payload, Signature: base64.StdEncoding.EncodeToString(make([]byte, ed25519.SignatureSize))}
	invalid, _ := json.Marshal(Config{Sites: []Site{tampered}})
	if e.applyRemoteConfig(cache, invalid) == nil {
		t.Fatal("cached plan bypassed signed release verification")
	}
	retained, _ := os.ReadFile(cache)
	if !bytes.Equal(committed, retained) {
		t.Fatal("rejected signature changed persisted policy")
	}
	next := site
	next.RuleRelease, next.Version = nil, site.Version+1
	next = signedRuntimeSite(t, private, next, `SecRule ARGS:q "@contains replacement" "id:42124,phase:2,deny"`)
	changed, _ := json.Marshal(Config{Sites: []Site{next}})
	if err := e.applyRemoteConfig(cache, changed); err != nil {
		t.Fatal(err)
	}
	active := e.sites.Load().(map[string]runtimeSite)[next.Hostname].rulePolicy.policy
	if active.digest == policy.digest {
		t.Fatal("new signed source reused the previous plan")
	}
	for _, fixture := range []struct {
		value   string
		blocked bool
	}{{"replacement", true}, {"attack", false}} {
		result, err := e.rulePool.evaluatePolicy(context.Background(), active, secLangFixture{Variables: map[string][]string{"ARGS:q": {fixture.value}}})
		if err != nil || result.Blocked != fixture.blocked {
			t.Fatalf("changed signed source was not activated: %+v %v", result, err)
		}
	}
}
