package main

import (
	"reflect"
	"strings"
	"testing"
)

func TestInstallationInitRequiresConsistentRealHost(t *testing.T) {
	for _, tc := range []struct {
		pid             string
		systemd, openrc bool
		want            string
	}{
		{"systemd\n", true, false, "systemd"}, {"init\n", false, true, "openrc"},
		{"node", false, true, ""}, {"bash", true, false, ""}, {"init", false, false, ""},
		{"systemd", false, true, ""}, {"init", true, true, ""},
	} {
		got, err := detectInstallationInit(tc.pid, tc.systemd, tc.openrc)
		if got != tc.want || (err != nil) != (tc.want == "") {
			t.Fatalf("%+v => %q %v", tc, got, err)
		}
	}
}

func TestInstallationServiceOperationsAreFiniteAndPreserveSystemdArguments(t *testing.T) {
	for _, tc := range []struct {
		manager string
		args    []string
		want    [][]string
	}{
		{"systemd", []string{"disable", "--now", "selfguard-collector.service"}, [][]string{{"systemctl", "disable", "--now", "selfguard-collector.service"}}},
		{"openrc", []string{"daemon-reload"}, nil},
		{"openrc", []string{"is-active", "--quiet", "selfguard-collector.service"}, [][]string{{"rc-service", "--quiet", "selfguard-collector", "status"}}},
		{"openrc", []string{"enable", "selfguard-executor.service"}, [][]string{{"rc-update", "add", "selfguard-executor", "default"}}},
		{"openrc", []string{"disable", "--now", "selfguard-collector.service"}, [][]string{{"rc-service", "--quiet", "selfguard-collector", "stop"}, {"rc-update", "del", "selfguard-collector", "default"}}},
	} {
		got, err := installationServiceOperations(tc.manager, tc.args...)
		if err != nil || !reflect.DeepEqual(got, tc.want) {
			t.Fatalf("%+v => %v %v", tc, got, err)
		}
	}
	for _, args := range [][]string{{"restart", "other.service"}, {"restart", "--bad"}, {"shell", "selfguard-collector.service"}, {"enable", "selfguard-collector.service", "extra"}} {
		if _, err := installationServiceOperations("openrc", args...); err == nil {
			t.Fatalf("arbitrary service operation accepted: %v", args)
		}
	}
}

func TestOpenRCServiceSpecSeparatesIdentityAndResourceBudgets(t *testing.T) {
	c := Config{MaxMemoryBytes: 96 << 20, CPUQuotaPercent: 17}
	path, mode, body, err := installationServiceSpec("openrc", "selfguard-collector.service", true, c)
	if err != nil || path != "/etc/init.d/selfguard-collector" || mode != 0755 {
		t.Fatal(path, mode, err)
	}
	for _, text := range []string{"#!/sbin/openrc-run", "supervisor=supervise-daemon", "command_user=\"selfguard-agent:selfguard-agent\"", "AGENT_CONFIG=/etc/selfguard-agent/collector.json", "need selfguard-executor", "cpu.max 17000 100000", "memory.max 100663296", "pids.max 64"} {
		if !strings.Contains(body, text) {
			t.Fatal("missing collector contract: " + text)
		}
	}
	_, _, collector, err := installationServiceSpec("openrc", "selfguard-collector.service", false, c)
	if err != nil || strings.Contains(collector, "need selfguard-executor") {
		t.Fatal("executor enabled implicitly")
	}
	_, _, executor, err := installationServiceSpec("openrc", "selfguard-executor.service", true, Config{})
	if err != nil || !strings.Contains(executor, "command_user=\"root:selfguard-agent\"") || !strings.Contains(executor, "--executor") || !strings.Contains(executor, "pids.max 32") {
		t.Fatal("executor isolation missing", err)
	}
	path, mode, systemd, err := installationServiceSpec("systemd", "selfguard-collector.service", true, c)
	if err != nil || path != "/etc/systemd/system/selfguard-collector.service" || mode != 0644 || systemd != installationCollectorUnit(true, c) {
		t.Fatal("systemd unit changed", err)
	}
}
