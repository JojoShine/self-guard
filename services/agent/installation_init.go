package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

func detectInstallationInit(pid string, systemd, openrc bool) (string, error) {
	pid = strings.TrimSpace(pid)
	if pid == "systemd" && systemd && !openrc {
		return "systemd", nil
	}
	if pid == "init" && openrc && !systemd {
		return "openrc", nil
	}
	return "", errors.New("a running systemd or OpenRC host is required; container startup is not service acceptance")
}
func currentInstallationInit() (string, error) {
	pid, err := readBoundedFile("/proc/1/comm", 128)
	if err != nil {
		return "", err
	}
	_, sd := os.Stat("/run/systemd/system")
	_, rc := os.Stat("/run/openrc/softlevel")
	return detectInstallationInit(string(pid), sd == nil, rc == nil)
}
func requireInstallationHost() error {
	manager, err := currentInstallationInit()
	if err != nil {
		return err
	}
	if manager == "openrc" {
		for _, tool := range []string{"/sbin/openrc-run", "/sbin/rc-service", "/sbin/rc-update", "/sbin/supervise-daemon"} {
			resolved, err := filepath.EvalSymlinks(tool)
			if err != nil || executorTrustedConfig(resolved) != nil {
				return fmt.Errorf("trusted OpenRC tool required: %s", tool)
			}
		}
		mounts, err := readBoundedFile("/proc/1/mounts", 1<<20)
		if err != nil {
			return err
		}
		unified := false
		for _, line := range strings.Split(string(mounts), "\n") {
			fields := strings.Fields(line)
			if len(fields) >= 3 && fields[1] == "/sys/fs/cgroup" && fields[2] == "cgroup2" {
				unified = true
			}
		}
		controllers, err := readBoundedFile("/sys/fs/cgroup/cgroup.controllers", 4096)
		if err != nil || !unified {
			return errors.New("OpenRC installation requires mounted unified cgroup v2")
		}
		for _, controller := range []string{"cpu", "memory", "pids"} {
			if !strings.Contains(" "+strings.Join(strings.Fields(string(controllers)), " ")+" ", " "+controller+" ") {
				return fmt.Errorf("OpenRC resource controller unavailable: %s", controller)
			}
		}
	}
	return nil
}
func installationServicePathFor(manager, name string) (string, error) {
	if name != "selfguard-collector.service" && name != "selfguard-executor.service" {
		return "", errors.New("unknown managed service")
	}
	if manager == "systemd" {
		return "/etc/systemd/system/" + name, nil
	}
	if manager == "openrc" {
		return "/etc/init.d/" + strings.TrimSuffix(name, ".service"), nil
	}
	return "", errors.New("unknown service manager")
}
func installationServicePath(name string) string {
	manager, err := currentInstallationInit()
	if err != nil {
		manager = "systemd"
	} // Paths in legacy journal/unit fixtures; production entry points check the host first.
	path, _ := installationServicePathFor(manager, name)
	return path
}
func installationServiceOperations(manager string, args ...string) ([][]string, error) {
	if manager != "systemd" && manager != "openrc" {
		return nil, errors.New("unknown service manager")
	}
	if len(args) == 1 && args[0] == "daemon-reload" {
		if manager == "openrc" {
			return nil, nil
		}
		return [][]string{{"systemctl", "daemon-reload"}}, nil
	}
	if len(args) < 2 || len(args) > 3 {
		return nil, errors.New("invalid managed service operation")
	}
	op, name := args[0], args[len(args)-1]
	if _, err := installationServicePathFor(manager, name); err != nil {
		return nil, err
	}
	if len(args) == 3 && !((op == "is-active" || op == "is-enabled") && args[1] == "--quiet" || op == "disable" && args[1] == "--now") {
		return nil, errors.New("invalid managed service option")
	}
	switch op {
	case "enable", "disable", "is-active", "is-enabled", "start", "stop", "restart":
	default:
		return nil, errors.New("unknown managed service operation")
	}
	if manager == "systemd" {
		return [][]string{append([]string{"systemctl"}, args...)}, nil
	}
	name = strings.TrimSuffix(name, ".service")
	switch op {
	case "enable":
		return [][]string{{"rc-update", "add", name, "default"}}, nil
	case "disable":
		commands := [][]string{}
		if len(args) == 3 {
			commands = append(commands, []string{"rc-service", "--quiet", name, "stop"})
		}
		return append(commands, []string{"rc-update", "del", name, "default"}), nil
	case "is-enabled":
		return nil, errors.New("OpenRC enablement must be checked from its exact runlevel link")
	case "is-active":
		return [][]string{{"rc-service", "--quiet", name, "status"}}, nil
	default:
		return [][]string{{"rc-service", "--quiet", name, op}}, nil
	}
}
func installationServiceCommand(args ...string) error {
	manager, err := currentInstallationInit()
	if err != nil {
		return err
	}
	if manager == "openrc" && len(args) > 1 && args[0] == "is-enabled" {
		if len(args) != 2 && !(len(args) == 3 && args[1] == "--quiet") {
			return errors.New("invalid managed service option")
		}
		name := args[len(args)-1]
		path, err := installationServicePathFor(manager, name)
		if err != nil {
			return err
		}
		resolved, err := filepath.EvalSymlinks("/etc/runlevels/default/" + strings.TrimSuffix(name, ".service"))
		if err != nil || resolved != path {
			return errors.New("managed OpenRC service is not enabled")
		}
		return nil
	}
	commands, err := installationServiceOperations(manager, args...)
	if err != nil {
		return err
	}
	for _, command := range commands {
		if command[0] == "rc-update" && command[1] == "del" {
			if _, err := os.Lstat("/etc/runlevels/default/" + command[2]); os.IsNotExist(err) {
				continue
			} else if err != nil {
				return err
			}
		}
		if err := trustedInstallCommand(command[0], command[1:]...); err != nil {
			return err
		}
	}
	return nil
}
func installationServiceSpec(manager, name string, executor bool, config Config) (string, os.FileMode, string, error) {
	path, err := installationServicePathFor(manager, name)
	if err != nil {
		return "", 0, "", err
	}
	if manager == "systemd" {
		body := installationCollectorUnit(executor, config)
		if name == "selfguard-executor.service" {
			body = installationExecutorUnit(config.AllowedRoot)
		}
		return path, 0644, body, nil
	}
	role, user, arguments, dependency := "collector", "selfguard-agent:selfguard-agent", "", ""
	memory, quota, tasks := config.MaxMemoryBytes, config.CPUQuotaPercent, 64
	if memory == 0 {
		memory = 128 << 20
	}
	if quota == 0 {
		quota = 20
	}
	if executor {
		dependency = "\n\tneed selfguard-executor"
	}
	prepare := ""
	if name == "selfguard-executor.service" {
		role, user, arguments, dependency = "executor", "root:selfguard-agent", "--executor", ""
		memory, quota, tasks = 128<<20, 0, 32
		prepare = "\n\tcheckpath -d -m 0750 -o root:selfguard-agent /run/selfguard-executor || return 1"
	}
	if memory < 64<<20 || memory > 1<<30 || quota < 0 || quota > 100 {
		return "", 0, "", errors.New("invalid service resource budget")
	}
	settings := "memory.max " + strconv.FormatInt(memory, 10) + "\npids.max " + strconv.Itoa(tasks)
	checks := fmt.Sprintf("\t[ \"$(cat \"$limits/memory.max\")\" = \"%d\" ] || return 1\n\t[ \"$(cat \"$limits/pids.max\")\" = \"%d\" ] || return 1", memory, tasks)
	if quota > 0 {
		settings += fmt.Sprintf("\ncpu.max %d 100000", quota*1000)
		checks += fmt.Sprintf("\n\t[ \"$(cat \"$limits/cpu.max\")\" = \"%d 100000\" ] || return 1", quota*1000)
	}
	body := fmt.Sprintf(`#!/sbin/openrc-run
description="Self Guard %s"
supervisor=supervise-daemon
no_new_privs=yes
command=/opt/selfguard-agent/current
command_args="%s"
command_user="%s"
pidfile="/run/${RC_SVCNAME}.pid"
respawn_delay=10
respawn_max=5
respawn_period=60
export AGENT_CONFIG=/etc/selfguard-agent/%s.json
export SELFGUARD_OPENRC_SERVICE=1
rc_cgroup_settings="%s"
depend() {
	need net%s
}
start_pre() {
	umask 077%s
}
start_post() {
	limits="/sys/fs/cgroup/openrc.${RC_SVCNAME}"
%s
}
`, role, arguments, user, role, settings, dependency, prepare, checks)
	return path, 0755, body, nil
}
func writeInstallationService(name string, executor bool, config Config, tx *installationTransaction) error {
	manager, err := currentInstallationInit()
	if err != nil {
		return err
	}
	path, mode, body, err := installationServiceSpec(manager, name, executor, config)
	if err != nil {
		return err
	}
	return writeInstallationManagedFile(path, []byte(body), mode, tx)
}
