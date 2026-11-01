package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
)

func TestOpenRCServicePrivilegeFloor(t *testing.T) {
	mode := os.Getenv("SELF_GUARD_PRIVILEGE_CHILD")
	if mode == "PREPARE_EXEC" {
		// Model a supervisor setting the flag before executing the Go runtime.
		runtime.LockOSThread()
		if _, _, err := syscall.RawSyscall6(syscall.SYS_PRCTL, 38, 1, 0, 0, 0, 0); err != 0 {
			t.Fatal(err)
		}
		os.Setenv("SELF_GUARD_PRIVILEGE_CHILD", "VERIFY_INHERITED")
		t.Fatal(syscall.Exec(os.Args[0], []string{os.Args[0], "-test.run=^TestOpenRCServicePrivilegeFloor$"}, os.Environ()))
	}
	if mode == "VERIFY_INHERITED" {
		if err := requireNoNewPrivileges(); err != nil {
			t.Fatal(err)
		}
		release, ready := make(chan struct{}), make(chan error, 4)
		defer close(release)
		for i := 0; i < 4; i++ {
			go func() {
				runtime.LockOSThread()
				defer runtime.UnlockOSThread()
				ready <- requireNoNewPrivileges()
				<-release
			}()
		}
		for i := 0; i < 4; i++ {
			if err := <-ready; err != nil {
				t.Fatal(err)
			}
		}
		threads, err := os.ReadDir("/proc/self/task")
		if err != nil {
			t.Fatal(err)
		}
		for _, thread := range threads {
			status, err := os.ReadFile(filepath.Join("/proc/self/task", thread.Name(), "status"))
			if os.IsNotExist(err) {
				continue
			}
			if err != nil || !strings.Contains(string(status), "NoNewPrivs:\t1\n") {
				t.Fatal("NoNewPrivileges not inherited by every runtime thread", thread.Name(), err)
			}
		}
		return
	}
	if mode == "CHECK_UNPREPARED" {
		status, err := os.ReadFile("/proc/self/status")
		if err != nil {
			t.Fatal(err)
		}
		inherited := strings.Contains(string(status), "NoNewPrivs:\t1\n")
		if (requireNoNewPrivileges() == nil) != inherited {
			t.Fatal("missing supervisor boundary was not rejected")
		}
		return
	}
	for _, child := range []string{"CHECK_UNPREPARED", "PREPARE_EXEC"} {
		command := exec.Command(os.Args[0], "-test.run=^TestOpenRCServicePrivilegeFloor$")
		command.Env = append(os.Environ(), "SELF_GUARD_PRIVILEGE_CHILD="+child)
		if output, err := command.CombinedOutput(); err != nil {
			t.Fatalf("%s %v", output, err)
		}
	}
}
