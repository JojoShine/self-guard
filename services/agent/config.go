package main

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
	"unicode"
)

var configKey = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

func (a *Agent) executeConfig(t Task) Result {
	fail := func(s string) Result { return Result{Evidence: s} }
	p := t.Parameters
	if t.ExpiresAt.IsZero() || !t.ExpiresAt.After(time.Now()) {
		return fail("task expired or missing expiry")
	}
	if !configKey.MatchString(p.Key) {
		return fail("invalid key")
	}
	for _, v := range []string{p.Value, p.ExpectedValue} {
		for _, r := range v {
			if unicode.IsControl(r) {
				return fail("control characters refused")
			}
		}
	}
	if e := safePath(a.Config.AllowedRoot, p.Path); e != nil {
		return fail("unsafe configuration path")
	}
	f, e := openWritable(p.Path)
	if e != nil {
		return fail("cannot open configuration securely")
	}
	defer f.Close()
	s, e := f.Stat()
	if e != nil || !s.Mode().IsRegular() || multipleLinks(s) || s.Size() > 64<<10 {
		return fail("configuration must be a regular file within 64 KiB")
	}
	before, e := io.ReadAll(io.LimitReader(f, (64<<10)+1))
	if e != nil || len(before) > 64<<10 {
		return fail("configuration read failed")
	}
	lines := strings.Split(string(before), "\n")
	count := 0
	for i, line := range lines {
		key, value, ok := strings.Cut(line, "=")
		if ok && key == p.Key {
			count++
			if value != p.ExpectedValue {
				return fail("configuration precondition conflict")
			}
			lines[i] = key + "=" + p.Value
		}
	}
	if count != 1 {
		return fail("exactly one matching key required")
	}
	after := []byte(strings.Join(lines, "\n"))
	if len(after) > 64<<10 {
		return fail("result exceeds 64 KiB")
	}
	name := fmt.Sprintf("config-backup-%x.json", sha256.Sum256([]byte(t.ID)))
	if e := writePrivate(filepath.Join(a.Config.StateDir, name), map[string]any{"content": before, "mode": s.Mode().Perm()}); e != nil {
		return fail("backup persistence failed")
	}
	write := func(b []byte) error {
		if _, e := f.Seek(0, io.SeekStart); e != nil {
			return e
		}
		n, e := f.Write(b)
		if e != nil {
			return e
		}
		if n != len(b) {
			return io.ErrShortWrite
		}
		if e = f.Truncate(int64(len(b))); e != nil {
			return e
		}
		return f.Sync()
	}
	marker := filepath.Join(a.Config.StateDir, "config-recovery.json")
	if e := writePrivate(marker, map[string]string{"taskId": t.ID, "backup": name, "path": p.Path, "status": "manual recovery required if interrupted"}); e != nil {
		return fail("cannot persist recovery marker")
	}
	e = write(after)
	if e == nil {
		_, e = f.Seek(0, io.SeekStart)
		if e == nil {
			var actual []byte
			actual, e = io.ReadAll(io.LimitReader(f, (64<<10)+1))
			if e == nil && !bytes.Equal(actual, after) {
				e = fmt.Errorf("content mismatch")
			}
		}
	}
	current, statErr := os.Lstat(p.Path)
	if statErr != nil || !os.SameFile(s, current) {
		e = fmt.Errorf("path changed")
	}
	if e != nil {
		rollback := write(before)
		if rollback == nil {
			_ = removeDurable(marker)
		}
		return Result{Evidence: "configuration write or verification failed", Details: map[string]string{"rollbackSucceeded": fmt.Sprint(rollback == nil)}}
	}
	if e := removeDurable(marker); e != nil {
		return fail("verified configuration but recovery marker removal failed; manual review required")
	}
	return Result{Success: true, Evidence: "configuration content verified; manual functional health verification required", Details: map[string]string{"backup": name, "beforeBytes": fmt.Sprint(len(before)), "afterBytes": fmt.Sprint(len(after))}}
}
