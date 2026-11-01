package main

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

type logWindow struct {
	Database  []databaseObservation
	Hits      []int64
	LastAlert int64
}
type fileState struct {
	Generation   uint64
	Hash         string
	Status       string
	Offset       int64
	Prefix       string
	PrefixLength int
	Identity     string
	Partial      string
	Dropping     bool
	Windows      map[string]logWindow
}

func event(id, title, source string, evidence any) map[string]any {
	return map[string]any{"externalId": id, "title": title, "kind": "ALERT", "severity": "MEDIUM", "source": source, "evidence": evidence}
}

func (a *Agent) collectFiles() []map[string]any { return a.collectFilesAt(time.Now()) }

// Cursor, incomplete lines and rolling-window counters are committed only after the report is durable.
func (a *Agent) collectFilesAt(now time.Time) []map[string]any {
	a.LogContexts = nil
	redactions, redactionErr := compileLogRedactions(a.Config)
	includeContext := a.Config.LogIncludeMessage && redactionErr == nil
	state := map[string]fileState{}
	if read(filepath.Join(a.Config.StateDir, "collectors.json"), &state) != nil {
		return nil
	}
	out := append([]map[string]any{}, a.PolicyFindings...)
	for i, p := range append(append([]string{}, a.Config.FIMPaths...), a.RemoteFIM...) {
		if i >= 100 {
			break
		}
		prev, known := state["fim:"+p]
		next := fileState{Status: "unreadable", Generation: prev.Generation}
		f, e := openTarget(p)
		if os.IsNotExist(e) {
			next.Status = "missing"
		}
		if e == nil {
			s, err := f.Stat()
			if err == nil && s.Mode().IsRegular() && s.Size() <= 8<<20 {
				h := sha256.New()
				n, err := io.Copy(h, io.LimitReader(f, (8<<20)+1))
				if err == nil && n <= 8<<20 {
					next.Status = "present"
					next.Hash = fmt.Sprintf("%x", h.Sum(nil))
				}
			}
			f.Close()
		}
		// Older cursor files did not record Status.
		if prev.Status == "" && prev.Hash != "" {
			prev.Status = "present"
		}
		change := ""
		if known && next.Status != prev.Status {
			switch next.Status {
			case "missing":
				change = "deleted"
			case "present":
				change = "created"
			default:
				change = "unreadable"
			}
		} else if known && next.Hash != prev.Hash {
			change = "modified"
		}
		if !known && next.Status == "unreadable" {
			change = "unreadable"
		}
		if change != "" {
			next.Generation++
			out = append(out, event(fmt.Sprintf("fim:%s:%d:%s", p, next.Generation, change), "File integrity "+change, "agent-fim", map[string]string{"path": p, "change": change, "previousHash": prev.Hash, "hash": next.Hash, "status": next.Status}))
		}
		state["fim:"+p] = next
	}
	logPaths := append([]string{}, a.Config.LogPaths...)
	for _, r := range a.LogRules {
		if databaseLogRule(r.Config) {
			found := false
			for _, p := range logPaths {
				if p == r.Config.Path {
					found = true
				}
			}
			if !found {
				logPaths = append(logPaths, r.Config.Path)
			}
		}
	}
	for i, p := range logPaths {
		if i >= 20 {
			for _, r := range a.LogRules {
				if databaseLogRule(r.Config) && r.Config.Path == p {
					out = append(out, databaseCoverage(r, p, "日志路径数量超过20条预算，未读取本路径"))
				}
			}
			continue
		}
		f, e := openTarget(p)
		if e != nil {
			for _, r := range a.LogRules {
				if databaseLogRule(r.Config) && r.Config.Path == p {
					out = append(out, databaseCoverage(r, p, "日志无法读取，核对文件存在性、权限与安全路径约束"))
				}
			}
			continue
		}
		s, e := f.Stat()
		if e != nil || !s.Mode().IsRegular() {
			f.Close()
			continue
		}
		prev := state["log:"+p]
		size := 64
		if prev.PrefixLength > 0 {
			size = prev.PrefixLength
		}
		prefix := make([]byte, size)
		n, _ := f.Read(prefix)
		sig := fmt.Sprintf("%x", sha256.Sum256(prefix[:n]))
		identity := fileIdentity(s)
		offset := prev.Offset
		if s.Size() < offset || (prev.Identity != "" && identity != prev.Identity) || (prev.Prefix != "" && prev.Prefix != sig) {
			offset = 0
			prev.Partial = ""
			prev.Dropping = false
		}
		if _, e = f.Seek(offset, io.SeekStart); e != nil {
			f.Close()
			continue
		}
		b, e := io.ReadAll(io.LimitReader(f, 16<<10))
		f.Close()
		if e != nil {
			continue
		}
		partialBytes := len(prev.Partial)
		lineOffset := offset - int64(partialBytes)
		consumed := 0
		completed := 0
		body := prev.Partial + string(b)
		lines := []string{}
		for {
			line, rest, ok := strings.Cut(body, "\n")
			if !ok {
				break
			}
			if !prev.Dropping && len(line) <= 64<<10 {
				lines = append(lines, line)
				if includeContext {
					a.addLogContext(p, identity, lineOffset, line, redactions, now)
				}
			}
			prev.Dropping = false
			body = rest
			consumed += len(line) + 1
			lineOffset += int64(len(line) + 1)
			completed++
			if completed >= 100 {
				// Leave unread complete lines in the file, rather than advancing the cursor past the context budget.
				keep := consumed - partialBytes
				if keep < 0 {
					keep = 0
				}
				if keep > len(b) {
					keep = len(b)
				}
				b = b[:keep]
				body = ""
				break
			}
		}
		if len(body) > 64<<10 {
			prev.Dropping = true
			body = ""
		}
		if prev.Dropping {
			body = ""
		}
		if prev.Windows == nil {
			prev.Windows = map[string]logWindow{}
		}
		activeWindows := map[string]logWindow{}
		for _, rule := range a.LogRules {
			if databaseLogRule(rule.Config) {
				if rule.Config.Path != p {
					continue
				}
				windows, findings := databaseWindows(prev.Windows, rule, p, lines, now)
				for key, w := range windows {
					activeWindows[key] = w
				}
				out = append(out, findings...)
				continue
			}
			w, matched, count := advanceRuleWindow(prev.Windows[rule.ID], rule, p, lines, now)
			if matched {
				seconds := rule.Config.WindowSeconds
				if seconds <= 0 {
					seconds = 60
				}
				out = append(out, event(fmt.Sprintf("log-rule:%s:%s:%s:%d:%x", rule.ID, p, identity, offset, sha256.Sum256(b)), "Log rule matched", "agent-log", map[string]any{"ruleId": rule.ID, "path": p, "count": count, "windowSeconds": seconds}))
			}
			activeWindows[rule.ID] = w
		}
		if len(b) > 0 {
			sum := fmt.Sprintf("%x", sha256.Sum256(b))
			out = append(out, event(fmt.Sprintf("log:%s:%s:%d:%s", p, identity, offset, sum), "Configured log activity", "agent-log", map[string]any{"path": p, "offset": offset, "bytes": len(b), "sha256": sum, "lines": len(lines)}))
		}
		state["log:"+p] = fileState{Offset: offset + int64(len(b)), Prefix: sig, PrefixLength: n, Identity: identity, Partial: body, Dropping: prev.Dropping, Windows: activeWindows}
	}
	a.CollectorState = state
	return out
}

type cappedOutput struct {
	b         []byte
	truncated bool
}

func (w *cappedOutput) Write(b []byte) (int, error) {
	n := len(b)
	if len(w.b)+n > 256<<10 {
		w.truncated = true
	}
	if len(w.b) < 256<<10 {
		remaining := (256 << 10) - len(w.b)
		if len(b) > remaining {
			b = b[:remaining]
		}
		w.b = append(w.b, b...)
	}
	return n, nil
}
func packageInventory() ([]string, PackageCollection) {
	// CPUQuota also throttles package-manager subprocesses. Keep a bounded
	// collection window that permits a normal RPM database under that quota.
	return packageInventoryWithin(30 * time.Second)
}
func packageInventoryWithin(budget time.Duration) ([]string, PackageCollection) {
	for _, cmd := range [][]string{{"dpkg-query", "-W", "-f=${Package}\t${Version}\t${source:Package}\t${source:Version}\t${Architecture}\tdpkg\t${db:Status-Status}\n"}, {"rpm", "-qa", "--qf", "%{NAME}\t%{EPOCHNUM}:%{VERSION}-%{RELEASE}\t%{SOURCERPM}\t\t%{ARCH}\trpm\n"}} {
		ctx, cancel := context.WithTimeout(context.Background(), budget)
		c := exec.CommandContext(ctx, cmd[0], cmd[1:]...)
		output := &cappedOutput{}
		c.Stdout = output
		e := c.Run()
		cancel()
		if e == nil {
			return packageLines(output, nil)
		}
	}
	return []string{}, PackageCollection{Reason: "package manager unavailable or collection failed"}

}

func (a *Agent) commitCollectors() error {
	return writePrivate(filepath.Join(a.Config.StateDir, "collectors.json"), a.CollectorState)
}

type PackageCollection struct {
	Complete bool   `json:"complete"`
	Reason   string `json:"reason"`
}

func packageLines(output *cappedOutput, err error) ([]string, PackageCollection) {
	status := PackageCollection{Complete: err == nil, Reason: "collected"}
	if err != nil {
		status.Reason = "collection failed"
	}
	body := string(output.b)
	if output.truncated {
		status = PackageCollection{Reason: "output limit exceeded"}
		if i := strings.LastIndex(body, "\n"); i >= 0 {
			body = body[:i]
		} else {
			body = ""
		}
	}
	lines := []string{}
	if strings.TrimSpace(body) != "" {
		lines = strings.Split(strings.TrimSpace(body), "\n")
	}
	if len(lines) > 2000 {
		lines = lines[:2000]
		status = PackageCollection{Reason: "package count limit exceeded"}
	}
	return lines, status
}
