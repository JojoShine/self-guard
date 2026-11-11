//go:build linux

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"syscall"
	"time"
)

var version = "dev"
var uuidPattern = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

func readConfig(path string) (Config, error) {
	var c Config
	s, e := os.Stat(path)
	if e != nil || !s.Mode().IsRegular() || s.Mode().Perm()&0077 != 0 {
		return c, errors.New("configuration must be private regular file (0600)")
	}
	f, e := os.Open(path)
	if e != nil {
		return c, e
	}
	defer f.Close()
	d := json.NewDecoder(io.LimitReader(f, 64*1024))
	d.DisallowUnknownFields()
	if e = d.Decode(&c); e != nil {
		return c, errors.New("configuration invalid")
	}
	if c.Schema != "selfguard-suricata-config-v1" || !uuidPattern.MatchString(c.SensorID) || !uuidPattern.MatchString(c.AssetID) || c.Token == "" || !filepath.IsAbs(c.EVEPath) || c.IdentityPath != "/var/lib/selfguard-agent/identity.json" || c.StateDir != "/var/lib/selfguard-suricata/"+c.SensorID {
		return c, errors.New("configuration binding invalid")
	}
	return c, nil
}
func verifyIdentity(c Config) error {
	f, e := os.Open(c.IdentityPath)
	if e != nil {
		return errors.New("agent identity unavailable")
	}
	defer f.Close()
	var id struct {
		AssetID string `json:"assetId"`
	}
	if json.NewDecoder(io.LimitReader(f, 64*1024)).Decode(&id) != nil || id.AssetID != c.AssetID {
		return errors.New("agent asset binding mismatch")
	}
	return nil
}
func rulesHealth(c Config, h *Health) {
	if c.RuleFile == "" {
		return
	}
	f, e := regularOpen(c.RuleFile)
	if e != nil {
		h.Status = "ERROR"
		h.DetailCode = "RULE_FILE_UNAVAILABLE"
		return
	}
	defer f.Close()
	s, e := f.Stat()
	if e != nil || !s.Mode().IsRegular() || s.Size() > 32*1024*1024 {
		h.Status = "ERROR"
		h.DetailCode = "RULE_FILE_UNAVAILABLE"
		return
	}
	hash := sha256.New()
	n, e := io.Copy(hash, io.LimitReader(f, 32*1024*1024+1))
	if e != nil || n > 32*1024*1024 {
		h.Status = "ERROR"
		h.DetailCode = "RULE_FILE_UNAVAILABLE"
		return
	}
	h.RulesSHA256 = hex.EncodeToString(hash.Sum(nil))
	h.RulesModifiedAt = s.ModTime().UTC().Format(time.RFC3339Nano)
	if c.ExpectedRuleSHA256 != "" && h.RulesSHA256 != c.ExpectedRuleSHA256 {
		h.Status = "ERROR"
		h.DetailCode = "RULE_FILE_UNAVAILABLE"
	}
}
func run(c Config, once, local bool) error {
	if e := verifyIdentity(c); e != nil {
		return e
	}
	cl, e := newClient(c, local)
	if e != nil {
		return e
	}
	unlock, e := lockState(c.StateDir)
	if e != nil {
		return e
	}
	defer unlock()
	st, e := loadState(c.StateDir)
	if e != nil {
		return errors.New("persistent state invalid")
	}
	r := reader{path: c.EVEPath}
	defer r.close()
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(stop)
	mode := "LIVE"
	if once {
		mode = "REPLAY"
	}
	for {
		select {
		case <-stop:
			return nil
		default:
		}
		if e = cl.check(); e != nil {
			var reject *rejection
			if errors.As(e, &reject) && (reject.status == 401 || reject.status == 403) {
				return e
			}
			if once {
				return e
			}
			fmt.Fprintln(os.Stderr, "source check blocked; no EVE read")
			select {
			case <-stop:
				return nil
			case <-time.After(5 * time.Second):
				continue
			}
		}
		if st.Pending != nil {
			if e = deliver(cl, c.StateDir, &st); e != nil {
				var reject *rejection
				if errors.As(e, &reject) && (reject.status == 401 || reject.status == 403) {
					return e
				}
				if once {
					return e
				}
				fmt.Fprintln(os.Stderr, "pending batch blocked; retained for retry")
				select {
				case <-stop:
					return nil
				case <-time.After(5 * time.Second):
					continue
				}
			}
		}
		before := st.Cursor
		events, next, h, readErr := r.read(st.Cursor, c.ReadFromStart || once)
		if readErr != nil && !os.IsNotExist(readErr) {
			h.Status = "ERROR"
			h.DetailCode = "READ_ERROR"
		}
		st.Invalid += h.InvalidLines
		st.Skipped += h.SkippedLines
		st.Gaps += h.RotationGaps
		h.InvalidLines = st.Invalid
		h.SkippedLines = st.Skipped
		h.RotationGaps = st.Gaps
		h.PendingEvents = len(events)
		rulesHealth(c, &h)
		st.Pending = &Pending{Batch: Batch{BatchID: uuid(), Mode: mode, Events: events, Health: h}, Next: next}
		if e = saveState(c.StateDir, st); e != nil {
			return errors.New("state write failed")
		}
		if e = deliver(cl, c.StateDir, &st); e != nil {
			var reject *rejection
			if errors.As(e, &reject) && (reject.status == 401 || reject.status == 403) {
				return e
			}
			if once {
				return e
			}
			continue
		}
		if once && readErr != nil {
			return errors.New("replay incomplete: EVE unavailable or unreadable")
		}
		if once && len(events) == 0 && next == before {
			return r.replayEOF(next)
		}
		if once || len(events) > 0 {
			continue
		}
		select {
		case <-stop:
			return nil
		case <-time.After(10 * time.Second):
		}
	}
}
func main() {
	config := flag.String("config", "/etc/selfguard-suricata/config.json", "private config file")
	once := flag.Bool("once", false, "replay to EOF and exit (REPLAY evidence)")
	show := flag.Bool("version", false, "print version")
	local := flag.Bool("allow-local-http", false, "allow numeric loopback HTTP for isolated tests only")
	flag.Parse()
	if *show {
		fmt.Println("selfguard-suricata-bridge " + version)
		return
	}
	c, e := readConfig(*config)
	if e == nil {
		e = run(c, *once, *local)
	}
	if e != nil {
		fmt.Fprintln(os.Stderr, "suricata bridge stopped:", e)
		os.Exit(1)
	}
}
