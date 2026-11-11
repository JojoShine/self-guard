package main

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func (q *Queue) rejectedCount() (int, error) {
	files, err := os.ReadDir(q.root)
	if err != nil {
		return 0, err
	}
	n := 0
	for _, file := range files {
		if strings.HasSuffix(file.Name(), ".rejected") {
			n++
		}
	}
	return n, nil
}
func (q *Queue) quarantine(name string) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	body, err := q.unseal(name)
	if err != nil {
		return err
	}
	digest := sha256.Sum256(body)
	target := strings.TrimSuffix(name, ".event") + "-" + hex.EncodeToString(digest[:]) + ".rejected"
	if err = os.Link(filepath.Join(q.root, name), filepath.Join(q.root, target)); err != nil && !os.IsExist(err) {
		return err
	}
	if err = os.Remove(filepath.Join(q.root, name)); err != nil && !os.IsNotExist(err) {
		return err
	}
	return syncDirectory(q.root)
}

// Called only while holding the process-wide queue lock, before workers start.
func (q *Queue) recoverUncommitted() (int, error) {
	files, err := os.ReadDir(q.root)
	if err != nil {
		return 0, err
	}
	referenced := map[string]bool{}
	manifests := map[string]bool{}
	for _, file := range files {
		if !strings.HasSuffix(file.Name(), ".event") && !strings.HasSuffix(file.Name(), ".rejected") {
			continue
		}
		event, err := q.load(file.Name())
		if err != nil {
			return 0, err
		}
		manifests[event.EventID] = true
		for _, part := range event.Chunks {
			referenced[chunkName(event.EventID, part)] = true
		}
	}
	groups := map[string][]string{}
	times := map[string]time.Time{}
	for _, file := range files {
		name := file.Name()
		if strings.HasSuffix(name, ".chunk") && !referenced[name] {
			if len(name) < 37 || !sourceIDPattern.MatchString(name[:36]) {
				return 0, errors.New("uncommitted evidence name invalid")
			}
			groups[name[:36]] = append(groups[name[:36]], name)
		} else if strings.HasSuffix(name, ".pending") {
			info, err := file.Info()
			if err != nil {
				return 0, err
			}
			id := sourceUUID("pending-recovery:" + name)
			groups[id] = append(groups[id], name)
			times[id] = info.ModTime()
		}
	}
	recovered := 0
	for original, names := range groups {
		id := sourceUUID("uncommitted:" + original)
		if !manifests[id] {
			event := q.newEvent()
			event.EventID = id
			event.SessionID = "recovery:" + original
			event.Operation = "PROBE_RECOVERY"
			event.gap("DISCONNECTED")
			event.gap("CORRELATION_UNKNOWN")
			event.gap("BODY_NOT_CAPTURED")
			var first, last time.Time
			for _, name := range names {
				at := times[original]
				if strings.HasSuffix(name, ".chunk") {
					body, err := q.unseal(name)
					if err != nil {
						return recovered, err
					}
					raw, err := os.ReadFile(filepath.Join(q.root, name))
					if err != nil || len(raw) < 8 {
						return recovered, errors.New("uncommitted capture time invalid")
					}
					at = time.Unix(0, int64(binary.BigEndian.Uint64(raw[:8])))
					if strings.Contains(name, "-REQUEST-") {
						event.RequestBytes += int64(len(body))
					} else if strings.Contains(name, "-RESPONSE-") {
						event.ResponseBytes += int64(len(body))
					}
				}
				if first.IsZero() || at.Before(first) {
					first = at
				}
				if last.IsZero() || at.After(last) {
					last = at
				}
			}
			if first.IsZero() {
				return recovered, errors.New("recovery timestamp unavailable")
			}
			event.StartedAt = first.UTC().Format(time.RFC3339Nano)
			event.EndedAt = last.UTC().Format(time.RFC3339Nano)
			body, err := json.Marshal(event)
			if err != nil {
				return recovered, err
			}
			if err = q.sealReserved(id+".event", body, true); err != nil {
				return recovered, err
			}
			recovered++
		}
		// Preserve a durable, explicit gap before reclaiming any uncommitted bytes.
		for _, name := range names {
			if err = os.Remove(filepath.Join(q.root, name)); err != nil && !os.IsNotExist(err) {
				return recovered, err
			}
		}
	}
	return recovered, syncDirectory(q.root)
}
