//go:build linux

package main

import (
	"bufio"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

const maxLine = 256 * 1024
const maxRead = 4 * 1024 * 1024

type Cursor struct {
	FileID     string `json:"fileId"`
	Generation string `json:"generation"`
	Offset     int64  `json:"offset"`
	Discard    bool   `json:"discard,omitempty"`
	Anchor     string `json:"anchor,omitempty"`
}
type Health struct {
	Status          string `json:"status"`
	DetailCode      string `json:"detailCode"`
	ObservedAt      string `json:"observedAt"`
	InvalidLines    uint64 `json:"invalidLines"`
	SkippedLines    uint64 `json:"skippedLines"`
	RotationGaps    uint64 `json:"rotationGaps"`
	PendingEvents   int    `json:"pendingEvents"`
	RulesSHA256     string `json:"rulesSha256,omitempty"`
	RulesModifiedAt string `json:"rulesModifiedAt,omitempty"`
}
type reader struct {
	path string
	f    *os.File
	id   string
}

func uuid() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic("random source unavailable")
	}
	b[6] = (b[6] & 15) | 64
	b[8] = (b[8] & 63) | 128
	s := hex.EncodeToString(b[:])
	return s[:8] + "-" + s[8:12] + "-" + s[12:16] + "-" + s[16:20] + "-" + s[20:]
}
func fileID(s os.FileInfo) string {
	v := s.Sys().(*syscall.Stat_t)
	return fmt.Sprintf("%d:%d", v.Dev, v.Ino)
}
func regularOpen(p string) (*os.File, error) {
	fd, e := syscall.Open(p, syscall.O_RDONLY|syscall.O_NONBLOCK|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if e != nil {
		return nil, e
	}
	f := os.NewFile(uintptr(fd), p)
	s, e := f.Stat()
	if e != nil || !s.Mode().IsRegular() {
		f.Close()
		return nil, errors.New("EVE must be regular file")
	}
	return f, nil
}
func (r *reader) close() {
	if r.f != nil {
		r.f.Close()
		r.f = nil
	}
}
func (r *reader) open(c Cursor) (bool, error) {
	if r.f != nil && r.id == c.FileID {
		return false, nil
	}
	r.close()
	if c.FileID != "" {
		paths, err := filepath.Glob(filepath.Join(filepath.Dir(r.path), "*"))
		if err != nil {
			return false, err
		}
		for _, p := range paths {
			s, e := os.Stat(p)
			if e == nil && s.Mode().IsRegular() && fileID(s) == c.FileID {
				f, e := regularOpen(p)
				if e == nil {
					r.f = f
					r.id = c.FileID
					return false, nil
				}
			}
		}
	}
	f, e := regularOpen(r.path)
	if e != nil {
		return false, e
	}
	s, e := f.Stat()
	if e != nil {
		f.Close()
		return false, e
	}
	r.f = f
	r.id = fileID(s)
	return c.FileID != "" && c.FileID != r.id, nil
}
func anchor(f *os.File, off int64) string {
	n := int64(128)
	if off < n {
		n = off
	}
	if n == 0 {
		return ""
	}
	b := make([]byte, n)
	got, e := f.ReadAt(b, off-n)
	if e != nil || int64(got) != n {
		return "mismatch"
	}
	return digest(b)
}
func (r *reader) read(c Cursor, start bool) ([]Event, Cursor, Health, error) {
	h := Health{Status: "WAITING", DetailCode: "WAITING_FOR_EVE", ObservedAt: time.Now().UTC().Format(time.RFC3339Nano)}
	events := []Event{}
	gap, e := r.open(c)
	if e != nil {
		if !os.IsNotExist(e) {
			h.Status = "ERROR"
			h.DetailCode = "READ_ERROR"
		}
		return events, c, h, e
	}
	if gap {
		h.RotationGaps++
	}
	s, e := r.f.Stat()
	if e != nil {
		return events, c, h, e
	}
	if c.FileID != r.id {
		initial := c.FileID == ""
		c = Cursor{FileID: r.id, Generation: uuid()}
		if initial && !start {
			c.Offset = s.Size()
			if c.Offset > 0 {
				var last [1]byte
				if n, err := r.f.ReadAt(last[:], c.Offset-1); err == nil && n == 1 && last[0] != '\n' {
					c.Discard = true
				}
			}
			c.Anchor = anchor(r.f, c.Offset)
		}
	} else if s.Size() < c.Offset || (c.Anchor != "" && anchor(r.f, c.Offset) != c.Anchor) {
		h.RotationGaps++
		c = Cursor{FileID: r.id, Generation: uuid()}
	}
	if _, e = r.f.Seek(c.Offset, io.SeekStart); e != nil {
		return events, c, h, e
	}
	br := bufio.NewReaderSize(io.LimitReader(r.f, maxRead), 32*1024)
	consumed := 0
	for len(events) < 50 && consumed < maxRead {
		begin := c.Offset
		line := []byte{}
		discard := c.Discard
		alreadyDiscard := c.Discard
		complete := false
		for {
			part, err := br.ReadSlice('\n')
			consumed += len(part)
			if !discard && len(line)+len(part) <= maxLine {
				line = append(line, part...)
			} else {
				discard = true
				line = nil
			}
			if err == nil {
				c.Offset += int64(len(part))
				complete = true
				break
			}
			if err == bufio.ErrBufferFull {
				c.Offset += int64(len(part))
				continue
			}
			if err != io.EOF {
				return events, c, h, err
			}
			if discard {
				c.Offset += int64(len(part))
				c.Discard = true
			} else {
				c.Offset = begin
			}
			break
		}
		if !complete {
			if discard && !alreadyDiscard {
				h.InvalidLines++
			}
			break
		}
		c.Discard = false
		if discard {
			if !alreadyDiscard {
				h.InvalidLines++
			}
			continue
		}
		line = line[:len(line)-1]
		if len(line) == 0 {
			h.InvalidLines++
			continue
		}
		event, err := normalize(line, c.Generation, begin)
		if err == errSkipped {
			h.SkippedLines++
		} else if err != nil {
			h.InvalidLines++
		} else {
			events = append(events, event)
		}
	}
	c.Anchor = anchor(r.f, c.Offset)
	if len(events) > 0 {
		h.Status = "READING"
		h.DetailCode = "OK"
	}
	if h.InvalidLines > 0 {
		h.Status = "ERROR"
		h.DetailCode = "INVALID_EVE"
	}
	if h.RotationGaps > 0 {
		h.Status = "ERROR"
		h.DetailCode = "ROTATION_GAP"
	}
	// Switch only once the old handle has been drained. A partial final line in a
	// rotated file cannot be completed; report that loss explicitly.
	if current, err := os.Stat(r.path); err == nil && fileID(current) != r.id && len(events) < 50 {
		old, _ := r.f.Stat()
		if old != nil && (c.Offset >= old.Size() || consumed < maxRead) {
			// Directory names/mtimes do not prove a consecutive generation chain.
			// More files may have rotated while this handle was backlogged, so
			// jumping to the current pathname must never imply complete coverage.
			h.RotationGaps++
			h.Status = "ERROR"
			h.DetailCode = "ROTATION_GAP"
			r.close()
			f, err := regularOpen(r.path)
			if err == nil {
				s, _ := f.Stat()
				r.f = f
				r.id = fileID(s)
				c = Cursor{FileID: r.id, Generation: uuid()}
			}
		}
	}
	return events, c, h, nil
}

// A stable cursor alone is not EOF: short partial lines retain their starting
// offset and oversized incomplete lines retain discard state at the file end.
func (r *reader) replayEOF(c Cursor) error {
	if r.f == nil || c.FileID != r.id || c.Discard {
		return errors.New("replay incomplete: EVE has no proven complete EOF")
	}
	s, err := r.f.Stat()
	if err != nil || s.Size() != c.Offset {
		return errors.New("replay incomplete: EVE has unread or partial data")
	}
	current, err := os.Stat(r.path)
	if err != nil || fileID(current) != r.id {
		return errors.New("replay incomplete: EVE changed during completion")
	}
	return nil
}
