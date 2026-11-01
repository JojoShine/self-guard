package main

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

type hostLogContext struct {
	ID        string
	Message   string
	Timestamp time.Time
}

var defaultLogRedactions = []string{
	`(?i)(["']?authorization["']?\s*[:=]\s*)(?:bearer|basic)\s+[^\s,;]+`,
	`(?i)(["']?(?:password|passwd|pwd|token|access[_-]?token|refresh[_-]?token|secret|api[_-]?key|authorization)["']?\s*[:=]\s*)(?:"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|[^\s,;]+)`,
}

func compileLogRedactions(c Config) ([]*regexp.Regexp, error) {
	if len(c.LogRedactions) > 20 {
		return nil, errors.New("at most 20 log redactions allowed")
	}
	out := []*regexp.Regexp{}
	for _, pattern := range append(append([]string{}, defaultLogRedactions...), c.LogRedactions...) {
		if len(pattern) == 0 || len(pattern) > 512 {
			return nil, errors.New("log redaction pattern must contain 1-512 bytes")
		}
		r, err := regexp.Compile(pattern)
		if err != nil || r.MatchString("") {
			return nil, errors.New("invalid or empty-matching RE2 log redaction")
		}
		out = append(out, r)
	}
	return out, nil
}
func redactLogLine(line string, patterns []*regexp.Regexp) (string, bool) {
	for i, r := range patterns {
		replacement := "[REDACTED]"
		if i < len(defaultLogRedactions) {
			replacement = "$1[REDACTED]"
		}
		line = r.ReplaceAllString(line, replacement)
		if len(line) > 128<<10 {
			return "", false
		}
	}
	line = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) && r != '\t' {
			return ' '
		}
		return r
	}, strings.ToValidUTF8(line, "�"))
	if len(line) > 4096 {
		const tail = " [truncated]"
		line = line[:4096-len(tail)]
		for !utf8.ValidString(line) {
			line = line[:len(line)-1]
		}
		line += tail
	}
	return line, true
}
func (a *Agent) addLogContext(source, identity string, offset int64, line string, patterns []*regexp.Regexp, now time.Time) {
	message, ok := redactLogLine(line, patterns)
	if !ok {
		return
	}
	key := fmt.Sprintf("%s:%s:%s:%d:%x", a.Identity.AssetID, source, identity, offset, sha256.Sum256([]byte(line)))
	a.LogContexts = append(a.LogContexts, hostLogContext{ID: fmt.Sprintf("%x", sha256.Sum256([]byte(key))), Message: message, Timestamp: now})
}
