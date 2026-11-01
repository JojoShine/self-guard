package main

import (
	"strings"
	"time"
)

func advanceRuleWindow(w logWindow, rule PolicyRule, path string, lines []string, now time.Time) (logWindow, bool, int) {
	threshold := rule.Config.Threshold
	if threshold < 1 {
		threshold = 1
	}
	if threshold > 10000 {
		return w, false, 0
	}
	seconds := rule.Config.WindowSeconds
	if seconds <= 0 {
		seconds = 60
	}
	window := int64(seconds) * int64(time.Second)
	hits := []int64{}
	for _, hit := range w.Hits {
		if hit > now.UnixNano()-window && hit <= now.UnixNano() {
			hits = append(hits, hit)
		}
	}
	newHits := 0
	for _, line := range lines {
		if rule.Config.Field == "source" {
			line = path
		}
		if strings.Contains(line, rule.Config.Contains) {
			hits = append(hits, now.UnixNano())
			newHits++
		}
	}
	if len(hits) > threshold {
		hits = hits[len(hits)-threshold:]
	}
	matched := newHits > 0 && len(hits) >= threshold && (w.LastAlert == 0 || now.UnixNano()-w.LastAlert >= window)
	if matched {
		w.LastAlert = now.UnixNano()
	}
	w.Hits = hits
	return w, matched, len(hits)
}
