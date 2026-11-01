package main

import (
	"sort"
	"strconv"
	"strings"
)

type secRuleIndex struct {
	ID            string `json:"id"`
	File          string `json:"file"`
	Line          int    `json:"line"`
	Phase         int    `json:"phase"`
	ParanoiaLevel int    `json:"paranoiaLevel"`
	Inactive      bool   `json:"inactiveByConfiguration"`
}

func secLangRuleIndex(rules []secRule) []secRuleIndex {
	entries := []secRuleIndex{}
	constants := secProfileConstants(rules)
	for _, rule := range rules {
		if rule.ID == "" {
			continue
		}
		phase, _ := strconv.Atoi(secFirst(rule.Actions, "phase"))
		if phase == 0 {
			phase = 2
		}
		level := 1
		for _, tag := range rule.Actions["tag"] {
			if strings.HasPrefix(tag, "paranoia-level/") {
				value, err := strconv.Atoi(strings.TrimPrefix(tag, "paranoia-level/"))
				if err == nil {
					level = value
				}
			}
		}
		entries = append(entries, secRuleIndex{ID: rule.ID, File: rule.File, Line: rule.Line, Phase: phase, ParanoiaLevel: level, Inactive: secProfileConditionFalse(rule, constants)})
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].ID < entries[j].ID })
	return entries
}
