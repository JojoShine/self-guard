package main

import "strings"

func secASCIILower(value string) string {
	first := -1
	for index := 0; index < len(value); index++ {
		if value[index] >= 'A' && value[index] <= 'Z' {
			first = index
			break
		}
	}
	if first < 0 {
		return value
	}
	b := []byte(value)
	for i := first; i < len(b); i++ {
		if b[i] >= 'A' && b[i] <= 'Z' {
			b[i] += 32
		}
	}
	return string(b)
}

// Return the first completed phrase in the input, with the original bytes for
// TX:0. Byte folding keeps binary data and source offsets intact.
func matchSecPhrases(phrases []string, value string) (string, bool) {
	folded := secASCIILower(value)
	firstEnd, firstStart := len(value)+1, -1
	for _, phrase := range phrases {
		if phrase == "" {
			continue
		}
		start := strings.Index(folded, secASCIILower(phrase))
		if start >= 0 && start+len(phrase) < firstEnd {
			firstStart, firstEnd = start, start+len(phrase)
		}
	}
	if firstStart < 0 {
		return "", false
	}
	return value[firstStart:firstEnd], true
}
