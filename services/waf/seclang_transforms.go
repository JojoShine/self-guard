package main

import (
	"fmt"
	"strconv"
	"strings"
)

func secWhitespace(b byte) bool { return b == ' ' || b >= 9 && b <= 13 || b == 0xa0 }
func secHTMLDecode(value string) string {
	if !strings.Contains(value, "&") {
		return value
	}
	var output strings.Builder
	names := []struct {
		name  string
		value byte
	}{{"quot", '"'}, {"amp", '&'}, {"lt", '<'}, {"gt", '>'}, {"nbsp", 0xa0}}
	for i := 0; i < len(value); i++ {
		if value[i] != '&' {
			output.WriteByte(value[i])
			continue
		}
		start := i
		cursor := i + 1
		matched := false
		if cursor < len(value) && value[cursor] == '#' {
			cursor++
			base := 10
			if cursor < len(value) && (value[cursor] == 'x' || value[cursor] == 'X') {
				base = 16
				cursor++
			}
			digits := cursor
			var decoded byte
			for cursor < len(value) {
				digit, err := strconv.ParseUint(value[cursor:cursor+1], base, 4)
				if err != nil {
					break
				}
				decoded = byte(int(decoded)*base + int(digit))
				cursor++
			}
			if cursor > digits {
				if cursor < len(value) && value[cursor] == ';' {
					cursor++
				}
				output.WriteByte(decoded)
				i = cursor - 1
				matched = true
			}
		} else {
			for _, entry := range names {
				if len(value)-cursor >= len(entry.name) && strings.EqualFold(value[cursor:cursor+len(entry.name)], entry.name) {
					cursor += len(entry.name)
					if cursor < len(value) && value[cursor] == ';' {
						cursor++
					}
					output.WriteByte(entry.value)
					i = cursor - 1
					matched = true
					break
				}
			}
		}
		if !matched {
			output.WriteByte(value[start])
		}
	}
	return output.String()
}
func secReplaceComments(value string) string {
	var output strings.Builder
	for i := 0; i < len(value); {
		if strings.HasPrefix(value[i:], "/*") {
			output.WriteByte(' ')
			end := strings.Index(value[i+2:], "*/")
			if end < 0 {
				break
			}
			i += end + 4
		} else {
			output.WriteByte(value[i])
			i++
		}
	}
	return output.String()
}
func secRemoveCommentCharacters(value string) string {
	var output strings.Builder
	for i := 0; i < len(value); {
		if strings.HasPrefix(value[i:], "/*") || strings.HasPrefix(value[i:], "*/") || strings.HasPrefix(value[i:], "--") {
			i += 2
		} else if value[i] == '#' {
			i++
		} else {
			output.WriteByte(value[i])
			i++
		}
	}
	return output.String()
}
func secNormalizePath(value string, windows bool) string {
	if windows {
		value = strings.ReplaceAll(value, "\\", "/")
	}
	absolute := strings.HasPrefix(value, "/")
	trailing := strings.HasSuffix(value, "/") || strings.HasSuffix(value, "/.") || strings.HasSuffix(value, "/..")
	parts := []string{}
	for _, part := range strings.Split(value, "/") {
		switch part {
		case "", ".":
			continue
		case "..":
			if len(parts) > 0 && parts[len(parts)-1] != ".." {
				parts = parts[:len(parts)-1]
			} else {
				parts = append(parts, part)
			}
		default:
			parts = append(parts, part)
		}
	}
	result := strings.Join(parts, "/")
	if absolute {
		result = "/" + result
	}
	if trailing && result != "" && result != "/" {
		result += "/"
	}
	return result
}
func secCommandLine(value string) string {
	var output strings.Builder
	space := false
	for i := 0; i < len(value); i++ {
		b := value[i]
		if b == '\\' || b == '\'' || b == '"' || b == '^' {
			continue
		}
		if b == ',' || b == ';' || secWhitespace(b) {
			if !space {
				output.WriteByte(' ')
				space = true
			}
			continue
		}
		if b >= 'A' && b <= 'Z' {
			b += 32
		}
		output.WriteByte(b)
		space = false
	}
	result := output.String()
	result = strings.ReplaceAll(result, " /", "/")
	return strings.ReplaceAll(result, " (", "(")
}

// multiMatch examines original bytes and every changed intermediate result.
// t:none clears the preceding transform list before any operator is invoked.
func secTransformStages(value string, transforms []string, multi bool) ([]string, error) {
	if !multi {
		final, err := transformSecValue(value, transforms)
		return []string{final}, err
	}
	start := 0
	for i, transform := range transforms {
		if strings.EqualFold(transform, "none") {
			start = i + 1
		}
	}
	stages := []string{value}
	size := len(value)
	for _, transform := range transforms[start:] {
		next, err := transformSecValue(value, []string{transform})
		if err != nil {
			return nil, err
		}
		if next != value {
			size += len(next)
			if size > 8<<20 || len(stages) >= 64 {
				return nil, fmt.Errorf("multiMatch transformation budget exceeded")
			}
			stages = append(stages, next)
		}
		value = next
	}
	return stages, nil
}
