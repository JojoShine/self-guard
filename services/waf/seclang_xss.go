package main

import (
	"errors"
	"html"
	"strings"
)

func secHTMLName(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == ':' || c == '-' || c == '_'
}
func secDangerousURL(value string) bool {
	value = html.UnescapeString(value)
	var normalized strings.Builder
	for i := 0; i < len(value); i++ {
		if value[i] > 32 && value[i] != 127 {
			normalized.WriteByte(value[i])
		}
	}
	value = strings.ToLower(normalized.String())
	return strings.HasPrefix(value, "javascript:") || strings.HasPrefix(value, "vbscript:") || strings.HasPrefix(value, "data:text/html") || strings.HasPrefix(value, "data:image/svg+xml")
}
func detectSecXSS(value string) (bool, error) {
	if len(value) > 1<<20 {
		return false, errors.New("HTML subject budget exceeded")
	}
	value = strings.ToLower(value)
	if secDangerousURL(value) {
		return true, nil
	}
	dangerous := map[string]bool{"script": true, "iframe": true, "object": true, "embed": true, "applet": true, "base": true, "meta": true}
	urlAttributes := map[string]bool{"href": true, "src": true, "action": true, "formaction": true, "background": true, "xlink:href": true, "data": true}
	for i := 0; i < len(value); {
		if value[i] != '<' {
			i++
			continue
		}
		i++
		if i == len(value) {
			break
		}
		if value[i] == '/' || value[i] == '!' || value[i] == '?' {
			continue
		}
		start := i
		for i < len(value) && secHTMLName(value[i]) {
			i++
		}
		if i == start {
			continue
		}
		tag := value[start:i]
		if colon := strings.LastIndexByte(tag, ':'); colon >= 0 {
			tag = tag[colon+1:]
		}
		if i < len(value) && value[i] != '>' && value[i] != '/' && value[i] > 32 {
			continue
		}
		if dangerous[tag] {
			return true, nil
		}
		for i < len(value) && value[i] != '>' && value[i] != '<' {
			if value[i] <= 32 || value[i] == '/' {
				i++
				continue
			}
			start = i
			for i < len(value) && secHTMLName(value[i]) {
				i++
			}
			if i == start {
				i++
				continue
			}
			name := value[start:i]
			for i < len(value) && value[i] <= 32 {
				i++
			}
			if i == len(value) || value[i] != '=' {
				continue
			}
			i++
			for i < len(value) && value[i] <= 32 {
				i++
			}
			start = i
			if i < len(value) && (value[i] == '\'' || value[i] == '"') {
				quote := value[i]
				i++
				start = i
				for i < len(value) && value[i] != quote {
					i++
				}
			} else {
				for i < len(value) && value[i] > 32 && value[i] != '>' {
					i++
				}
			}
			attribute := value[start:i]
			if i < len(value) && (value[i] == '\'' || value[i] == '"') {
				i++
			}
			if strings.HasPrefix(name, "on") && len(name) > 2 {
				return true, nil
			}
			if urlAttributes[name] && secDangerousURL(attribute) {
				return true, nil
			}
			if name == "style" {
				style := secCSSDecode(attribute)
				if strings.Contains(style, "expression(") || strings.Contains(style, "javascript:") || strings.Contains(style, "vbscript:") {
					return true, nil
				}
			}
		}
	}
	return false, nil
}
