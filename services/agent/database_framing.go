package main

import "strings"

// Frame source records before decoding; physical newlines may occur inside CSV or JSON values.
func databaseRecord(body, format string) (string, string, bool) {
	if format == "postgresql-csv" || format == "postgresql-csv-sql" {
		quoted := false
		for i := 0; i < len(body); i++ {
			if body[i] == '"' {
				if quoted && i+1 < len(body) && body[i+1] == '"' {
					i++
					continue
				}
				quoted = !quoted
			}
			if body[i] == '\n' && !quoted {
				return strings.TrimSuffix(body[:i], "\r"), body[i+1:], true
			}
		}
		return "", body, false
	}
	start := 0
	for start < len(body) && strings.ContainsRune(" \r\n\t[],", rune(body[start])) {
		start++
	}
	if start == len(body) {
		return "", "", false
	}
	if body[start] != '{' {
		line, rest, ok := strings.Cut(body[start:], "\n")
		if ok {
			return line, rest, true
		}
		return "", body[start:], false
	}
	depth := 0
	quoted := false
	escaped := false
	for i := start; i < len(body); i++ {
		b := body[i]
		if quoted {
			if escaped {
				escaped = false
			} else if b == '\\' {
				escaped = true
			} else if b == '"' {
				quoted = false
			}
			continue
		}
		switch b {
		case '"':
			quoted = true
		case '{', '[':
			depth++
		case '}', ']':
			depth--
			if depth == 0 {
				return body[start : i+1], body[i+1:], true
			}
		}
	}
	return "", body[start:], false
}
func nativeRecordFormat(format string) bool {
 if databaseStatementFormat(format) {return true}
	return databaseIncludes([]string{"postgresql-csv", "postgresql-csv-sql", "postgresql-audit-json", "mysql-audit-json", "oracle-traditional-json", "oracle-unified-json", "sqlserver-audit-json", "dm-audit-json"}, format)
}
