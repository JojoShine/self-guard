package main

import (
	"errors"
	"strings"
)

type secSQLToken struct {
	kind byte
	text string
}

func secSQLWord(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c == '_' || c == '$' || c == '@'
}
func secSQLTokens(value string, context byte) ([]secSQLToken, error) {
	tokens := []secSQLToken{}
	i := 0
	if context != 0 {
		end := strings.IndexByte(value, context)
		if end < 0 {
			return tokens, nil
		}
		tokens = append(tokens, secSQLToken{'s', value[:end]})
		i = end + 1
	}
	for i < len(value) {
		if len(tokens) >= 4096 {
			return nil, errors.New("SQL token budget exceeded")
		}
		c := value[i]
		if c <= 32 {
			i++
			continue
		}
		if strings.HasPrefix(value[i:], "/*") {
			end := strings.Index(value[i+2:], "*/")
			if end < 0 {
				break
			}
			i += end + 4
			continue
		}
		if strings.HasPrefix(value[i:], "--") || c == '#' {
			end := strings.IndexByte(value[i:], '\n')
			if end < 0 {
				break
			}
			i += end + 1
			continue
		}
		if c == '\'' || c == '"' || c == '`' {
			quote := c
			start := i
			i++
			for i < len(value) {
				if value[i] == '\\' && i+1 < len(value) {
					i += 2
					continue
				}
				if value[i] == quote {
					i++
					if i < len(value) && value[i] == quote {
						i++
						continue
					}
					break
				}
				i++
			}
			kind := byte('s')
			if quote == '`' {
				kind = 'w'
			}
			tokens = append(tokens, secSQLToken{kind, value[start:i]})
			continue
		}
		if c >= '0' && c <= '9' {
			start := i
			i++
			for i < len(value) && (value[i] >= '0' && value[i] <= '9' || value[i] == '.') {
				i++
			}
			tokens = append(tokens, secSQLToken{'n', value[start:i]})
			continue
		}
		if secSQLWord(c) {
			start := i
			i++
			for i < len(value) && (secSQLWord(value[i]) || value[i] >= '0' && value[i] <= '9') {
				i++
			}
			tokens = append(tokens, secSQLToken{'w', strings.ToLower(value[start:i])})
			continue
		}
		start := i
		i++
		if i < len(value) && strings.Contains("<>=!|&", string(c)) && strings.Contains("=<>|&", value[i:i+1]) {
			i++
		}
		tokens = append(tokens, secSQLToken{'o', value[start:i]})
	}
	return tokens, nil
}
func secSQLValue(token secSQLToken) bool {
	return token.kind == 'n' || token.kind == 's' || token.text == "null" || token.text == "true" || token.text == "false"
}
func secSQLGrammar(tokens []secSQLToken, quoted bool) string {
	functions := map[string]bool{"sleep": true, "pg_sleep": true, "benchmark": true, "load_file": true, "extractvalue": true, "updatexml": true, "xp_cmdshell": true, "utl_inaddr": true}
	statements := map[string]bool{"select": true, "insert": true, "update": true, "delete": true, "drop": true, "alter": true, "exec": true, "execute": true, "create": true}
	pipes := 0
	for i, token := range tokens {
		if token.text == "|" || token.text == "||" {
			pipes++
		}
		if functions[token.text] && i+2 < len(tokens) && tokens[i+1].text == "(" && tokens[i+2].text != ")" {
			return "self-sql:call"
		}
		if token.text == "waitfor" && i+2 < len(tokens) && tokens[i+1].text == "delay" && tokens[i+2].kind == 's' {
			return "self-sql:delay"
		}
		if token.text == ";" && i+2 < len(tokens) && statements[tokens[i+1].text] {
			return "self-sql:statement"
		}
		if (token.text == "and" || token.text == "or" || token.text == "&&" || token.text == "||") && i > 0 && i+3 < len(tokens) && secSQLValue(tokens[i-1]) && secSQLValue(tokens[i+1]) && secSQLValue(tokens[i+3]) {
			switch tokens[i+2].text {
			case "=", "!=", "<>", "<", ">", "<=", ">=":
				return "self-sql:comparison"
			}
		}
		if token.text == "union" {
			j := i + 1
			if j < len(tokens) && (tokens[j].text == "all" || tokens[j].text == "distinct") {
				j++
			}
			if j+1 >= len(tokens) || tokens[j].text != "select" {
				continue
			}
			j++
			if secSQLValue(tokens[j]) || tokens[j].text == "*" {
				return "self-sql:union"
			}
			for k := j + 1; k < len(tokens) && k < j+8; k++ {
				if tokens[k].text == "from" {
					return "self-sql:union"
				}
			}
		}
		if token.text == "select" && i+1 < len(tokens) && (tokens[i+1].text == "*" || tokens[i+1].text == "@@version" || tokens[i+1].text == "@@hostname") {
			return "self-sql:query"
		}
	}
	if quoted && pipes >= 2 && len(tokens) >= 5 {
		return "self-sql:quoted-operator"
	}
	return ""
}
func detectSecSQL(value string) (bool, string, error) {
	if len(value) > 1<<20 {
		return false, "", errors.New("SQL subject budget exceeded")
	}
	for _, context := range []byte{0, '\'', '"'} {
		tokens, err := secSQLTokens(value, context)
		if err != nil {
			return false, "", err
		}
		if fingerprint := secSQLGrammar(tokens, context != 0); fingerprint != "" {
			return true, fingerprint, nil
		}
	}
	return false, "", nil
}
