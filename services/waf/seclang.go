package main

import (
	"crypto/sha1"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"
)

type secRule struct {
	Directive        string              `json:"directive"`
	ID               string              `json:"id"`
	File             string              `json:"file"`
	Line             int                 `json:"line"`
	Targets          string              `json:"targets"`
	Operator         string              `json:"operator"`
	Operand          string              `json:"operand"`
	Negated          bool                `json:"negated"`
	Actions          map[string][]string `json:"actions"`
	ActionOrder      []secAction         `json:"actionOrder"`
	Phrases          []string            `json:"-"`
	PhraseDataLoaded bool                `json:"-"`
	Chain            []secRule           `json:"chain,omitempty"`
}
type secAction struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}
type secCompatibility struct {
	InactiveByConfiguration int      `json:"inactiveByConfiguration"`
	Publishable             bool     `json:"publishable"`
	Parsed                  int      `json:"parsed"`
	Unsupported             []string `json:"unsupported"`
	OutsideProfile          int      `json:"outsideProfile"`
	Engine                  string   `json:"engine"`
}
type secResult struct {
	ProcessorError      string             `json:"processorError,omitempty"`
	DiagnosticEnabled   bool               `json:"diagnosticEnabled,omitempty"`
	DiagnosticLog       []string           `json:"diagnosticLog,omitempty"`
	DiagnosticTruncated bool               `json:"diagnosticTruncated,omitempty"`
	AuditEnabled        bool               `json:"auditEnabled"`
	Evidence            []secMatchEvidence `json:"evidence,omitempty"`
	OmittedEvidence     int                `json:"omittedEvidence,omitempty"`
	Incomplete          []string           `json:"incomplete,omitempty"`
	Status              int                `json:"status,omitempty"`
	Blocked             bool               `json:"blocked"`
	Score               int                `json:"score"`
	Matches             []string           `json:"matches"`
	Variables           map[string]string  `json:"variables"`
}

func secTokens(line string) ([]string, error) {
	var result []string
	for i := 0; i < len(line); {
		for i < len(line) && (line[i] == ' ' || line[i] == '\t' || line[i] == '\r') {
			i++
		}
		if i == len(line) || line[i] == '#' {
			break
		}
		var token strings.Builder
		if line[i] == '"' {
			i++
			closed := false
			for i < len(line) {
				if line[i] == '"' {
					i++
					closed = true
					break
				}
				if line[i] == '\\' && i+1 < len(line) && line[i+1] == '"' {
					token.WriteByte('"')
					i += 2
				} else {
					token.WriteByte(line[i])
					i++
				}
			}
			if !closed {
				return nil, errors.New("unclosed quoted argument")
			}
		} else {
			start := i
			for i < len(line) && line[i] != ' ' && line[i] != '\t' && line[i] != '\r' {
				i++
			}
			token.WriteString(line[start:i])
		}
		result = append(result, token.String())
	}
	return result, nil
}
func secActions(value string) (map[string][]string, []secAction, error) {
	actions := map[string][]string{}
	order := []secAction{}
	start := 0
	quoted := false
	for i := 0; i <= len(value); i++ {
		if i < len(value) && value[i] == '\'' && (i == 0 || value[i-1] != '\\') {
			quoted = !quoted
		}
		if i < len(value) && (value[i] != ',' || quoted) {
			continue
		}
		part := strings.TrimSpace(value[start:i])
		start = i + 1
		if part == "" {
			continue
		}
		name, val, _ := strings.Cut(part, ":")
		name = strings.ToLower(strings.TrimSpace(name))
		val = strings.TrimSpace(val)
		if len(val) >= 2 && val[0] == '\'' && val[len(val)-1] == '\'' {
			val = val[1 : len(val)-1]
		}
		actions[name] = append(actions[name], val)
		order = append(order, secAction{name, val})
	}
	if quoted {
		return nil, nil, errors.New("unclosed action value")
	}
	return actions, order, nil
}
func secFirst(actions map[string][]string, key string) string {
	if len(actions[key]) > 0 {
		return actions[key][0]
	}
	return ""
}
func parseSecLang(file, source string) ([]secRule, error) {
	if len(source) > 3<<20 || !utf8.ValidString(source) {
		return nil, errors.New("invalid or oversized rule source")
	}
	lines := strings.Split(strings.ReplaceAll(source, "\r\n", "\n"), "\n")
	result := []secRule{}
	ids := map[string]bool{}
	var chainRoot *secRule
	chainPending := false
	for number := 0; number < len(lines); number++ {
		firstLine := number + 1
		line := strings.TrimSpace(lines[number])
		for strings.HasSuffix(line, "\\") && number+1 < len(lines) {
			number++
			line = strings.TrimSuffix(line, "\\") + strings.TrimSpace(lines[number])
		}
		tokens, err := secTokens(line)
		if err != nil {
			return nil, fmt.Errorf("%s:%d: %w", file, firstLine, err)
		}
		if len(tokens) == 0 {
			continue
		}
		r := secRule{Directive: tokens[0], File: file, Line: firstLine, Actions: map[string][]string{}}
		switch tokens[0] {
		case "SecRule":
			if len(tokens) != 4 && !(chainPending && len(tokens) == 3) {
				return nil, fmt.Errorf("%s:%d: SecRule requires targets, operator and actions", file, firstLine)
			}
			r.Targets = tokens[1]
			op := tokens[2]
			if strings.HasPrefix(op, "!") {
				r.Negated = true
				op = op[1:]
			}
			if strings.HasPrefix(op, "@") {
				r.Operator, r.Operand, _ = strings.Cut(op[1:], " ")
				r.Operator = strings.ToLower(r.Operator)
			} else {
				r.Operator = "rx"
				r.Operand = op
			}
			if len(tokens) == 4 {
				r.Actions, r.ActionOrder, err = secActions(tokens[3])
			}
		case "SecAction":
			if len(tokens) != 2 {
				return nil, errors.New("SecAction requires actions")
			}
			r.Actions, r.ActionOrder, err = secActions(tokens[1])
		case "SecRuleUpdateTargetById":
			if len(tokens) != 3 {
				return nil, errors.New("target update requires one rule ID and target list")
			}
			r.Operand = tokens[1]
			r.Targets = tokens[2]
		case "SecMarker", "SecComponentSignature":
			if len(tokens) != 2 {
				return nil, errors.New("directive requires one argument")
			}
			r.Operand = tokens[1]
		default:
			r.Operand = strings.Join(tokens[1:], " ")
		}
		if err != nil {
			return nil, err
		}
		r.ID = secFirst(r.Actions, "id")
		if chainPending {
			if r.Directive != "SecRule" || r.ID != "" {
				return nil, errors.New("chain continuation must be an unnumbered SecRule")
			}
			chainRoot.Chain = append(chainRoot.Chain, r)
			chainPending = len(r.Actions["chain"]) > 0
			continue
		}
		if r.Directive == "SecRule" || r.Directive == "SecAction" {
			if r.ID == "" || ids[r.ID] {
				return nil, errors.New("missing or duplicate rule ID")
			}
			ids[r.ID] = true
		}
		result = append(result, r)
		if len(result) > 10000 {
			return nil, errors.New("rule count limit exceeded")
		}
		chainRoot = &result[len(result)-1]
		chainPending = len(r.Actions["chain"]) > 0
	}
	if chainPending {
		return nil, errors.New("incomplete rule chain")
	}
	return result, nil
}

var secOperators = map[string]bool{"contains": true, "streq": true, "beginswith": true, "endswith": true, "within": true, "eq": true, "ge": true, "gt": true, "lt": true, "le": true, "unconditionalmatch": true, "pm": true, "ipmatch": true, "validatebyterange": true, "validateurlencoding": true, "validateutf8encoding": true, "detectsqli": true, "detectxss": true}
var secTransforms = map[string]bool{"none": true, "lowercase": true, "length": true, "urldecode": true, "urldecodeuni": true, "htmlentitydecode": true, "removenulls": true, "compresswhitespace": true, "removewhitespace": true, "hexencode": true, "sha1": true, "replacecomments": true, "removecommentschar": true, "normalizepath": true, "normalizepathwin": true, "cmdline": true, "jsdecode": true, "cssdecode": true, "escapeseqdecode": true, "base64decode": true, "utf8tounicode": true}
var secActionNames = map[string]bool{"id": true, "phase": true, "deny": true, "block": true, "pass": true, "log": true, "nolog": true, "auditlog": true, "noauditlog": true, "msg": true, "tag": true, "ver": true, "severity": true, "status": true, "rev": true, "accuracy": true, "maturity": true, "t": true, "chain": true, "setvar": true, "skipafter": true, "capture": true, "multimatch": true, "skip": true, "ctl": true, "logdata": true}
var secTargetCollections = map[string]bool{"ARGS": true, "ARGS_NAMES": true, "REQUEST_HEADERS": true, "REQUEST_HEADERS_NAMES": true, "REQUEST_COOKIES": true, "REQUEST_COOKIES_NAMES": true, "REQUEST_URI": true, "REQUEST_URI_RAW": true, "REQUEST_FILENAME": true, "REQUEST_METHOD": true, "REQUEST_PROTOCOL": true, "REQUEST_BODY": true, "QUERY_STRING": true, "REMOTE_ADDR": true, "TX": true, "ARGS_GET": true, "ARGS_POST": true, "ARGS_GET_NAMES": true, "ARGS_POST_NAMES": true, "REQUEST_BASENAME": true, "REQUEST_BODY_LENGTH": true, "REQUEST_LINE": true, "UNIQUE_ID": true, "ARGS_COMBINED_SIZE": true, "REQBODY_PROCESSOR": true, "FILES": true, "FILES_NAMES": true, "FILES_COMBINED_SIZE": true, "MULTIPART_PART_HEADERS": true, "XML": true, "MATCHED_VAR": true, "MATCHED_VAR_NAME": true, "MATCHED_VARS": true, "MATCHED_VARS_NAMES": true, "URLENCODED_ERROR": true, "REQBODY_ERROR": true, "REQBODY_PROCESSOR_ERROR": true, "REQBODY_ERROR_MSG": true, "REQBODY_PROCESSOR_ERROR_MSG": true}

func secLangCompatibility(rules []secRule) secCompatibility {
	report := secCompatibility{Publishable: true, Parsed: len(rules), Unsupported: []string{}, Engine: "selfguard-seclang-v1"}
	unsupported := map[string]bool{}
	compiled, compileErr := secCompileTargets(rules)
	if compileErr != nil {
		report.Publishable = false
		report.Unsupported = []string{"directive:target-update-invalid"}
		return report
	}
	rules = compiled
	constants := secProfileConstants(rules)
	var check func(secRule, string)
	check = func(r secRule, inheritedPhase string) {
		if values := r.Actions["status"]; len(values) > 0 {
			status, err := strconv.Atoi(values[0])
			if len(values) != 1 || err != nil || status < 200 || status > 599 {
				unsupported["action:status-invalid"] = true
			}
		}
		if values := r.Actions["skip"]; len(values) > 0 {
			n, err := strconv.Atoi(values[0])
			if len(values) != 1 || err != nil || n < 0 || n > 10000 || len(r.Actions["skipafter"]) > 0 {
				unsupported["action:skip-invalid"] = true
			}
		}
		phase := secFirst(r.Actions, "phase")
		if phase == "" {
			phase = inheritedPhase
		}
		if phase == "3" || phase == "4" || phase == "5" {
			report.OutsideProfile++
			return
		}
		if phase != "" && phase != "1" && phase != "2" {
			unsupported["phase:"+phase] = true
		}
		if secProfileConditionFalse(r, constants) {
			report.InactiveByConfiguration += secRuleTreeSize(r)
			return
		}
		if r.Directive != "SecRule" && r.Directive != "SecAction" && r.Directive != "SecMarker" && r.Directive != "SecComponentSignature" {
			unsupported["directive:"+r.Directive] = true
		}
		if r.Directive == "SecRule" && !(secOperators[r.Operator] || r.Operator == "rx" && secRegexAvailable() || r.Operator == "pmfromfile" && r.PhraseDataLoaded) {
			unsupported["operator:"+r.Operator] = true
		}
		if (r.Operator == "pm" || r.Operator == "pmfromfile") && strings.Contains(r.Operand, "%{") {
			unsupported["phrase:macro"] = true
		}

		if r.Directive == "SecRule" && !strings.Contains(r.Operand, "%{") {
			sample := ""
			if r.Operator == "ipmatch" {
				sample = "192.0.2.1"
			}
			if r.Operator == "ipmatch" || r.Operator == "validatebyterange" || r.Operator == "rx" && secRegexAvailable() {
				if _, err := matchSecOperator(r.Operator, r.Operand, sample); err != nil {
					unsupported["operand:"+r.ID] = true
				}
			}
		}
		macroValues := []string{r.Operand, r.Targets}
		for _, action := range r.ActionOrder {
			macroValues = append(macroValues, action.Value)
			if action.Name == "setvar" {
				name, _, _ := strings.Cut(action.Value, "=")
				if !strings.HasPrefix(strings.ToLower(name), "tx.") {
					unsupported["setvar:collection"] = true
				}
			}
		}
		for _, value := range macroValues {
			for strings.Contains(value, "%{") {
				start := strings.Index(value, "%{")
				end := strings.Index(value[start:], "}")
				if end < 0 {
					unsupported["macro:unterminated"] = true
					break
				}
				name := strings.ToLower(value[start+2 : start+end])
				if !secMacroSupported(name) {
					unsupported["macro:"+name] = true
				}
				value = value[start+end+1:]
			}
		}
		for key, values := range r.Actions {
			if !secActionNames[key] {
				unsupported["action:"+key] = true
			}
			if key == "ctl" {
				for _, value := range values {
					if control, err := parseSecControl(value); err != nil {
						name, _, _ := strings.Cut(value, "=")
						unsupported["ctl:"+name] = true
					} else if (control.name == "requestbodyprocessor" || control.name == "forcerequestbodyvariable") && phase != "1" {
						unsupported["ctl:body-phase"] = true
					}
				}
			}
			if key == "t" {
				for _, v := range values {
					if !secTransforms[strings.ToLower(v)] {
						unsupported["transform:"+v] = true
					}
				}
			}
			if key == "setvar" {
				for _, v := range values {
					if !strings.HasPrefix(strings.ToLower(v), "tx.") || !strings.Contains(v, "=") {
						unsupported["setvar:"+v] = true
					}
				}
			}
		}
		if strings.Contains(r.Targets, "%{") {
			unsupported["variable-selector:dynamic"] = true
		}
		selectors, selectorErr := secParseSelectors(r.Targets)
		if selectorErr != nil {
			unsupported["variable-selector:invalid"] = true
		}
		for _, selector := range selectors {
			target := selector.target
			if target == "" {
				continue
			}
			name := strings.TrimLeft(target, "&!")
			collection, _, _ := strings.Cut(name, ":")
			if !secTargetCollections[strings.ToUpper(collection)] {
				unsupported["variable:"+collection] = true
			}
			if selector.regex {
				if !secRegexAvailable() {
					unsupported["variable-selector:regex-runtime"] = true
				} else if _, err := matchSecRegex("(?i)"+selector.key, ""); err != nil {
					unsupported["variable-selector:regex-operand"] = true
				}
			}
		}
		for index, child := range r.Chain {
			for _, name := range []string{"deny", "block", "pass", "phase", "skipafter", "skip", "status"} {
				if len(child.Actions[name]) > 0 {
					unsupported["chain-action:"+name] = true
				}
			}
			check(child, phase)
			if secProfileConditionFalse(child, constants) {
				for _, remaining := range r.Chain[index+1:] {
					report.InactiveByConfiguration += secRuleTreeSize(remaining)
				}
				break
			}
		}
	}
	for _, r := range rules {
		check(r, "2")
	}
	for item := range unsupported {
		report.Unsupported = append(report.Unsupported, item)
	}
	sort.Strings(report.Unsupported)
	report.Publishable = len(report.Unsupported) == 0
	return report
}
func expandSecValue(value string, tx map[string]string, scopes ...func(string) (string, error)) (string, error) {
	var result strings.Builder
	macros := 0
	appendBounded := func(part string) error {
		if result.Len()+len(part) > 1<<20 {
			return errors.New("macro expansion exceeds 1 MiB")
		}
		result.WriteString(part)
		return nil
	}
	for {
		start := strings.Index(value, "%{")
		if start < 0 {
			if err := appendBounded(value); err != nil {
				return "", err
			}
			break
		}
		macros++
		if macros > 1024 {
			return "", errors.New("macro count limit")
		}
		if err := appendBounded(value[:start]); err != nil {
			return "", err
		}
		end := strings.Index(value[start:], "}")
		if end < 0 {
			return "", errors.New("unclosed macro")
		}
		name := strings.ToLower(value[start+2 : start+end])
		var replacement string
		if strings.HasPrefix(name, "tx.") {
			replacement = tx[strings.TrimPrefix(name, "tx.")]
		} else if len(scopes) > 0 {
			var err error
			replacement, err = scopes[0](name)
			if err != nil {
				return "", err
			}
		} else {
			return "", errors.New("unsupported macro collection")
		}
		if err := appendBounded(replacement); err != nil {
			return "", err
		}
		value = value[start+end+1:]
	}
	return result.String(), nil
}
func decodeSecURL(value string, unicode bool) string {
	if !strings.ContainsAny(value, "%+") {
		return value
	}
	var result strings.Builder
	for i := 0; i < len(value); i++ {
		if value[i] == '+' {
			result.WriteByte(' ')
			continue
		}
		if value[i] == '%' && unicode && i+5 < len(value) && (value[i+1] == 'u' || value[i+1] == 'U') {
			if code, err := strconv.ParseUint(value[i+2:i+6], 16, 16); err == nil {
				if code >= 0xff01 && code <= 0xff5e {
					code -= 0xfee0
				}
				result.WriteByte(byte(code))
				i += 5
				continue
			}
		}
		if value[i] == '%' && i+2 < len(value) {
			if code, err := strconv.ParseUint(value[i+1:i+3], 16, 8); err == nil {
				result.WriteByte(byte(code))
				i += 2
				continue
			}
		}
		result.WriteByte(value[i])
	}
	return result.String()
}
func transformSecValue(value string, transforms []string) (string, error) {
	// t:none resets the inherited transformation list. This engine has no implicit
	// decoding; transformations are applied in the declared order only.
	start := 0
	for i, t := range transforms {
		if strings.EqualFold(t, "none") {
			start = i + 1
		}
	}
	for _, t := range transforms[start:] {
		switch strings.ToLower(t) {
		case "lowercase":
			value = secASCIILower(value)
		case "compresswhitespace", "removewhitespace":
			var output strings.Builder
			space := false
			for i := 0; i < len(value); i++ {
				white := secWhitespace(value[i])
				if white {
					if strings.EqualFold(t, "compressWhitespace") && !space {
						output.WriteByte(' ')
					}
					space = true
				} else {
					output.WriteByte(value[i])
					space = false
				}
			}
			value = output.String()
		case "hexencode":
			value = hex.EncodeToString([]byte(value))
		case "sha1":
			digest := sha1.Sum([]byte(value))
			value = string(digest[:])
		case "length":
			value = strconv.Itoa(len(value))
		case "removenulls":
			value = strings.ReplaceAll(value, "\x00", "")
		case "htmlentitydecode":
			value = secHTMLDecode(value)
		case "replacecomments":
			value = secReplaceComments(value)
		case "removecommentschar":
			value = secRemoveCommentCharacters(value)
		case "normalizepath", "normalizepathwin":
			value = secNormalizePath(value, strings.EqualFold(t, "normalizePathWin"))
		case "base64decode":
			value = secBase64Decode(value)
		case "utf8tounicode":
			var err error
			value, err = secUTF8Unicode(value)
			if err != nil {
				return "", err
			}
		case "jsdecode", "escapeseqdecode":
			value = secBackslashDecode(value, strings.EqualFold(t, "jsDecode"))
		case "cssdecode":
			value = secCSSDecode(value)
		case "cmdline":
			value = secCommandLine(value)
		case "urldecode", "urldecodeuni":
			value = decodeSecURL(value, strings.EqualFold(t, "urldecodeuni"))
		default:
			return "", errors.New("unsupported transformation")
		}
	}
	return value, nil
}
func matchSecOperator(operator, operand, value string) (bool, error) {
	switch operator {
	case "detectsqli":
		ok, _, err := detectSecSQL(value)
		return ok, err
	case "detectxss":
		return detectSecXSS(value)
	case "pm":
		_, matched := matchSecPhrases(strings.Fields(operand), value)
		return matched, nil
	case "ipmatch":
		address, err := netip.ParseAddr(value)
		if err != nil {
			return false, nil
		}
		matches := false
		for _, item := range strings.Fields(strings.ReplaceAll(operand, ",", " ")) {
			prefix, e := netip.ParsePrefix(item)
			if e != nil {
				single, e := netip.ParseAddr(item)
				if e != nil {
					return false, errors.New("invalid configured IP range")
				}
				if single == address {
					matches = true
				}
			} else if prefix.Contains(address) {
				matches = true
			}
		}
		return matches, nil
	case "validateutf8encoding":
		return !utf8.ValidString(value), nil
	case "validateurlencoding":
		for i := 0; i < len(value); i++ {
			if value[i] != '%' {
				continue
			}
			if i+2 >= len(value) {
				return true, nil
			}
			if _, err := strconv.ParseUint(value[i+1:i+3], 16, 8); err != nil {
				return true, nil
			}
			i += 2
		}
		return false, nil
	case "validatebyterange":
		if strings.TrimSpace(operand) == "" {
			return false, nil
		}
		var allowed [256]bool
		for _, item := range strings.Fields(strings.ReplaceAll(operand, ",", " ")) {
			from, to, rangeFound := strings.Cut(item, "-")
			a, e := strconv.Atoi(from)
			if e != nil || a < 0 || a > 255 {
				return false, errors.New("invalid configured byte range")
			}
			b := a
			if rangeFound {
				b, e = strconv.Atoi(to)
				if e != nil || b < a || b > 255 {
					return false, errors.New("invalid configured byte range")
				}
			}
			for i := a; i <= b; i++ {
				allowed[i] = true
			}
		}
		for i := 0; i < len(value); i++ {
			if !allowed[value[i]] {
				return true, nil
			}
		}
		return false, nil
	case "rx":
		return matchSecRegex(operand, value)
	case "contains":
		return strings.Contains(value, operand), nil
	case "streq":
		return value == operand, nil
	case "beginswith":
		return strings.HasPrefix(value, operand), nil
	case "endswith":
		return strings.HasSuffix(value, operand), nil
	case "within":
		return strings.Contains(operand, value), nil
	case "unconditionalmatch":
		return true, nil
	case "eq", "ge", "gt", "lt", "le":
		a, err := secInteger(value)
		if err != nil {
			return false, errors.New("invalid numeric variable")
		}
		b, err := secInteger(operand)
		if err != nil {
			return false, errors.New("invalid numeric operand")
		}
		switch operator {
		case "eq":
			return a == b, nil
		case "ge":
			return a >= b, nil
		case "gt":
			return a > b, nil
		case "lt":
			return a < b, nil
		case "le":
			return a <= b, nil
		}
	}
	return false, errors.New("unsupported operator")
}
func secInteger(value string) (int64, error) {
	value = strings.TrimLeft(value, " \t\r\n\v\f")
	end := 0
	if len(value) > 0 && (value[0] == '+' || value[0] == '-') {
		end++
	}
	digits := end
	for end < len(value) && value[end] >= '0' && value[end] <= '9' {
		end++
	}
	if end == digits {
		return 0, nil
	}
	return strconv.ParseInt(value[:end], 10, 64)
}
func addSecInteger(a, b int) (int, error) {
	max := int(^uint(0) >> 1)
	min := -max - 1
	if b > 0 && a > max-b || b < 0 && a < min-b {
		return 0, errors.New("transaction integer overflow")
	}
	return a + b, nil
}
func secAnomalyScore(tx map[string]string) (int, error) {
	for _, name := range []string{"blocking_inbound_anomaly_score", "inbound_anomaly_score"} {
		if value, ok := tx[name]; ok {
			return strconv.Atoi(value)
		}
	}
	score := 0
	for level := 1; level <= 4; level++ {
		if value := tx["inbound_anomaly_score_pl"+strconv.Itoa(level)]; value != "" {
			n, err := strconv.Atoi(value)
			if err != nil {
				return 0, err
			}
			score, err = addSecInteger(score, n)
			if err != nil {
				return 0, err
			}
		}
	}
	return score, nil
}

type secBodyLoader func(string, bool) (map[string][]string, error)

type secLangPlan struct {
	rules         []secRule
	compatibility secCompatibility
	selections    map[string]*secSelection
}

func cloneSecLangRules(source []secRule) []secRule {
	rules := make([]secRule, len(source))
	for i, rule := range source {
		rules[i] = rule
		rules[i].Actions = make(map[string][]string, len(rule.Actions))
		for name, values := range rule.Actions {
			rules[i].Actions[name] = append([]string(nil), values...)
		}
		rules[i].ActionOrder = append([]secAction(nil), rule.ActionOrder...)
		rules[i].Phrases = append([]string(nil), rule.Phrases...)
		rules[i].Chain = cloneSecLangRules(rule.Chain)
	}
	return rules
}
func prepareSecLangPlan(source []secRule) (*secLangPlan, error) {
	rules := cloneSecLangRules(source)
	compiled, err := secCompileTargets(rules)
	if err != nil {
		return nil, err
	}
	report := secLangCompatibility(rules)
	if !report.Publishable {
		return nil, fmt.Errorf("unsupported rule semantics: %s", strings.Join(report.Unsupported, ", "))
	}
	selections := map[string]*secSelection{}
	var prepare func([]secRule) error
	prepare = func(rules []secRule) error {
		for _, rule := range rules {
			if rule.Directive == "SecRule" && selections[rule.Targets] == nil {
				selection, err := prepareSecSelection(rule.Targets)
				if err != nil {
					return err
				}
				selections[rule.Targets] = selection
			}
			if err := prepare(rule.Chain); err != nil {
				return err
			}
		}
		return nil
	}
	if err := prepare(compiled); err != nil {
		return nil, err
	}
	return &secLangPlan{rules: compiled, compatibility: report, selections: selections}, nil
}
func evaluateSecLang(rules []secRule, input map[string][]string, threshold int, bodyLoaders ...secBodyLoader) (secResult, error) {
	plan, err := prepareSecLangPlan(rules)
	if err != nil {
		return secResult{}, err
	}
	return evaluateSecLangPlan(plan, input, threshold, bodyLoaders...)
}

type secMatchObserver func(secRule, secVariable, string, string)

func evaluateSecLangPlan(plan *secLangPlan, input map[string][]string, threshold int, bodyLoaders ...secBodyLoader) (secResult, error) {
	return evaluateSecLangObserved(plan, input, threshold, nil, bodyLoaders...)
}
func evaluateSecLangObserved(plan *secLangPlan, input map[string][]string, threshold int, observe secMatchObserver, bodyLoaders ...secBodyLoader) (secResult, error) {
	rules := plan.rules
	result := secResult{Matches: []string{}, Variables: map[string]string{}}
	result.AuditEnabled = true
	for name := range input {
		collection, _, _ := strings.Cut(name, ":")
		if strings.EqualFold(collection, "TX") {
			return result, errors.New("request variables cannot override transaction state")
		}
	}
	if values := input["URLENCODED_ERROR"]; len(values) > 0 && values[0] == "1" {
		result.Incomplete = []string{"malformed-percent-encoding"}
	}
	result.Variables["inbound_anomaly_score_threshold"] = strconv.Itoa(threshold)
	result.Variables["enable_default_collections"] = "0"
	frame := secTransaction{input: input}
	for name, value := range result.Variables {
		frame.txBytes += len(name) + len(value)
	}
	activePhase := 0
	var activeRule, rootRule secRule
	var rootMatches []secVariable
	rootOmitted := 0
	expand := func(value string) (string, error) {
		return expandSecValue(value, result.Variables, func(name string) (string, error) { return frame.macro(name, activeRule) })
	}
	if threshold < 1 {
		return result, errors.New("positive threshold required")
	}
	applyNonDisruptive := func(r secRule) error {
		for _, action := range r.ActionOrder {
			if action.Name == "ctl" {
				control, err := parseSecControl(action.Value)
				if err != nil {
					return err
				}
				switch control.name {
				case "requestbodyprocessor":
					if activePhase != 1 || len(bodyLoaders) == 0 {
						return errors.New("body processor requires raw request header phase")
					}
					frame.processor = control.target
					continue
				case "forcerequestbodyvariable":
					if activePhase != 1 {
						return errors.New("raw body control requires header phase")
					}
					frame.forceBody = control.target == "On"
					continue
				case "auditengine":
					result.AuditEnabled = control.target != "Off"
					continue
				}
				if len(frame.controls) >= 1000 {
					return errors.New("runtime control budget exceeded")
				}
				frame.controls = append(frame.controls, control)
				continue
			}
			if action.Name != "setvar" {
				continue
			}
			name, value, _ := strings.Cut(action.Value, "=")
			name, err := expand(name)
			if err != nil {
				return err
			}
			name = strings.TrimPrefix(strings.ToLower(name), "tx.")

			relative := strings.HasPrefix(value, "+") || strings.HasPrefix(value, "-")
			expanded, err := expand(value)
			if err != nil {
				return err
			}
			value = expanded
			if relative {
				delta, e := strconv.Atoi(value)
				if e != nil {
					return e
				}
				current, e := strconv.Atoi(result.Variables[name])
				if result.Variables[name] != "" && e != nil {
					return e
				}
				added, e := addSecInteger(current, delta)
				if e != nil {
					return e
				}
				value = strconv.Itoa(added)
			}
			if err := frame.setTX(result.Variables, name, value); err != nil {
				return err
			}
		}
		return nil
	}
	var matches func(secRule) (bool, error)
	matches = func(r secRule) (bool, error) {
		activeRule = r
		matched := r.Directive == "SecAction"
		if r.Directive != "SecAction" {
			operand, err := expand(r.Operand)
			if err != nil {
				return false, err
			}
			targets, err := frame.targets(r, rootRule)
			if err != nil {
				return false, err
			}
			selection := plan.selections[targets]
			if selection == nil {
				selection, err = prepareSecSelection(targets)
				if err != nil {
					return false, err
				}
			}
			candidates, err := selection.variables(frame.variablesFor(selection.collections), result.Variables)
			if err != nil {
				return false, err
			}
			frame.matched = nil
			frame.matchedBytes = 0
			for _, candidate := range candidates {
				stages, stageErr := frame.transforms.stages(candidate.value, r.Actions["t"], len(r.Actions["multimatch"]) > 0)
				if stageErr != nil {
					return false, stageErr
				}
				for _, value := range stages {
					operand, err = expand(r.Operand)
					if err != nil {
						return false, err
					}
					var ok bool
					var captures map[string]string
					if r.Operator == "detectsqli" {
						var fingerprint string
						ok, fingerprint, err = detectSecSQL(value)
						if err != nil {
							return false, err
						}
						if ok {
							captures = map[string]string{"0": fingerprint}
						}
					} else if r.Operator == "detectxss" {
						ok, err = detectSecXSS(value)
						if err != nil {
							return false, err
						}
						if ok {
							captures = map[string]string{"0": value}
						}
					} else if r.Operator == "rx" && len(r.Actions["capture"]) > 0 {
						ok, captures, err = captureSecRegex(operand, value)
						if err != nil {
							return false, fmt.Errorf("%w [rule %s]", err, rootRule.ID)
						}
					} else if r.Operator == "pmfromfile" || r.Operator == "pm" {
						phrases := r.Phrases
						if r.Operator == "pm" {
							phrases = strings.Fields(operand)
						}
						if r.Operator == "pmfromfile" && !r.PhraseDataLoaded {
							return false, errors.New("phrase file dependency unavailable")
						}
						phrase, found := matchSecPhrases(phrases, value)
						ok = found
						if found {
							captures = map[string]string{"0": phrase}
						}
					} else {
						ok, err = matchSecOperator(r.Operator, operand, value)
						if err != nil {
							return false, fmt.Errorf("%w [rule %s]", err, rootRule.ID)
						}
					}
					if len(r.Actions["capture"]) > 0 && ok && captures != nil {
						for i := 0; i < 100; i++ {
							frame.deleteTX(result.Variables, strconv.Itoa(i))
						}
						for name, capture := range captures {
							if err := frame.setTX(result.Variables, name, capture); err != nil {
								return false, err
							}
						}
					}
					if r.Negated {
						ok = !ok
					}
					if ok {
						if err := frame.record(candidate.name, value); err != nil {
							return false, err
						}
						if r.ID != "" {
							if len(rootMatches) < 100 {
								rootMatches = append(rootMatches, secVariable{candidate.name, value})
							} else {
								rootOmitted++
							}
						}
						if err := applyNonDisruptive(r); err != nil {
							return false, err
						}
						matched = true
					}
				}
			}
		}
		if !matched {
			return false, nil
		}
		// Non-disruptive actions belong to each matched chain member. They can set
		// transaction state consumed by the next member even if a later member fails.
		if r.Directive == "SecAction" {
			if err := applyNonDisruptive(r); err != nil {
				return false, err
			}
		}
		for _, child := range r.Chain {
			ok, err := matches(child)
			if err != nil || !ok {
				return false, err
			}
		}
		return true, nil
	}
evaluation:
	for phase := 1; phase <= 2; phase++ {
		activePhase = phase
		if phase == 2 && len(bodyLoaders) > 0 {
			next, err := bodyLoaders[0](frame.processor, frame.forceBody)
			if err != nil {
				return result, err
			}
			frame.input = next
			frame.inputCollections = nil
			if values := next["REQBODY_ERROR"]; len(values) > 0 && values[0] == "1" {
				result.Incomplete = append(result.Incomplete, "request-body-processor-error")
				if messages := next["REQBODY_ERROR_MSG"]; len(messages) > 0 {
					result.ProcessorError = messages[0]
				}
			}
			if len(result.Incomplete) == 0 {
				if values := next["URLENCODED_ERROR"]; len(values) > 0 && values[0] == "1" {
					result.Incomplete = append(result.Incomplete, "malformed-percent-encoding")
				}
			}
		}
		skip := ""
		skipCount := 0
		for _, r := range rules {
			if skip != "" {
				if r.Directive == "SecMarker" && r.Operand == skip || r.ID == skip {
					skip = ""
				}
				continue
			}
			if r.Directive != "SecRule" && r.Directive != "SecAction" {
				continue
			}
			p := secFirst(r.Actions, "phase")
			if p == "" {
				p = "2"
			}
			if p != strconv.Itoa(phase) {
				continue
			}
			if skipCount > 0 {
				skipCount--
				continue
			}
			rootRule = r
			rootMatches = nil
			rootOmitted = 0
			disabled, err := frame.disabled(r)
			if err != nil {
				return result, err
			}
			if disabled {
				continue
			}
			matched, err := matches(r)
			if err != nil {
				return result, err
			}
			if !matched {
				continue
			}
			result.Matches = append(result.Matches, r.ID)
			result.OmittedEvidence += rootOmitted
			activeRule = r
			logData, err := expand(secFirst(r.Actions, "logdata"))
			if err != nil {
				return result, err
			}
			message := ""
			if observe != nil && len(r.Actions["nolog"]) == 0 {
				message, err = expand(secFirst(r.Actions, "msg"))
				if err != nil {
					return result, err
				}
			}
			for _, variable := range rootMatches {
				if observe != nil && len(r.Actions["nolog"]) == 0 {
					observe(r, variable, message, logData)
				}
				if len(result.Evidence) >= 100 {
					result.OmittedEvidence++
					continue
				}
				result.Evidence = append(result.Evidence, secEvidence(r, variable, logData))
			}
			disruptive := ""
			for _, action := range r.ActionOrder {
				if action.Name == "deny" || action.Name == "block" || action.Name == "pass" {
					disruptive = action.Name
				}
			}
			// In the inbound anomaly profile, block contributes evidence/score; the
			// explicit denial rule or final configured threshold makes the decision.
			if disruptive == "deny" {
				if status := secFirst(r.Actions, "status"); status != "" {
					result.Status, _ = strconv.Atoi(status)
				}
				result.Blocked = true
				break evaluation
			}
			if count := secFirst(r.Actions, "skip"); count != "" {
				skipCount, _ = strconv.Atoi(count)
			}
			if marker := secFirst(r.Actions, "skipafter"); marker != "" {
				skip = marker
			}
		}
		if skip != "" {
			return result, errors.New("skip marker missing in execution phase")
		}
	}
	score, err := secAnomalyScore(result.Variables)
	if err != nil {
		return result, err
	}
	result.Score = score
	if score >= threshold {
		result.Blocked = true
	}
	if result.Blocked && result.Status == 0 {
		result.Status = 403
	}
	return result, nil
}
