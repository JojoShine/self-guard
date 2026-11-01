package main

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

func databaseLogRule(c PolicyConfig) bool {
	return c.Type == "DATABASE_AUTH" || c.Type == "DATABASE_CLEARTEXT"
}

// Only explicitly reported connection encryption is evidence of plaintext traffic.
type databaseObservation struct {
	At         time.Time `json:"timestamp"`
	SourceIP   string    `json:"sourceIp"`
	SourcePort int       `json:"sourcePort,omitempty"`
	User       string    `json:"user,omitempty"`
	Database   string    `json:"database,omitempty"`
	Service    string    `json:"service"`
	Outcome    string    `json:"outcome"`
	TLS        *bool     `json:"tls,omitempty"`
	SHA256     string    `json:"sha256"`
}

var mysqlDenied = regexp.MustCompile(`Access denied for user '([^'\r\n]{1,128})'@'([^'\r\n]{1,253})'`)

func databaseTime(s string) time.Time {
	for _, layout := range []string{time.RFC3339Nano, "2006-01-02 15:04:05.999999 MST", "2006-01-02 15:04:05 MST", "2006-01-02 15:04:05.999999-07:00"} {
		if at, err := time.Parse(layout, s); err == nil {
			return at
		}
	}
	return time.Time{}
}
func databaseLog(line, format string) (databaseObservation, bool) {
	o := databaseObservation{}
	if len(line) > 64<<10 {
		return o, false
	}
	switch format {
	case "mysql":
		fields := strings.Fields(line)
		m := mysqlDenied.FindStringSubmatch(line)
		if len(fields) == 0 || len(m) != 3 {
			return o, false
		}
		o.At = databaseTime(fields[0])
		o.User = m[1]
		o.SourceIP = m[2]
		o.Service = "mysql"
		o.Outcome = "AUTH_FAILURE"
	case "postgresql":
		var row struct {
			Timestamp string          `json:"timestamp"`
			User      string          `json:"user"`
			Database  string          `json:"dbname"`
			Host      string          `json:"remote_host"`
			Port      json.RawMessage `json:"remote_port"`
			State     string          `json:"state_code"`
		}
		if json.Unmarshal([]byte(line), &row) != nil || (row.State != "28P01" && row.State != "28000") {
			return o, false
		}
		o.At = databaseTime(row.Timestamp)
		o.User = row.User
		o.Database = row.Database
		o.SourceIP = row.Host
		o.SourcePort, _ = strconv.Atoi(strings.Trim(string(row.Port), "\""))
		o.Service = "postgresql"
		o.Outcome = "AUTH_FAILURE"
	case "audit-json":
		if json.Unmarshal([]byte(line), &o) != nil {
			return o, false
		}
		if o.Outcome != "AUTH_FAILURE" && o.Outcome != "CONNECTED" {
			return o, false
		}
		if !map[string]bool{"mysql": true, "postgresql": true, "mongodb": true, "redis": true, "sqlserver": true}[o.Service] {
			return o, false
		}
	default:
		return o, false
	}
	ip := net.ParseIP(o.SourceIP)
	if ip == nil || o.At.IsZero() || len(o.User) > 128 || len(o.Database) > 128 || o.SourcePort < 0 || o.SourcePort > 65535 {
		return o, false
	}
	o.SourceIP = ip.String()
	// Never retain arbitrary message, SQL, credentials or untrusted extra JSON keys.
	o.SHA256 = fmt.Sprintf("%x", sha256.Sum256([]byte(line)))
	return o, true
}

// State is bounded per file/rule and committed with the collector cursor.
func databaseWindows(previous map[string]logWindow, rule PolicyRule, path string, lines []string, now time.Time) (map[string]logWindow, []map[string]any) {
	next := map[string]logWindow{}
	out := []map[string]any{}
	seconds := rule.Config.WindowSeconds
	if seconds < 1 {
		seconds = 60
	}
	threshold := rule.Config.Threshold
	if threshold < 1 {
		threshold = 5
	}
	if rule.Config.Type == "DATABASE_CLEARTEXT" {
		threshold = 1
	}
	cutoff := now.Add(-time.Duration(seconds) * time.Second)
	prefix := rule.ID + ":database:"
	for key, w := range previous {
		if !strings.HasPrefix(key, prefix) {
			continue
		}
		samples := []databaseObservation{}
		for _, s := range w.Database {
			if s.At.After(cutoff) && !s.At.After(now) {
				samples = append(samples, s)
			}
		}
		if len(samples) > 0 {
			w.Database = samples
			next[key] = w
		}
	}
	incomplete := false
	for _, line := range lines {
		if rule.Config.Service == "mysql" && !strings.Contains(line, "Access denied for user") {
			continue
		}
		if rule.Config.Service == "postgresql" {
			var header struct {
				State     string `json:"state_code"`
				Severity  string `json:"error_severity"`
				Timestamp string `json:"timestamp"`
			}
			if json.Unmarshal([]byte(line), &header) == nil {
				ordinary := map[string]bool{"LOG": true, "INFO": true, "NOTICE": true, "DEBUG1": true, "DEBUG2": true, "DEBUG3": true, "DEBUG4": true, "DEBUG5": true}
				if (len(header.State) == 5 && header.State != "28P01" && header.State != "28000") || (header.State == "" && ordinary[header.Severity] && !databaseTime(header.Timestamp).IsZero()) {
					continue
				}
			}
		}
		o, ok := databaseLog(line, rule.Config.Service)
		if !ok {
			incomplete = true
			continue
		}
		if o.At.After(now.Add(5 * time.Minute)) {
			incomplete = true
			continue
		}
		if !o.At.After(cutoff) || o.At.After(now) {
			continue
		}
		if rule.Config.Type == "DATABASE_AUTH" && o.Outcome != "AUTH_FAILURE" {
			continue
		}
		if rule.Config.Type == "DATABASE_CLEARTEXT" && (o.Outcome != "CONNECTED" || o.TLS == nil || *o.TLS) {
			continue
		}
		key := prefix + fmt.Sprintf("%x", sha256.Sum256([]byte(o.Service+"\x00"+o.SourceIP)))
		w := next[key]
		if _, ok := next[key]; !ok && len(next) >= 128 {
			incomplete = true
			continue
		}
		duplicate := false
		for _, s := range w.Database {
			if s.SHA256 == o.SHA256 {
				duplicate = true
				break
			}
		}
		if duplicate {
			continue
		}
		total := 0
		for _, existing := range next {
			total += len(existing.Database)
		}
		if total >= 1024 {
			incomplete = true
			continue
		}
		w.Database = append(w.Database, o)
		sort.Slice(w.Database, func(i, j int) bool { return w.Database[i].At.Before(w.Database[j].At) })
		if len(w.Database) > threshold {
			w.Database = w.Database[len(w.Database)-threshold:]
		}
		next[key] = w
	}
	keys := []string{}
	for key := range next {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		w := next[key]
		if len(w.Database) < threshold || (w.LastAlert != 0 && now.UnixNano()-w.LastAlert < int64(seconds)*int64(time.Second)) {
			continue
		}
		last := w.Database[len(w.Database)-1]
		first := w.Database[0]
		title := "数据库疑似口令爆破"
		kind := "DATABASE_AUTH"
		if rule.Config.Type == "DATABASE_CLEARTEXT" {
			title = "数据库未加密连接"
			kind = "DATABASE_CLEARTEXT"
		}
		samples := w.Database
		if len(samples) > 20 {
			samples = samples[len(samples)-20:]
		}
		evidence := map[string]any{"ruleId": rule.ID, "ruleName": rule.Name, "type": kind, "path": path, "sourceIp": last.SourceIP, "service": last.Service, "count": len(w.Database), "windowSeconds": seconds, "from": first.At, "to": last.At, "observations": samples, "omittedObservations": len(w.Database) - len(samples), "action": "DETECT_ONLY", "outcome": "NOT_BLOCKED", "scope": "OBSERVED_CONNECTION_LOGS", "reason": "依据连接审计；未自动封禁、断开连接或修改数据库"}
		f := event(fmt.Sprintf("database:%s:%s:%s", rule.ID, key, last.SHA256), title, "agent-log", evidence)
		f["severity"] = "HIGH"
		if rule.Name != "" {
			f["title"] = rule.Name
		}
		if rule.Severity != "" {
			f["severity"] = rule.Severity
		}
		out = append(out, f)
		w.LastAlert = now.UnixNano()
		next[key] = w
	}
	if incomplete {
		f := databaseCoverage(rule, path, "核对格式、原始时间、来源IP及128组/1024观测上限；未识别记录不参与攻击判定")
		out = append(out, f)
	}
	return next, out
}

// Configuration observations are potential exposure, never proof of a live plaintext session.
func databaseBaseline(c Check, body, mode string) (string, string, string) {
	switch c.Key {
	case "CREDENTIAL_FILE_MODE":
		actual, err := strconv.ParseUint(mode, 8, 32)
		if err != nil {
			return "", "0600", "unreadable"
		}
		if actual & ^uint64(0600) == 0 {
			return "private", "private", "checked"
		}
		return mode, "private", "checked"
	case "MYSQL_TLS_REQUIRED", "POSTGRES_TLS_ENABLED":
		key := "require_secure_transport"
		sectionOK := false
		if c.Key == "POSTGRES_TLS_ENABLED" {
			key = "ssl"
			sectionOK = true
		}
		count := 0
		value := ""
		unsupported := false
		for _, line := range strings.Split(body, "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
				continue
			}
			if strings.HasPrefix(line, "!") || strings.HasPrefix(line, "include") {
				unsupported = true
				continue
			}
			if strings.HasPrefix(line, "[") {
				sectionOK = line == "[mysqld]" || line == "[server]"
				continue
			}
			if !sectionOK {
				continue
			}
			k, v, ok := strings.Cut(line, "=")
			if !ok || strings.TrimSpace(k) != key {
				continue
			}
			// These boolean settings cannot contain quoted comment markers.
			v = strings.TrimSpace(strings.Split(strings.Split(v, "#")[0], ";")[0])
			v = strings.Trim(v, "'\"")
			value = strings.ToLower(v)
			count++
		}
		if unsupported || count != 1 {
			return "", "enabled", "missing, duplicate or included configuration"
		}
		switch value {
		case "on", "true", "yes", "1":
			return "enabled", "enabled", "checked"
		case "off", "false", "no", "0":
			return "disabled", "enabled", "checked"
		}
		return "", "enabled", "unknown boolean"
	case "POSTGRES_HBA_TLS", "POSTGRES_HBA_AUTH":
		risk := []string{}
		unknown := false
		for n, line := range strings.Split(body, "\n") {
			fields, ok := hbaFields(line)
			if !ok {
				unknown = true
				continue
			}
			if len(fields) == 0 {
				continue
			}
			if strings.HasPrefix(fields[0], "include") {
				unknown = true
				continue
			}
			if fields[0] == "local" {
				continue
			}
			if !map[string]bool{"host": true, "hostssl": true, "hostnossl": true, "hostgssenc": true, "hostnogssenc": true}[fields[0]] || len(fields) < 5 {
				unknown = true
				continue
			}
			method := 4
			if net.ParseIP(fields[3]) != nil && len(fields) > 5 && net.ParseIP(fields[4]) != nil {
				method = 5
			}
			auth := fields[method]
			if auth == "reject" {
				continue
			}
			if (c.Key == "POSTGRES_HBA_AUTH" && auth == "trust") || (c.Key == "POSTGRES_HBA_TLS" && fields[0] != "hostssl" && fields[0] != "hostgssenc") {
				risk = append(risk, fmt.Sprintf("line %d: %s %s", n+1, fields[0], auth))
			}
		}
		if len(risk) > 0 {
			return strings.Join(risk, "; "), "no permissive configuration", "checked"
		}
		if unknown {
			return "", "no permissive configuration", "unsupported or included HBA records"
		}
		return "no permissive configuration", "no permissive configuration", "checked"
	}
	return "", "", "unsupported database check"
}
func hbaFields(line string) ([]string, bool) {
	fields := []string{}
	var word strings.Builder
	quoted := false
	for i := 0; i < len(line); i++ {
		b := line[i]
		if b == '\\' {
			return nil, false
		}
		if b == '"' {
			quoted = !quoted
			continue
		}
		if b == '#' && !quoted {
			break
		}
		if (b == ' ' || b == '\t') && !quoted {
			if word.Len() > 0 {
				fields = append(fields, word.String())
				word.Reset()
			}
		} else {
			word.WriteByte(b)
		}
	}
	if quoted {
		return nil, false
	}
	if word.Len() > 0 {
		fields = append(fields, word.String())
	}
	return fields, true
}

func databaseCoverage(rule PolicyRule, path, reason string) map[string]any {
	f := event(fmt.Sprintf("database-coverage:%s:%x", rule.ID, sha256.Sum256([]byte(path))), "数据库检测覆盖不完整", "agent-log", map[string]any{"ruleId": rule.ID, "path": path, "type": "DATABASE_COVERAGE", "status": "UNKNOWN", "complete": false, "reason": reason, "action": "DETECT_ONLY"})
	f["severity"] = "INFO"
	return f
}
