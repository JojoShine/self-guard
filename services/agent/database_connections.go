package main

import (
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var postgresAuthorized = regexp.MustCompile(`^connection authorized: user=([^\s=]{1,128}) database=([^\s=]{1,128})(?: application_name=.*| SSL enabled .*)?$`)
var postgresDisconnected = regexp.MustCompile(`^disconnection: session time: [0-9]+:[0-9]{2}:[0-9]{2}\.[0-9]{3} user=([^\s=]{1,128}) database=([^\s=]{1,128}) host=[^\s]+(?: port=[0-9]+)?$`)
var postgresDeniedUser = regexp.MustCompile(`^(?:(?i:password|peer|ident|pam|bsd|ldap|certificate|gssapi|sspi|radius) authentication failed for user "([^"\r\n]{1,128})"|role "([^"\r\n]{1,128})" (?:is not permitted to log in|does not exist))$`)
var postgresDeniedHost = regexp.MustCompile(`^(?:no pg_hba.conf entry|pg_hba.conf rejects connection) for host "[^"\r\n]{1,253}", user "([^"\r\n]{1,128})", database "([^"\r\n]{1,128})", [^"\r\n]+$`)
var postgresClock = regexp.MustCompile(`^[0-9]{10,11}\.[0-9]{3}$`)
var postgresSession = regexp.MustCompile(`^[0-9a-f]+\.[0-9a-f]+$`)

// Command tags distinguish startup authorization from a user's RAISE LOG text.
// A disconnect proves termination, not graceful completion or statement success.
func postgresConnection(value map[string]any, message, state, tag string) bool {
	if (state == "28P01" || state == "28000") && (tag == "" || tag == "authentication" || tag == "startup") {
		value["operation"], value["succeeded"] = "LOGIN", false
		return true
	}
	if tag == "authentication" && strings.HasPrefix(message, "connection authorized: ") {
		value["operation"], value["succeeded"] = "LOGIN", true
		return true
	}
	if databaseIncludes([]string{"idle", "idle in transaction", "idle in transaction (aborted)"}, tag) && strings.HasPrefix(message, "disconnection: session time: ") {
		value["operation"] = "LOGOUT"
		return true
	}
	return false
}

// The explicit prefix uses epoch milliseconds, avoiding ambiguous CST offsets.
// Message bodies never leave this parser. TLS and application names stay unknown:
// user-controlled application_name can imitate the optional SSL message suffix.
func postgresStderr(line string) (map[string]any, bool, bool) {
	parts := strings.SplitN(line, "|", 8)
	if len(parts) != 8 || parts[0] != "SGDB1" {
		ordinary := !strings.Contains(line, "connection authorized:") && !strings.Contains(line, "disconnection:") && !strings.Contains(line, "authentication failed")
		return nil, ordinary, ordinary
	}
	// Background and statement records have no session or remote endpoint.
	if parts[5] != "28P01" && parts[5] != "28000" && !strings.Contains(parts[7], "connection authorized:") && !strings.Contains(parts[7], "disconnection:") {
		return nil, true, true
	}
	if !postgresClock.MatchString(parts[1]) || !postgresSession.MatchString(parts[3]) || len(parts[3]) > 128 {
		return nil, false, false
	}
	pid, pidErr := strconv.ParseUint(parts[2], 10, 32)
	ms, clockErr := strconv.ParseInt(strings.ReplaceAll(parts[1], ".", ""), 10, 64)
	if pidErr != nil || pid == 0 || clockErr != nil {
		return nil, false, false
	}
	value := map[string]any{"timestamp": time.UnixMilli(ms).UTC().Format(time.RFC3339Nano), "service": "postgresql", "sessionId": parts[3]}
	remote := parts[4]
	if remote == "" {
		return nil, false, false
	}
	if remote != "[local]" {
		open := strings.LastIndexByte(remote, '(')
		if open < 1 || !strings.HasSuffix(remote, ")") {
			return nil, false, false
		}
		port, err := strconv.Atoi(remote[open+1 : len(remote)-1])
		if err != nil || port < 1 || port > 65535 {
			return nil, false, false
		}
		host := remote[:open]
		if ip := net.ParseIP(host); ip != nil {
			value["sourceIp"] = ip.String()
		} else if len(host) <= 253 && !strings.ContainsAny(host, " \t\r\n|") {
			value["sourceHost"] = host
		} else {
			return nil, false, false
		}
	} else if remote == "[local]" {
		value["sourceHost"] = "[local]"
	}
	level, message, ok := strings.Cut(parts[7], ":  ")
	if !ok {
		return nil, false, false
	}
	state, tag := parts[5], parts[6]
	if level == "LOG" && tag == "authentication" && strings.HasPrefix(message, "connection authorized:") {
		m := postgresAuthorized.FindStringSubmatch(message)
		if len(m) != 3 {
			return nil, false, false
		}
		value["user"], value["database"] = m[1], m[2]
	} else if level == "LOG" && strings.HasPrefix(message, "disconnection:") {
		// An active command can emit arbitrary LOG text. Without independent
		// termination evidence, report a gap rather than assert a session ended.
		if !databaseIncludes([]string{"idle", "idle in transaction", "idle in transaction (aborted)"}, tag) {
			return nil, false, false
		}
		m := postgresDisconnected.FindStringSubmatch(message)
		if len(m) != 3 {
			return nil, false, false
		}
		value["user"], value["database"] = m[1], m[2]
	} else if level == "FATAL" && (state == "28P01" || state == "28000") && (tag == "authentication" || tag == "startup") {
		m := postgresDeniedUser.FindStringSubmatch(message)
		if len(m) == 3 {
			value["user"] = m[1] + m[2]
		} else if m = postgresDeniedHost.FindStringSubmatch(message); len(m) == 3 {
			value["user"], value["database"] = m[1], m[2]
		} else {
			return nil, false, false
		}
	} else {
		return nil, true, true
	}
	if !postgresConnection(value, message, state, tag) {
		return nil, false, false
	}
	return value, true, false
}
