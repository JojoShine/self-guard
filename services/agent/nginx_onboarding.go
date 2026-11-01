package main

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strings"
)

type nginxDirective struct {
	name              string
	args              []string
	start, end, depth int
}

// A deliberately small lexer: parse comments and quoted values before assessing
// a supported single-server/single-location configuration. Never regex-rewrite blocks.
func nginxDirectives(b []byte) ([]nginxDirective, error) {
	var result []nginxDirective
	var words []string
	start, depth := 0, 0
	for i := 0; i < len(b); {
		c := b[i]
		if c == ' ' || c == '\t' || c == '\r' || c == '\n' {
			i++
			continue
		}
		if c == '#' {
			for i < len(b) && b[i] != '\n' {
				i++
			}
			continue
		}
		if c == ';' || c == '{' || c == '}' {
			if c == '}' {
				if len(words) > 0 || depth == 0 {
					return nil, errors.New("malformed nginx block")
				}
				depth--
				result = append(result, nginxDirective{name: "}", start: i, end: i + 1, depth: depth})
			} else {
				if len(words) == 0 {
					return nil, errors.New("missing nginx directive")
				}
				d := nginxDirective{name: words[0], args: append([]string{}, words[1:]...), start: start, end: i + 1, depth: depth}
				if c == '{' {
					d.name += "{"
					depth++
				}
				result = append(result, d)
				words = nil
			}
			i++
			continue
		}
		if len(words) == 0 {
			start = i
		}
		var word strings.Builder
		quote := byte(0)
		if c == '\'' || c == '"' {
			quote = c
			i++
		}
		closed := quote == 0
		for i < len(b) {
			c = b[i]
			if c == '\\' {
				return nil, errors.New("escaped nginx syntax requires manual review")
			}
			if quote != 0 {
				if c == quote {
					i++
					closed = true
					break
				}
			} else if strings.ContainsRune(" \t\r\n;{}#", rune(c)) {
				break
			}
			word.WriteByte(c)
			i++
		}
		if !closed {
			return nil, errors.New("unterminated nginx quote")
		}
		words = append(words, word.String())
	}
	if depth != 0 || len(words) > 0 {
		return nil, errors.New("incomplete nginx configuration")
	}
	return result, nil
}
func planNginxOnboarding(source []byte, hostname, upstream, local string) ([]byte, error) {
	if len(source) == 0 || len(source) > 256<<10 || !regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9.-]{0,252}$`).MatchString(hostname) {
		return nil, errors.New("bounded configuration and exact hostname required")
	}
	origin, err := url.Parse(upstream)
	if err != nil || origin.Scheme != "http" || origin.User != nil || origin.Hostname() == "" || origin.RawQuery != "" || origin.Fragment != "" || origin.Path != "" {
		return nil, errors.New("first supported mode requires an explicit HTTP origin without a path")
	}
	host, port, err := net.SplitHostPort(local)
	if err != nil || host != "127.0.0.1" || port == "" || local == origin.Host {
		return nil, errors.New("distinct loopback WAF listener required")
	}
	ds, err := nginxDirectives(source)
	if err != nil {
		return nil, err
	}
	servers, locations, names, proxies := 0, 0, 0, 0
	originalHost := origin.Host
	hostHeaders := 0
	proxyStart, proxyEnd, locationEnd := 0, 0, 0
	remove := map[int]int{}
	for _, d := range ds {
		switch {
		case d.name == "server{" && d.depth == 0 && len(d.args) == 0:
			servers++
		case d.name == "location{" && d.depth == 1 && len(d.args) == 1 && d.args[0] == "/":
			locations++
		case d.name == "}" && (d.depth == 0 || d.depth == 1):
			if d.depth == 1 {
				locationEnd = d.start
			}
		case d.depth == 1 && d.name == "server_name":
			if len(d.args) != 1 || !strings.EqualFold(d.args[0], hostname) {
				return nil, errors.New("server names do not exactly match selected site")
			}
			names++
		case d.depth == 1 && (d.name == "listen" || d.name == "ssl_certificate" || d.name == "ssl_certificate_key" || d.name == "ssl_protocols" || d.name == "ssl_ciphers" || d.name == "ssl_prefer_server_ciphers" || d.name == "ssl_session_cache" || d.name == "ssl_session_timeout" || d.name == "access_log" || d.name == "error_log" || d.name == "client_max_body_size"):
		case d.depth == 2 && d.name == "proxy_pass":
			if len(d.args) != 1 || d.args[0] != upstream {
				return nil, errors.New("configured upstream differs from the selected site")
			}
			proxies++
			proxyStart = d.start
			proxyEnd = d.end
		case d.depth == 2 && d.name == "proxy_set_header":
			if len(d.args) != 2 {
				return nil, errors.New("invalid proxy header")
			}

			if strings.EqualFold(d.args[0], "Host") {
				hostHeaders++
				if hostHeaders > 1 {
					return nil, errors.New("duplicate upstream Host directives require review")
				}
				originalHost = d.args[1]
				if originalHost == "$proxy_host" {
					originalHost = origin.Host
				}
				if originalHost != "$host" && originalHost != "$http_host" && !regexp.MustCompile(`^[A-Za-z0-9.:[\]-]{1,300}$`).MatchString(originalHost) {
					return nil, errors.New("unsupported dynamic upstream Host; configuration unchanged")
				}
			}
			switch strings.ToLower(d.args[0]) {
			case "host", "x-real-ip", "x-forwarded-for", "x-forwarded-proto", "x-selfguard-original-host":
				remove[d.start] = d.end
			}
		case d.depth == 2 && (d.name == "proxy_http_version" || d.name == "proxy_connect_timeout" || d.name == "proxy_read_timeout" || d.name == "proxy_send_timeout" || d.name == "client_max_body_size"):
		default:
			return nil, fmt.Errorf("unsupported nginx directive or block: %s; configuration left unchanged", d.name)
		}
	}
	if servers != 1 || locations != 1 || names != 1 || proxies != 1 || locationEnd == 0 {
		return nil, errors.New("exactly one server, exact hostname and one root reverse proxy are required")
	}
	var out strings.Builder
	for i := 0; i < len(source); {
		if i == proxyStart {
			out.WriteString("proxy_pass http://" + local + ";")
			i = proxyEnd
			continue
		}
		if end, ok := remove[i]; ok {
			i = end
			continue
		}
		if i == locationEnd {
			out.WriteString("\n    proxy_set_header X-Selfguard-Original-Host " + originalHost + ";\n")
			out.WriteString("\n    proxy_set_header Host " + hostname + ";\n    proxy_set_header X-Real-IP $remote_addr;\n    proxy_set_header X-Forwarded-For $remote_addr;\n    proxy_set_header X-Forwarded-Proto $scheme;\n  ")
		}
		out.WriteByte(source[i])
		i++
	}
	return []byte(out.String()), nil
}
