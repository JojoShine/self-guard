package main

import (
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

// Validate the authority and request target before site lookup or forwarding.
// net/http accepts literal fragments in RequestURI; an HTTP request target must
// encode '#' as %23 instead. HTTP/0.x is rejected by the server itself (505).
func validInboundProtocol(r *http.Request) bool {
	if r.Host == "" || strings.Contains(r.RequestURI, "#") {
		return false
	}
	authority, err := url.Parse("http://" + r.Host)
	if err != nil || authority.Hostname() == "" || authority.User != nil || authority.Path != "" || authority.RawQuery != "" || authority.Fragment != "" {
		return false
	}
	if r.Method == http.MethodConnect {
		host, port, err := net.SplitHostPort(r.RequestURI)
		value, numberError := strconv.Atoi(port)
		if err != nil || host == "" || numberError != nil || value < 1 || value > 65535 {
			return false
		}
	}
	return true
}
