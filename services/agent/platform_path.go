package main

import (
	"net/url"
	"regexp"
	"strings"
)

var platformPathPattern = regexp.MustCompile(`^(?:/[A-Za-z0-9_-]+)*/?$`)

func validPlatformPath(u *url.URL) bool {
	return u != nil && u.RawPath == "" && u.RawQuery == "" && !u.ForceQuery && u.Fragment == "" && platformPathPattern.MatchString(u.Path) && !strings.HasSuffix(strings.TrimSuffix(u.Path, "/"), "/api")
}
