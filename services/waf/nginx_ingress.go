package main

import (
	"net/url"
	"regexp"
)

var nginxHostAuthority = regexp.MustCompile(`^[A-Za-z0-9.:[\]-]{1,300}$`)

func validNginxOriginalHost(value string) bool {
	if !nginxHostAuthority.MatchString(value) {
		return false
	}
	u, err := url.Parse("http://" + value)
	return err == nil && u.Hostname() != "" && u.User == nil && u.Path == "" && u.RawQuery == "" && u.Fragment == ""
}
