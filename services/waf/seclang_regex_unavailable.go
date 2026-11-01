//go:build !pcre2 || !cgo

package main

import "errors"

func secRegexAvailable() bool { return false }
func matchSecRegex(pattern, subject string) (bool, error) {
	return false, errors.New("PCRE2 backend unavailable; CRS regex cannot be approximated by another engine")
}
func captureSecRegex(pattern, subject string) (bool, map[string]string, error) {
	ok, err := matchSecRegex(pattern, subject)
	return ok, nil, err
}
