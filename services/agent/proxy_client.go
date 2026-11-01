package main

import (
	"errors"
	"net/http"
)

// Unspecified mode retains compatibility with manually configured older agents.
// Managed installation profiles persist a concrete mode instead.
func clientForConfig(c Config) (*http.Client, error) {
	switch c.ProxyMode {
	case "DIRECT":
		if c.ProxyURL != "" {
			return nil, errors.New("direct mode cannot specify a proxy URL")
		}
		return installationClient(c.CACertificate, "")
	case "EXPLICIT":
		if c.ProxyURL == "" {
			return nil, errors.New("explicit proxy URL required")
		}
		return installationClient(c.CACertificate, c.ProxyURL)
	case "", "ENVIRONMENT":
		if c.ProxyURL != "" {
			if c.ProxyMode == "ENVIRONMENT" {
				return nil, errors.New("environment mode cannot specify a proxy URL")
			}
			return installationClient(c.CACertificate, c.ProxyURL)
		}
		return installationClient(c.CACertificate)
	default:
		return nil, errors.New("unknown proxy mode")
	}
}
