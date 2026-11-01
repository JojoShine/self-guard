package scanner

import (
	"errors"
	"strings"
	"time"
)

// NetworkSample is supplied offline by a template author. It is never accepted
// as live scan evidence or used to establish that an actual target is vulnerable.
type NetworkSample struct {
	Connected  bool      `json:"connected"`
	Banner     string    `json:"banner,omitempty"`
	TLSVersion string    `json:"tlsVersion,omitempty"`
	ObservedAt time.Time `json:"observedAt,omitempty"`
	NotBefore  time.Time `json:"notBefore,omitempty"`
	NotAfter   time.Time `json:"notAfter,omitempty"`
}
type NetworkEvaluation struct {
	Matched     bool `json:"matched"`
	Observation bool `json:"observation"`
}

func CheckNetworkRule(rule NetworkRule, sample NetworkSample) (NetworkEvaluation, error) {
	protocol := "tls"
	if strings.HasPrefix(rule.Kind, "TCP_") {
		protocol = "tcp"
	}
	result := NetworkEvaluation{Observation: rule.Kind == "TCP_CONNECT" || rule.Kind == "TLS_HANDSHAKE"}
	if !validateNetworkRule(rule, protocol) || len(sample.Banner) > 4096 {
		return result, errors.New("invalid network rule or sample budget")
	}
	dates := !sample.ObservedAt.IsZero() || !sample.NotBefore.IsZero() || !sample.NotAfter.IsZero()
	if !sample.Connected {
		if sample.Banner != "" || sample.TLSVersion != "" || dates {
			return result, errors.New("disconnected sample cannot contain service observations")
		}
		return result, nil
	}
	if protocol == "tcp" {
		if sample.TLSVersion != "" || dates || rule.Kind == "TCP_CONNECT" && sample.Banner != "" {
			return result, errors.New("TCP sample contains unrelated observation fields")
		}
		if rule.Kind == "TCP_CONNECT" {
			result.Matched = true
			return result, nil
		}
		if sample.Banner == "" {
			return result, errors.New("banner sample is incomplete")
		}
		result.Matched = strings.Contains(sample.Banner, rule.Value)
		return result, nil
	}
	if sample.Banner != "" {
		return result, errors.New("TLS sample cannot contain an application banner")
	}
	switch sample.TLSVersion {
	case "TLS1.0", "TLS1.1", "TLS1.2", "TLS1.3":
	default:
		return result, errors.New("explicit TLS sample version required")
	}
	switch rule.Kind {
	case "TLS_HANDSHAKE":
		result.Matched = true
	case "TLS_WEAK_PROTOCOL":
		result.Matched = sample.TLSVersion == rule.Value
	case "TLS_CERT_EXPIRED", "TLS_CERT_EXPIRING":
		if sample.ObservedAt.IsZero() || sample.NotBefore.IsZero() || sample.NotAfter.IsZero() || !sample.NotAfter.After(sample.NotBefore) {
			return result, errors.New("complete ordered certificate dates and observation time required")
		}
		limit := sample.ObservedAt
		if rule.Kind == "TLS_CERT_EXPIRING" {
			limit = limit.Add(time.Duration(rule.Days) * 24 * time.Hour)
		}
		result.Matched = !sample.NotBefore.After(sample.ObservedAt) && !sample.NotAfter.After(limit)
	}
	return result, nil
}
