// Package scanner implements bounded, read-only checks against an approved target snapshot.
package scanner

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

type Target struct {
	Hostname      string   `json:"hostname"`
	Port          int      `json:"port"`
	Protocol      string   `json:"protocol"`
	Addresses     []string `json:"addresses"`
	AllowedPaths  []string `json:"allowedPaths,omitempty"`
	ExcludedPaths []string `json:"excludedPaths,omitempty"`
}
type resolver interface {
	LookupNetIP(context.Context, string, string) ([]netip.Addr, error)
}
type Policy struct {
	hostname, protocol string
	port               int
	addresses          map[netip.Addr]bool
	allowed, excluded  []string
	blocked            []netip.Prefix
	resolver           resolver
	dialer             contextDialer
}

var reserved = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"), netip.MustParsePrefix("127.0.0.0/8"), netip.MustParsePrefix("169.254.0.0/16"), netip.MustParsePrefix("224.0.0.0/4"), netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("100.100.100.200/32"), netip.MustParsePrefix("168.63.129.16/32"), netip.MustParsePrefix("fd00:ec2::254/128"),
	netip.MustParsePrefix("::/96"), netip.MustParsePrefix("64:ff9b::/96"), netip.MustParsePrefix("64:ff9b:1::/48"), netip.MustParsePrefix("2002::/16"), netip.MustParsePrefix("2001::/32"),
}

func canonicalHost(host string) (string, error) {
	if strings.TrimSpace(host) != host || len(host) > 253 || host == "" {
		return "", errors.New("invalid target hostname")
	}
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	if ip, err := netip.ParseAddr(host); err == nil {
		if ip.Zone() != "" {
			return "", errors.New("scoped address is not permitted")
		}
		return ip.Unmap().String(), nil
	}
	for _, label := range strings.Split(host, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", errors.New("invalid DNS label")
		}
		for _, ch := range label {
			if !(ch >= 'a' && ch <= 'z' || ch >= '0' && ch <= '9' || ch == '-') {
				return "", errors.New("target requires a DNS hostname or literal IP")
			}
		}
	}
	return host, nil
}
func canonicalPath(raw string) (string, error) {
	if raw == "" {
		raw = "/"
	}
	if len(raw) > 2048 || !strings.HasPrefix(raw, "/") {
		return "", errors.New("invalid approved path")
	}
	for level := 0; level < 3; level++ {
		lower := strings.ToLower(raw)
		if strings.Contains(lower, "%2f") || strings.Contains(lower, "%5c") {
			return "", errors.New("encoded path separator is ambiguous")
		}
		decoded, err := url.PathUnescape(raw)
		if err != nil {
			return "", errors.New("invalid path encoding")
		}
		if decoded == raw {
			break
		}
		raw = decoded
	}
	if strings.ContainsAny(raw, "\\%?#") || strings.Contains(raw, "//") {
		return "", errors.New("ambiguous path")
	}
	for _, ch := range raw {
		if ch < 32 || ch == 127 {
			return "", errors.New("control character in path")
		}
	}
	for _, segment := range strings.Split(raw, "/") {
		if segment == "." || segment == ".." {
			return "", errors.New("path traversal is not permitted")
		}
	}
	if len(raw) > 1 {
		raw = strings.TrimSuffix(raw, "/")
	}
	return raw, nil
}
func (p *Policy) permittedIP(ip netip.Addr) bool {
	if ip.Zone() != "" {
		return false
	}
	ip = ip.Unmap()
	if !ip.IsValid() || ip.Zone() != "" || !ip.IsGlobalUnicast() || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
		return false
	}
	for _, prefix := range p.blocked {
		if prefix.Contains(ip) {
			return false
		}
	}
	return true
}

// NewPolicy accepts private addresses only when they are explicitly frozen in the
// target. Control-plane deny ranges supplement non-overridable metadata exclusions.
func NewPolicy(target Target, blockedRanges []string) (*Policy, error) {
	host, err := canonicalHost(target.Hostname)
	if err != nil {
		return nil, err
	}
	if target.Port < 1 || target.Port > 65535 {
		return nil, errors.New("invalid target port")
	}
	if target.Protocol != "http" && target.Protocol != "https" && target.Protocol != "tcp" && target.Protocol != "tls" {
		return nil, errors.New("unsupported target protocol")
	}
	if len(target.Addresses) == 0 || len(target.Addresses) > 32 || len(blockedRanges) > 1000 {
		return nil, errors.New("target address budget exceeded")
	}
	p := &Policy{hostname: host, protocol: target.Protocol, port: target.Port, addresses: map[netip.Addr]bool{}, blocked: append([]netip.Prefix{}, reserved...), resolver: net.DefaultResolver}
	for _, raw := range blockedRanges {
		prefix, err := netip.ParsePrefix(raw)
		if err != nil || prefix.Addr().Is4In6() {
			return nil, errors.New("invalid control-plane deny range")
		}
		p.blocked = append(p.blocked, prefix)
	}
	for _, raw := range target.Addresses {
		ip, err := netip.ParseAddr(raw)
		if err != nil || !p.permittedIP(ip) {
			return nil, errors.New("target address is reserved or denied")
		}
		p.addresses[ip.Unmap()] = true
	}
	if literal, err := netip.ParseAddr(host); err == nil && (len(p.addresses) != 1 || !p.addresses[literal]) {
		return nil, errors.New("literal host and approved address disagree")
	}
	if target.Protocol == "http" || target.Protocol == "https" {
		if len(target.AllowedPaths) == 0 || len(target.AllowedPaths) > 100 || len(target.ExcludedPaths) > 100 {
			return nil, errors.New("explicit HTTP path scope required")
		}
		for index, paths := range [][]string{target.AllowedPaths, target.ExcludedPaths} {
			for _, raw := range paths {
				path, err := canonicalPath(raw)
				if err != nil {
					return nil, err
				}
				if index == 0 {
					p.allowed = append(p.allowed, path)
				} else {
					p.excluded = append(p.excluded, path)
				}
			}
		}
	} else if len(target.AllowedPaths) != 0 || len(target.ExcludedPaths) != 0 {
		return nil, errors.New("TCP and TLS scopes cannot include HTTP paths")
	}
	return p, nil
}
func pathWithin(path, prefix string) bool {
	return prefix == "/" || path == prefix || strings.HasPrefix(path, prefix+"/")
}
func (p *Policy) CheckURL(u *url.URL) error {
	if u == nil || u.Opaque != "" || u.User != nil || u.Fragment != "" || u.Scheme != p.protocol || len(u.RawQuery) > 4096 {
		return errors.New("request URL exceeds approved origin")
	}
	host, err := canonicalHost(u.Hostname())
	if err != nil || host != p.hostname {
		return errors.New("request hostname exceeds approved target")
	}
	port := 80
	if u.Scheme == "https" {
		port = 443
	}
	if u.Port() != "" {
		port, err = strconv.Atoi(u.Port())
		if err != nil {
			return errors.New("invalid request port")
		}
	}
	if port != p.port {
		return errors.New("request port exceeds approved target")
	}
	path, err := canonicalPath(u.EscapedPath())
	if err != nil {
		return err
	}
	for _, prefix := range p.excluded {
		if pathWithin(path, prefix) {
			return errors.New("request path is excluded")
		}
	}
	for _, prefix := range p.allowed {
		if pathWithin(path, prefix) {
			return nil
		}
	}
	return errors.New("request path exceeds approved scope")
}

// Resolve is called immediately before a connection. Every answer, including a
// mixed safe/unsafe DNS response, must belong to the approved immutable address set.
func (p *Policy) Resolve(ctx context.Context) ([]netip.Addr, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if ip, err := netip.ParseAddr(p.hostname); err == nil {
		return []netip.Addr{ip}, nil
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	answers, err := p.resolver.LookupNetIP(ctx, "ip", p.hostname)
	if err != nil || len(answers) == 0 || len(answers) > 32 {
		return nil, errors.New("target DNS resolution incomplete")
	}
	ips := []netip.Addr{}
	seen := map[netip.Addr]bool{}
	for _, ip := range answers {
		if !p.permittedIP(ip) || !p.addresses[ip.Unmap()] {
			return nil, errors.New("target DNS changed outside approved addresses")
		}
		ip = ip.Unmap()
		if !seen[ip] {
			seen[ip] = true
			ips = append(ips, ip)
		}
	}
	return ips, nil
}

// Validate resolves and returns canonical copied fields, without opening a service
// connection. The caller can review and approve these exact addresses and paths.
func (p *Policy) Validate(ctx context.Context) (Target, error) {
	ips, err := p.Resolve(ctx)
	if err != nil {
		return Target{}, err
	}
	addresses := make([]string, len(ips))
	for index, ip := range ips {
		addresses[index] = ip.String()
	}
	sort.Strings(addresses)
	return Target{Hostname: p.hostname, Port: p.port, Protocol: p.protocol, Addresses: addresses, AllowedPaths: append([]string(nil), p.allowed...), ExcludedPaths: append([]string(nil), p.excluded...)}, nil
}
