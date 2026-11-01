package scanner

import (
	"context"
	"net/netip"
	"net/url"
	"testing"
)

type fixedResolver struct{ ips []netip.Addr }

func (r fixedResolver) LookupNetIP(context.Context, string, string) ([]netip.Addr, error) {
	return r.ips, nil
}
func targetFixture() Target {
	return Target{Hostname: "app.example.test", Port: 443, Protocol: "https", Addresses: []string{"10.20.0.8"}, AllowedPaths: []string{"/health", "/public"}, ExcludedPaths: []string{"/public/admin"}}
}
func TestScopeRejectsAddressEscape(t *testing.T) {
	for _, address := range []string{"127.0.0.1", "::1", "::ffff:127.0.0.1", "169.254.169.254", "100.100.100.200", "168.63.129.16", "fd00:ec2::254", "::127.0.0.1", "::ffff:10.20.0.8%eth0", "64:ff9b::a9fe:a9fe", "2002:7f00:1::1", "2001::1", "fe80::1", "0.0.0.0", "224.0.0.1", "ff02::1", "10.20.0.9"} {
		t.Run(address, func(t *testing.T) {
			target := targetFixture()
			target.Addresses = []string{address}
			_, err := NewPolicy(target, []string{"10.20.0.9/32"})
			if err == nil {
				t.Fatal("reserved or control-plane target accepted")
			}
		})
	}
}
func TestScopePinsDNSBeforeEveryDial(t *testing.T) {
	policy, err := NewPolicy(targetFixture(), nil)
	if err != nil {
		t.Fatal(err)
	}
	policy.resolver = fixedResolver{[]netip.Addr{netip.MustParseAddr("10.20.0.8")}}
	ips, err := policy.Resolve(context.Background())
	if err != nil || len(ips) != 1 {
		t.Fatal(ips, err)
	}
	for _, addresses := range [][]netip.Addr{{netip.MustParseAddr("10.20.0.9")}, {netip.MustParseAddr("10.20.0.8"), netip.MustParseAddr("127.0.0.1")}, {}} {
		policy.resolver = fixedResolver{addresses}
		if _, err = policy.Resolve(context.Background()); err == nil {
			t.Fatal("DNS scope change accepted", addresses)
		}
	}
}
func TestScopeChecksRedirectOriginAndDecodedPath(t *testing.T) {
	policy, err := NewPolicy(targetFixture(), nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"https://app.example.test/health", "https://app.example.test:443/public/info?a=b", "https://app.example.test/public/"} {
		u, _ := url.Parse(path)
		if err = policy.CheckURL(u); err != nil {
			t.Fatal(path, err)
		}
	}
	for _, path := range []string{"http://app.example.test/health", "https://other.example.test/health", "https://app.example.test:8443/health", "https://user@ app.example.test/health", "https://app.example.test/public/admin", "https://app.example.test/public/admin/x", "https://app.example.test/publicity", "https://app.example.test/public/../private", "https://app.example.test/public/%2e%2e/private", "https://app.example.test/public/%252e%252e/private", "https://app.example.test/public%2fadmin", "https://app.example.test/public//admin", "https://app.example.test/public/%255cadmin", "https://app.example.test/public/#fragment"} {
		u, err := url.Parse(path)
		if err == nil && policy.CheckURL(u) == nil {
			t.Fatal("scope escape accepted", path)
		}
	}
}
func TestLiteralHostCannotAuthorizeAnotherAddress(t *testing.T) {
	target := targetFixture()
	target.Hostname = "10.20.0.9"
	if _, err := NewPolicy(target, nil); err == nil {
		t.Fatal("literal target and frozen address disagree")
	}
	target.Hostname = "10.20.0.8"
	policy, err := NewPolicy(target, nil)
	if err != nil {
		t.Fatal(err)
	}
	ips, err := policy.Resolve(context.Background())
	if err != nil || ips[0].String() != "10.20.0.8" {
		t.Fatal(ips, err)
	}
}

func TestValidatedTargetReturnsCanonicalImmutableScopeAndHonorsCancellation(t *testing.T) {
	target := targetFixture()
	target.Hostname = "APP.EXAMPLE.TEST."
	target.AllowedPaths = []string{"/public/"}
	policy, err := NewPolicy(target, nil)
	if err != nil {
		t.Fatal(err)
	}
	policy.resolver = fixedResolver{[]netip.Addr{netip.MustParseAddr("10.20.0.8")}}
	validated, err := policy.Validate(context.Background())
	if err != nil || validated.Hostname != "app.example.test" || validated.Addresses[0] != "10.20.0.8" || validated.AllowedPaths[0] != "/public" {
		t.Fatal(validated, err)
	}
	validated.Addresses[0] = "10.20.0.9"
	validated.AllowedPaths[0] = "/private"
	again, err := policy.Validate(context.Background())
	if err != nil || again.Addresses[0] != "10.20.0.8" || again.AllowedPaths[0] != "/public" {
		t.Fatal("mutable approved scope", again, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err = policy.Validate(ctx); err == nil {
		t.Fatal("cancelled validation accepted")
	}
}
