package scanner

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"sort"
	"strconv"
	"strings"
	"time"
)

// NetworkRule describes a bounded service observation. Only explicit banner,
// certificate-date or weak-protocol matches can become confirmed findings.
type NetworkRule struct {
	ID          string `json:"id"`
	Description string `json:"description"`
	Kind        string `json:"kind"`
	Value       string `json:"value,omitempty"`
	Days        int    `json:"days,omitempty"`
}
type NetworkProof struct {
	RuleID           string            `json:"ruleId"`
	Description      string            `json:"description"`
	CheckKind        string            `json:"checkKind"`
	Hostname         string            `json:"hostname"`
	Port             int               `json:"port"`
	Protocol         string            `json:"protocol"`
	StartedAt        time.Time         `json:"startedAt"`
	DurationMs       int64             `json:"durationMs"`
	Connections      []ConnectionProof `json:"connections,omitempty"`
	ConnectedPeers   []string          `json:"connectedPeers,omitempty"`
	BannerSHA256     string            `json:"bannerSha256,omitempty"`
	BannerBytes      int               `json:"bannerBytes,omitempty"`
	BannerPreview    string            `json:"bannerPreview,omitempty"`
	TLS              *TLSProof         `json:"tls,omitempty"`
	ValidationReason string            `json:"validationReason,omitempty"`
}
type NetworkResult struct {
	Outcome  string       `json:"outcome"`
	Reason   string       `json:"reason,omitempty"`
	Evidence NetworkProof `json:"evidence"`
}

func validateNetworkRule(rule NetworkRule, protocol string) bool {
	if rule.ID == "" || len(rule.ID) > 200 || rule.Description == "" || len(rule.Description) > 2000 {
		return false
	}
	switch rule.Kind {
	case "TCP_CONNECT":
		return protocol == "tcp" && rule.Value == "" && rule.Days == 0
	case "TCP_BANNER":
		return protocol == "tcp" && rule.Value != "" && len(rule.Value) <= 512 && rule.Days == 0
	case "TLS_HANDSHAKE", "TLS_CERT_EXPIRED":
		return protocol == "tls" && rule.Value == "" && rule.Days == 0
	case "TLS_CERT_EXPIRING":
		return protocol == "tls" && rule.Value == "" && rule.Days >= 1 && rule.Days <= 365
	case "TLS_WEAK_PROTOCOL":
		return protocol == "tls" && (rule.Value == "TLS1.0" || rule.Value == "TLS1.1") && rule.Days == 0
	}
	return false
}

// Network makes at most one connection per check. It receives the same shared
// allowance as HTTP, rechecks DNS after that allowance, and never sends arbitrary
// application commands. Diagnostic TLS does not change HTTP certificate policy.
func (e *Engine) Network(ctx context.Context, rule NetworkRule) (result NetworkResult) {
	callerContext := ctx
	started := time.Now()
	result = NetworkResult{Outcome: "INCONCLUSIVE", Evidence: NetworkProof{RuleID: rule.ID, Description: rule.Description, CheckKind: rule.Kind, Hostname: e.policy.hostname, Port: e.policy.port, Protocol: e.policy.protocol, StartedAt: started.UTC()}}
	defer func() {
		result.Evidence.DurationMs = time.Since(started).Milliseconds()
		if callerContext.Err() != nil {
			result.Outcome = "INCONCLUSIVE"
			result.Reason = "CANCELLED"
		}
	}()
	if ctx.Err() != nil {
		return
	}
	if !validateNetworkRule(rule, e.policy.protocol) {
		result.Reason = "RULE_INVALID_OR_UNSUPPORTED"
		return
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if _, err := e.policy.Resolve(ctx); err != nil {
		result.Reason = "DNS_SCOPE_UNVERIFIED"
		return
	}
	if e.requests.Add(1) > 300 {
		result.Reason = "TARGET_REQUEST_LIMIT"
		return
	}
	keys := []string{}
	for ip := range e.policy.addresses {
		keys = append(keys, net.JoinHostPort(ip.String(), strconv.Itoa(e.policy.port)))
	}
	sort.Strings(keys)
	if err := e.budget.Acquire(ctx, keys); err != nil {
		result.Reason = "SHARED_BUDGET_UNAVAILABLE"
		return
	}
	ips, err := e.policy.Resolve(ctx)
	if err != nil {
		result.Reason = "DNS_SCOPE_UNVERIFIED"
		return
	}
	sort.Slice(ips, func(i, j int) bool { return ips[i].Compare(ips[j]) < 0 })
	dialer := e.policy.dialer
	if dialer == nil {
		dialer = &net.Dialer{Timeout: 3 * time.Second}
	}
	connectionCtx, stopDial := context.WithTimeout(ctx, 3*time.Second)
	connection, err := dialer.DialContext(connectionCtx, "tcp", net.JoinHostPort(ips[0].String(), strconv.Itoa(e.policy.port)))
	stopDial()
	if err != nil {
		result.Reason = "CONNECTION_FAILED"
		return
	}
	defer connection.Close()
	stopClose := context.AfterFunc(ctx, func() { connection.Close() })
	defer stopClose()
	result.Evidence.Connections = []ConnectionProof{{Source: connection.LocalAddr().String(), Destination: connection.RemoteAddr().String(), Transport: "TCP"}}
	result.Evidence.ConnectedPeers = []string{connection.RemoteAddr().String()}
	if rule.Kind == "TCP_CONNECT" {
		result.Outcome = "OBSERVED"
		result.Reason = "CONNECTION_OBSERVED"
		return
	}
	if rule.Kind == "TCP_BANNER" {
		connection.SetReadDeadline(time.Now().Add(3 * time.Second))
		banner, readErr := bufio.NewReaderSize(connection, 4096).ReadSlice('\n')
		result.Evidence.BannerSHA256 = hashBytes(banner)
		result.Evidence.BannerBytes = len(banner)
		result.Evidence.BannerPreview = boundedObserved(string(banner))
		if readErr != nil && readErr != io.EOF {
			result.Reason = "BANNER_INCOMPLETE"
			if errors.Is(readErr, bufio.ErrBufferFull) {
				result.Reason = "BANNER_LIMIT"
			}
			return
		}
		if len(banner) == 0 {
			result.Reason = "BANNER_UNAVAILABLE"
			return
		}
		result.Outcome = "NOT_FOUND"
		if strings.Contains(string(banner), rule.Value) {
			result.Outcome = "CONFIRMED"
		}
		return
	}
	// This isolated diagnostic handshake retains the actual leaf even when expired
	// or untrusted, then verifies it separately. HTTPS remains strictly verified.
	settings := &tls.Config{ServerName: e.policy.hostname, MinVersion: tls.VersionTLS12, InsecureSkipVerify: true}
	if rule.Kind == "TLS_WEAK_PROTOCOL" {
		settings.MinVersion = tls.VersionTLS10
		if rule.Value == "TLS1.1" {
			settings.MinVersion = tls.VersionTLS11
		}
		settings.MaxVersion = settings.MinVersion
		settings.CipherSuites = []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA, tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA, tls.TLS_RSA_WITH_AES_128_CBC_SHA}
	}
	session := tls.Client(connection, settings)
	handshakeCtx, stopHandshake := context.WithTimeout(ctx, 3*time.Second)
	err = session.HandshakeContext(handshakeCtx)
	stopHandshake()
	if err != nil {
		result.Reason = "TLS_HANDSHAKE_INCOMPLETE"
		return
	}
	state := session.ConnectionState()
	if len(state.PeerCertificates) == 0 || len(state.PeerCertificates) > 10 {
		result.Reason = "TLS_CERTIFICATE_INCOMPLETE"
		return
	}
	certificateBytes := 0
	for _, cert := range state.PeerCertificates {
		certificateBytes += len(cert.Raw)
	}
	if certificateBytes > 256<<10 {
		result.Reason = "TLS_CERTIFICATE_LIMIT"
		return
	}
	leaf := state.PeerCertificates[0]
	proof := certificateProof(leaf, false, "LEAF")
	proof.Version = tls.VersionName(state.Version)
	proof.CipherSuite = tls.CipherSuiteName(state.CipherSuite)
	result.Evidence.TLS = proof
	intermediates := x509.NewCertPool()
	for _, cert := range state.PeerCertificates[1:] {
		intermediates.AddCert(cert)
	}
	_, validationErr := leaf.Verify(x509.VerifyOptions{DNSName: e.policy.hostname, CurrentTime: started, Roots: e.rootCAs, Intermediates: intermediates})
	proof.Verified = validationErr == nil
	if validationErr != nil {
		reason, _ := certificateFailure(validationErr)
		if reason == "" {
			reason = "TLS_CERTIFICATE_INVALID"
		}
		result.Evidence.ValidationReason = reason
	}
	if rule.Kind == "TLS_HANDSHAKE" {
		result.Outcome = "OBSERVED"
		result.Reason = "TLS_HANDSHAKE_OBSERVED"
		return
	}
	if leaf.NotBefore.After(started) {
		result.Reason = "TLS_CERTIFICATE_NOT_YET_VALID"
		return
	}
	result.Outcome = "NOT_FOUND"
	switch rule.Kind {
	case "TLS_CERT_EXPIRED":
		if !leaf.NotAfter.After(started) {
			result.Outcome = "CONFIRMED"
		}
	case "TLS_CERT_EXPIRING":
		if !leaf.NotAfter.After(started.Add(time.Duration(rule.Days) * 24 * time.Hour)) {
			result.Outcome = "CONFIRMED"
		}
	case "TLS_WEAK_PROTOCOL":
		result.Outcome = "CONFIRMED"
	}
	return
}
