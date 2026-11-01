package scanner

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type contextDialer interface {
	DialContext(context.Context, string, string) (net.Conn, error)
}

// Budget must enforce the shared global and endpoint allowance atomically. There
// is deliberately no permissive default or per-process substitute for this contract.
type Budget interface {
	Acquire(context.Context, []string) error
}
type Engine struct {
	policy   *Policy
	budget   Budget
	requests atomic.Int32
	rootCAs  *x509.CertPool
}
type Condition struct {
	Comparison string `json:"comparison,omitempty"`
	Threshold  *int   `json:"threshold,omitempty"`
	Negative   bool   `json:"negative,omitempty"`
	Kind       string `json:"kind"`
	Header     string `json:"header,omitempty"`
	Value      string `json:"value,omitempty"`
	Status     int    `json:"status,omitempty"`
}
type ConditionGroup struct {
	Name       string      `json:"name,omitempty"`
	Operator   string      `json:"operator"`
	Negative   bool        `json:"negative,omitempty"`
	Conditions []Condition `json:"conditions"`
}
type GroupEvidence struct {
	Name       string              `json:"name,omitempty"`
	Operator   string              `json:"operator"`
	Negative   bool                `json:"negative,omitempty"`
	Matched    bool                `json:"matched"`
	Conditions []ConditionEvidence `json:"conditions"`
}
type ExtractionSpec struct {
	Kind  string `json:"kind"`
	Value string `json:"value"`
	Group int    `json:"group,omitempty"`
	Name  string `json:"name,omitempty"`
}
type ExtractedValue struct {
	SHA256 string `json:"sha256"`
	Bytes  int    `json:"bytes"`
}
type ExtractionEvidence struct {
	Name          string           `json:"name,omitempty"`
	PatternSHA256 string           `json:"patternSha256"`
	MatchCount    int              `json:"matchCount"`
	Truncated     bool             `json:"truncated"`
	Values        []ExtractedValue `json:"values"`
}
type HTTPRule struct {
	ResponseMode string           `json:"responseMode,omitempty"`
	Extractors   []ExtractionSpec `json:"extractors,omitempty"`
	Groups       []ConditionGroup `json:"groups,omitempty"`
	MaxRedirects *int             `json:"maxRedirects,omitempty"`
	ID           string           `json:"id"`
	Description  string           `json:"description"`
	Operator     string           `json:"operator"`
	Conditions   []Condition      `json:"conditions"`
}
type ConditionEvidence struct {
	Observed  string    `json:"observed,omitempty"`
	Condition Condition `json:"condition"`
	Matched   bool      `json:"matched"`
}
type HTTPHop struct {
	Method string `json:"method"`
	Path   string `json:"path"`
	Status int    `json:"status"`
}
type TLSProof struct {
	Verified          bool      `json:"verified"`
	Version           string    `json:"version,omitempty"`
	CipherSuite       string    `json:"cipherSuite,omitempty"`
	CertificateSHA256 string    `json:"certificateSha256"`
	Subject           string    `json:"subject"`
	NotBefore         time.Time `json:"notBefore"`
	NotAfter          time.Time `json:"notAfter"`
	CertificateRole   string    `json:"certificateRole"`
}
type ConnectionProof struct {
	Source      string `json:"source"`
	Destination string `json:"destination"`
	Transport   string `json:"transport"`
}
type ResponseEvidence struct {
	Path           string `json:"path"`
	Status         int    `json:"status"`
	ResponseSHA256 string `json:"responseSha256,omitempty"`
	BodyBytes      int    `json:"bodyBytes"`
	Outcome        string `json:"outcome"`
	Reason         string `json:"reason,omitempty"`
	Matched        bool   `json:"matched"`
}
type HTTPProof struct {
	EvaluatedResponseIndex *int                 `json:"evaluatedResponseIndex,omitempty"`
	Responses              []ResponseEvidence   `json:"responses,omitempty"`
	Extractions            []ExtractionEvidence `json:"extractions,omitempty"`
	Groups                 []GroupEvidence      `json:"groups,omitempty"`
	Connections            []ConnectionProof    `json:"connections,omitempty"`
	TLS                    *TLSProof            `json:"tls,omitempty"`
	RuleID                 string               `json:"ruleId"`
	Description            string               `json:"description"`
	Hostname               string               `json:"hostname"`
	Port                   int                  `json:"port"`
	Protocol               string               `json:"protocol"`
	Status                 int                  `json:"status"`
	BodyBytes              int                  `json:"bodyBytes"`
	WireBytes              int                  `json:"wireBytes"`
	ResponseSHA256         string               `json:"responseSha256,omitempty"`
	WireSHA256             string               `json:"wireSha256,omitempty"`
	Conditions             []ConditionEvidence  `json:"conditions,omitempty"`
	Requests               []HTTPHop            `json:"requests,omitempty"`
	ConnectedPeers         []string             `json:"connectedPeers,omitempty"`
	StartedAt              time.Time            `json:"startedAt"`
	DurationMs             int64                `json:"durationMs"`
}
type HTTPResult struct {
	Outcome  string    `json:"outcome"`
	Reason   string    `json:"reason,omitempty"`
	Evidence HTTPProof `json:"evidence"`
}
type probeError string

func (e probeError) Error() string { return string(e) }
func NewEngine(policy *Policy, budget Budget) (*Engine, error) {
	if policy == nil || budget == nil {
		return nil, errors.New("approved target and shared budget required")
	}
	return &Engine{policy: policy, budget: budget}, nil
}

var headerName = regexp.MustCompile("^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")

type compiledHTTPRule struct {
	conditions []*regexp.Regexp
	extractors []*regexp.Regexp
}

func validateHTTPRule(rule HTTPRule, method string) (*compiledHTTPRule, error) {
	if rule.ID == "" || len(rule.ID) > 200 || rule.Description == "" || len(rule.Description) > 2000 || rule.Operator != "ALL" && rule.Operator != "ANY" || rule.MaxRedirects != nil && (*rule.MaxRedirects < 0 || *rule.MaxRedirects > 10 || rule.ResponseMode != "ANY_REDIRECT" && *rule.MaxRedirects > 3) || rule.ResponseMode != "" && rule.ResponseMode != "FINAL" && rule.ResponseMode != "ANY_REDIRECT" {
		return nil, errors.New("invalid rule contract")
	}
	conditions := rule.Conditions
	if len(rule.Groups) > 0 {
		if len(conditions) > 0 || len(rule.Groups) > 32 {
			return nil, errors.New("mixed or oversized matcher groups")
		}
		for _, group := range rule.Groups {
			if len(group.Name) > 200 || group.Operator != "ALL" && group.Operator != "ANY" || len(group.Conditions) == 0 {
				return nil, errors.New("invalid matcher group")
			}
			conditions = append(conditions, group.Conditions...)
		}
	}
	if len(conditions) == 0 || len(conditions) > 32 {
		return nil, errors.New("condition count exceeds budget")
	}
	expressions := make([]*regexp.Regexp, len(conditions))
	for i, c := range conditions {
		if len(c.Value) > 4096 || len(c.Header) > 200 {
			return nil, errors.New("condition exceeds budget")
		}
		switch c.Kind {
		case "STATUS":
			if c.Status < 100 || c.Status > 599 {
				return nil, errors.New("invalid response status")
			}
		case "HEADER_CONTAINS", "HEADER_MISSING", "HEADER_LOWER_CONTAINS", "HEADER_FIELD_CONTAINS":
			if !headerName.MatchString(c.Header) || c.Kind != "HEADER_MISSING" && c.Value == "" {
				return nil, errors.New("invalid header condition")
			}
		case "RESPONSE_CONTAINS":
			if c.Value == "" || strings.ContainsAny(c.Value, "\r\n") {
				return nil, errors.New("response literal must be a bounded single line")
			}
		case "BODY_LENGTH":
			if method == "HEAD" || c.Threshold == nil || *c.Threshold < 0 || *c.Threshold > 1000000000 {
				return nil, errors.New("invalid body length condition")
			}
			switch c.Comparison {
			case "EQ", "NE", "GT", "GE", "LT", "LE":
			default:
				return nil, errors.New("invalid length comparison")
			}
		case "BODY_CONTAINS", "BODY_REGEX", "BODY_LOWER_CONTAINS", "BODY_FOLD_CONTAINS":
			if method == "HEAD" || c.Value == "" {
				return nil, errors.New("body condition requires GET")
			}
			if c.Kind == "BODY_REGEX" {
				var err error
				expressions[i], err = regexp.Compile(c.Value)
				if err != nil {
					return nil, errors.New("unsupported regular expression")
				}
			}
		default:
			return nil, errors.New("unsupported condition")
		}
	}
	if len(rule.Extractors) > 16 || len(rule.Extractors) > 0 && method != "GET" {
		return nil, errors.New("extractor count or method exceeds budget")
	}
	extractors := make([]*regexp.Regexp, len(rule.Extractors))
	for i, spec := range rule.Extractors {
		if spec.Kind != "BODY_REGEX" || spec.Value == "" || len(spec.Value) > 4096 || len(spec.Name) > 200 || spec.Group < 0 || spec.Group > 32 {
			return nil, errors.New("unsupported extractor")
		}
		expression, err := regexp.Compile(spec.Value)
		if err != nil || expression.NumSubexp() > 32 || spec.Group > expression.NumSubexp() {
			return nil, errors.New("unsupported extraction expression or capture group")
		}
		extractors[i] = expression
	}
	return &compiledHTTPRule{conditions: expressions, extractors: extractors}, nil
}
func (p *Policy) dialApproved(ctx context.Context, network, address string) (net.Conn, error) {
	if network != "tcp" && network != "tcp4" && network != "tcp6" {
		return nil, probeError("OUT_OF_SCOPE")
	}
	host, port, err := net.SplitHostPort(address)
	if err != nil || host != p.hostname || port != strconv.Itoa(p.port) {
		return nil, probeError("OUT_OF_SCOPE")
	}
	ips, err := p.Resolve(ctx)
	if err != nil {
		return nil, probeError("DNS_SCOPE_UNVERIFIED")
	}
	dialer := p.dialer
	if dialer == nil {
		dialer = &net.Dialer{Timeout: 3 * time.Second}
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	for _, ip := range ips {
		conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(ip.String(), port))
		if err == nil {
			return conn, nil
		}
		if ctx.Err() != nil {
			break
		}
	}
	return nil, probeError("CONNECTION_FAILED")
}

type capturedHTTPResponse struct {
	response   *http.Response
	path       string
	wire, body []byte
	reason     string
}
type guardedHTTP struct {
	captureResponses bool
	responses        []capturedHTTPResponse
	engine           *Engine
	transport        *http.Transport
	mu               sync.Mutex
	hops             []HTTPHop
	connections      []ConnectionProof
	peers            []string
}

func (g *guardedHTTP) RoundTrip(req *http.Request) (*http.Response, error) {
	if err := g.engine.policy.CheckURL(req.URL); err != nil {
		return nil, probeError("OUT_OF_SCOPE")
	}
	if g.engine.requests.Add(1) > 300 {
		return nil, probeError("TARGET_REQUEST_LIMIT")
	}
	keys := []string{}
	for ip := range g.engine.policy.addresses {
		keys = append(keys, net.JoinHostPort(ip.String(), strconv.Itoa(g.engine.policy.port)))
	}
	sort.Strings(keys)
	if err := g.engine.budget.Acquire(req.Context(), keys); err != nil {
		return nil, probeError("SHARED_BUDGET_UNAVAILABLE")
	}
	response, err := g.transport.RoundTrip(req)
	hop := HTTPHop{Method: req.Method, Path: req.URL.EscapedPath()}
	if response != nil {
		hop.Status = response.StatusCode
	}
	g.mu.Lock()
	g.hops = append(g.hops, hop)
	g.mu.Unlock()
	if response != nil && err == nil && g.captureResponses {
		wire, body, reason := boundedResponse(response)
		response.Body.Close()
		snapshot := new(http.Response)
		*snapshot = *response
		snapshot.Header = response.Header.Clone()
		snapshot.Body = nil
		g.mu.Lock()
		g.responses = append(g.responses, capturedHTTPResponse{response: snapshot, path: req.URL.EscapedPath(), wire: wire, body: body, reason: reason})
		g.mu.Unlock()
		if reason != "" {
			return nil, probeError(reason)
		}
		response.Body = io.NopCloser(bytes.NewReader(wire))
	}
	return response, err
}
func (g *guardedHTTP) dial(ctx context.Context, network, address string) (net.Conn, error) {
	conn, err := g.engine.policy.dialApproved(ctx, network, address)
	if err == nil {
		g.mu.Lock()
		g.peers = append(g.peers, conn.RemoteAddr().String())
		g.connections = append(g.connections, ConnectionProof{conn.LocalAddr().String(), conn.RemoteAddr().String(), "TCP"})
		g.mu.Unlock()
	}
	return conn, err
}
func hashBytes(value []byte) string { sum := sha256.Sum256(value); return hex.EncodeToString(sum[:]) }
func certificateProof(cert *x509.Certificate, verified bool, role string) *TLSProof {
	if cert == nil {
		return nil
	}
	subject := cert.Subject.CommonName
	if len(subject) > 200 {
		subject = subject[:200]
	}
	return &TLSProof{Verified: verified, CertificateSHA256: hashBytes(cert.Raw), Subject: subject, NotBefore: cert.NotBefore.UTC(), NotAfter: cert.NotAfter.UTC(), CertificateRole: role}
}
func certificateFailure(err error) (string, *TLSProof) {
	var hostname x509.HostnameError
	if errors.As(err, &hostname) {
		return "TLS_HOSTNAME_MISMATCH", certificateProof(hostname.Certificate, false, "VALIDATION_ERROR")
	}
	var invalid x509.CertificateInvalidError
	if errors.As(err, &invalid) {
		reason := "TLS_CERTIFICATE_INVALID"
		if invalid.Reason == x509.Expired {
			reason = "TLS_CERTIFICATE_EXPIRED"
			if invalid.Cert != nil && time.Now().Before(invalid.Cert.NotBefore) {
				reason = "TLS_CERTIFICATE_NOT_YET_VALID"
			}
		}
		return reason, certificateProof(invalid.Cert, false, "VALIDATION_ERROR")
	}
	var authority x509.UnknownAuthorityError
	if errors.As(err, &authority) {
		return "TLS_CERTIFICATE_UNTRUSTED", certificateProof(authority.Cert, false, "VALIDATION_ERROR")
	}
	return "", nil
}
func boundedResponse(response *http.Response) (wire, body []byte, reason string) {
	wire, err := io.ReadAll(io.LimitReader(response.Body, (1<<20)+1))
	if err != nil {
		return wire, nil, "RESPONSE_INCOMPLETE"
	}
	if len(wire) > 1<<20 {
		return wire, nil, "RESPONSE_WIRE_LIMIT"
	}
	if response.Request != nil && response.Request.Method == "HEAD" {
		return wire, wire, ""
	}
	switch strings.ToLower(strings.TrimSpace(response.Header.Get("Content-Encoding"))) {
	case "", "identity":
		return wire, wire, ""
	case "gzip":
		reader, err := gzip.NewReader(bytes.NewReader(wire))
		if err != nil {
			return wire, nil, "RESPONSE_DECOMPRESSION_FAILED"
		}
		defer reader.Close()
		body, err = io.ReadAll(io.LimitReader(reader, (1<<20)+1))
		if err != nil {
			return wire, body, "RESPONSE_DECOMPRESSION_FAILED"
		}
		if len(body) > 1<<20 {
			return wire, body, "RESPONSE_DECODED_LIMIT"
		}
		return wire, body, ""
	default:
		return wire, nil, "RESPONSE_ENCODING_UNSUPPORTED"
	}
}
func (e *Engine) HTTP(ctx context.Context, method, path string, rule HTTPRule) (result HTTPResult) {
	started := time.Now()
	result = HTTPResult{Outcome: "INCONCLUSIVE", Evidence: HTTPProof{RuleID: rule.ID, Description: rule.Description, Hostname: e.policy.hostname, Port: e.policy.port, Protocol: e.policy.protocol, StartedAt: started.UTC()}}
	defer func() { result.Evidence.DurationMs = time.Since(started).Milliseconds() }()
	if method != "GET" && method != "HEAD" || e.policy.protocol != "http" && e.policy.protocol != "https" {
		result.Reason = "METHOD_OR_PROTOCOL_UNSUPPORTED"
		return
	}
	expressions, err := validateHTTPRule(rule, method)
	if err != nil {
		result.Reason = "RULE_INVALID_OR_UNSUPPORTED"
		return
	}
	relative, err := url.ParseRequestURI(path)
	if err != nil || relative.IsAbs() || relative.Host != "" {
		result.Reason = "OUT_OF_SCOPE"
		return
	}
	u := &url.URL{Scheme: e.policy.protocol, Host: net.JoinHostPort(e.policy.hostname, strconv.Itoa(e.policy.port)), Path: relative.Path, RawPath: relative.RawPath, RawQuery: relative.RawQuery}
	if err = e.policy.CheckURL(u); err != nil {
		result.Reason = "OUT_OF_SCOPE"
		return
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	guard := &guardedHTTP{engine: e, captureResponses: rule.ResponseMode == "ANY_REDIRECT"}
	transport := &http.Transport{Proxy: nil, DialContext: guard.dial, DisableCompression: true, DisableKeepAlives: true, ForceAttemptHTTP2: false, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, ServerName: e.policy.hostname, RootCAs: e.rootCAs}, TLSHandshakeTimeout: 3 * time.Second, ResponseHeaderTimeout: 5 * time.Second, MaxResponseHeaderBytes: 16 << 10}
	guard.transport = transport
	defer transport.CloseIdleConnections()
	defer func() {
		guard.mu.Lock()
		result.Evidence.Requests = append([]HTTPHop(nil), guard.hops...)
		result.Evidence.ConnectedPeers = append([]string(nil), guard.peers...)
		result.Evidence.Connections = append([]ConnectionProof(nil), guard.connections...)
		guard.mu.Unlock()
	}()
	maxRedirects := 3
	if rule.MaxRedirects != nil {
		maxRedirects = *rule.MaxRedirects
	}
	client := &http.Client{Transport: guard, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if maxRedirects == 0 {
			return http.ErrUseLastResponse
		}
		if len(via) > maxRedirects {
			return probeError("REDIRECT_LIMIT")
		}
		if req.Method != "GET" && req.Method != "HEAD" || e.policy.CheckURL(req.URL) != nil {
			return probeError("OUT_OF_SCOPE")
		}
		return nil
	}}
	request, err := http.NewRequestWithContext(ctx, method, u.String(), nil)
	if err != nil {
		result.Reason = "REQUEST_INVALID"
		return
	}
	request.Header.Set("User-Agent", "SelfGuard-Scanner/0.1")
	request.Header.Set("Accept-Encoding", "identity")
	response, err := client.Do(request)
	if err != nil {
		var classified probeError
		result.Reason = "HTTP_REQUEST_INCOMPLETE"
		if reason, proof := certificateFailure(err); reason != "" {
			result.Reason = reason
			result.Evidence.TLS = proof
		}
		if errors.As(err, &classified) {
			result.Reason = string(classified)
		}
		if ctx.Err() != nil {
			result.Reason = "CANCELLED_OR_DEADLINE"
		}
		return
	}
	defer response.Body.Close()
	if rule.ResponseMode == "ANY_REDIRECT" {
		guard.mu.Lock()
		chain := append([]capturedHTTPResponse(nil), guard.responses...)
		guard.mu.Unlock()
		if len(chain) == 0 {
			result.Reason = "HTTP_REQUEST_INCOMPLETE"
			return
		}
		evaluations := make([]HTTPResult, len(chain))
		summaries := make([]ResponseEvidence, len(chain))
		for i, capture := range chain {
			evaluations[i] = evaluateCapturedResponse(result.Evidence, rule, expressions, capture)
			evaluated := evaluations[i]
			summaries[i] = ResponseEvidence{Path: capture.path, Status: evaluated.Evidence.Status, ResponseSHA256: evaluated.Evidence.ResponseSHA256, BodyBytes: evaluated.Evidence.BodyBytes, Outcome: evaluated.Outcome, Reason: evaluated.Reason, Matched: evaluated.Outcome == "CONFIRMED"}
		}
		selected, incomplete := len(chain)-1, -1
		for i := len(evaluations) - 1; i >= 0; i-- {
			if evaluations[i].Outcome == "CONFIRMED" {
				selected = i
				break
			}
			if incomplete < 0 && evaluations[i].Outcome == "INCONCLUSIVE" {
				incomplete = i
			}
		}
		if evaluations[selected].Outcome != "CONFIRMED" && incomplete >= 0 {
			selected = incomplete
		}
		result = evaluations[selected]
		result.Evidence.Responses = summaries
		result.Evidence.EvaluatedResponseIndex = &selected
		return
	}
	wire, body, reason := boundedResponse(response)
	result = evaluateCapturedResponse(result.Evidence, rule, expressions, capturedHTTPResponse{response: response, wire: wire, body: body, reason: reason})
	return
}

func evaluateCapturedResponse(base HTTPProof, rule HTTPRule, expressions *compiledHTTPRule, capture capturedHTTPResponse) (result HTTPResult) {
	result = HTTPResult{Outcome: "INCONCLUSIVE", Evidence: base}
	response, wire, body, reason := capture.response, capture.wire, capture.body, capture.reason
	result.Evidence.Status = response.StatusCode
	if response.TLS != nil && len(response.TLS.PeerCertificates) > 0 {
		result.Evidence.TLS = certificateProof(response.TLS.PeerCertificates[0], len(response.TLS.VerifiedChains) > 0, "LEAF")
		result.Evidence.TLS.Version = tls.VersionName(response.TLS.Version)
		result.Evidence.TLS.CipherSuite = tls.CipherSuiteName(response.TLS.CipherSuite)
	}
	result.Evidence.WireBytes = len(wire)
	result.Evidence.BodyBytes = len(body)
	if reason != "" {
		result.Reason = reason
		return
	}
	result.Evidence.WireSHA256 = hashBytes(wire)
	result.Evidence.ResponseSHA256 = hashBytes(body)
	if !requiredHeadersAvailable(rule, response.Header) {
		result.Reason = "REQUIRED_RESPONSE_FIELD_MISSING"
		return
	}
	view := ""
	if needsResponseView(rule) {
		var err error
		view, err = responseMatchView(response, body)
		if err != nil {
			result.Reason = "RESPONSE_HEADER_VIEW_INCOMPLETE"
			return
		}
	}
	matched, conditions, groups := evaluateHTTPRule(rule, expressions.conditions, response.StatusCode, response.Header, body, view)
	result.Evidence.Conditions = conditions
	result.Evidence.Groups = groups
	result.Outcome = "NOT_FOUND"
	if matched {
		result.Outcome = "CONFIRMED"
		result.Evidence.Extractions = extractResponse(rule.Extractors, expressions.extractors, body)
	}
	return
}

func evaluateHTTPConditions(rule HTTPRule, expressions []*regexp.Regexp, status int, headers http.Header, body []byte, responseView string) (bool, []ConditionEvidence) {
	conditions := make([]ConditionEvidence, 0, len(rule.Conditions))
	matched := rule.Operator == "ALL"
	text := string(body)
	for i, c := range rule.Conditions {
		hit := false
		observed := ""
		switch c.Kind {
		case "STATUS":
			hit = status == c.Status
			observed = strconv.Itoa(status)
		case "HEADER_CONTAINS":
			hit = strings.Contains(strings.Join(headers.Values(c.Header), "\n"), c.Value)
		case "HEADER_LOWER_CONTAINS", "HEADER_FIELD_CONTAINS":
			value := strings.Join(headers.Values(c.Header), " ")
			if c.Kind == "HEADER_LOWER_CONTAINS" {
				value = strings.ToLower(value)
			}
			hit = strings.Contains(value, c.Value)
			if hit {
				observed = boundedObserved(c.Value)
			}
		case "RESPONSE_CONTAINS":
			hit = strings.Contains(responseView, c.Value)
			if hit {
				observed = boundedObserved(c.Value)
			}
		case "BODY_LOWER_CONTAINS":
			hit = strings.Contains(strings.ToLower(text), c.Value)
			if hit {
				observed = boundedObserved(c.Value)
			}
		case "BODY_FOLD_CONTAINS":
			needle := strings.ToLower(c.Value)
			hit = strings.Contains(strings.ToLower(text), needle)
			if hit {
				observed = boundedObserved(needle)
			}
		case "BODY_LENGTH":
			length := len(body)
			observed = strconv.Itoa(length)
			switch c.Comparison {
			case "EQ":
				hit = length == *c.Threshold
			case "NE":
				hit = length != *c.Threshold
			case "GT":
				hit = length > *c.Threshold
			case "GE":
				hit = length >= *c.Threshold
			case "LT":
				hit = length < *c.Threshold
			case "LE":
				hit = length <= *c.Threshold
			}
		case "HEADER_MISSING":
			_, present := headers[http.CanonicalHeaderKey(c.Header)]
			hit = !present
			observed = "PRESENT"
			if hit {
				observed = "ABSENT"
			}
		case "BODY_CONTAINS":
			hit = strings.Contains(text, c.Value)
		case "BODY_REGEX":
			indices := expressions[i].FindIndex(body)
			hit = indices != nil
			if hit {
				observed = boundedObserved(string(body[indices[0]:indices[1]]))
			}
		}
		if hit && (c.Kind == "BODY_CONTAINS" || c.Kind == "HEADER_CONTAINS") {
			observed = boundedObserved(c.Value)
		}
		if c.Negative {
			hit = !hit
		}
		conditions = append(conditions, ConditionEvidence{Condition: c, Matched: hit, Observed: observed})
		if rule.Operator == "ALL" {
			matched = matched && hit
		} else {
			matched = matched || hit
		}
	}
	return matched, conditions
}

func boundedObserved(value string) string {
	count := 0
	for index := range value {
		if count == 128 {
			return value[:index]
		}
		count++
	}
	return value
}

func evaluateHTTPRule(rule HTTPRule, expressions []*regexp.Regexp, status int, headers http.Header, body []byte, responseView string) (bool, []ConditionEvidence, []GroupEvidence) {
	if len(rule.Groups) == 0 {
		matched, conditions := evaluateHTTPConditions(rule, expressions, status, headers, body, responseView)
		return matched, conditions, nil
	}
	matched := rule.Operator == "ALL"
	groups := make([]GroupEvidence, 0, len(rule.Groups))
	offset := 0
	for _, group := range rule.Groups {
		count := len(group.Conditions)
		hit, conditions := evaluateHTTPConditions(HTTPRule{Operator: group.Operator, Conditions: group.Conditions}, expressions[offset:offset+count], status, headers, body, responseView)
		offset += count
		if group.Negative {
			hit = !hit
		}
		groups = append(groups, GroupEvidence{Name: group.Name, Operator: group.Operator, Negative: group.Negative, Matched: hit, Conditions: conditions})
		if rule.Operator == "ALL" {
			matched = matched && hit
		} else {
			matched = matched || hit
		}
	}
	return matched, []ConditionEvidence{}, groups
}

func requiredHeadersAvailable(rule HTTPRule, headers http.Header) bool {
	check := func(conditions []Condition) bool {
		for _, c := range conditions {
			if c.Kind == "HEADER_LOWER_CONTAINS" || c.Kind == "HEADER_FIELD_CONTAINS" {
				if _, present := headers[http.CanonicalHeaderKey(c.Header)]; !present {
					return false
				}
			}
		}
		return true
	}
	if !check(rule.Conditions) {
		return false
	}
	for _, group := range rule.Groups {
		if !check(group.Conditions) {
			return false
		}
	}
	return true
}

func needsResponseView(rule HTTPRule) bool {
	check := func(conditions []Condition) bool {
		for _, c := range conditions {
			if c.Kind == "RESPONSE_CONTAINS" {
				return true
			}
		}
		return false
	}
	if check(rule.Conditions) {
		return true
	}
	for _, group := range rule.Groups {
		if check(group.Conditions) {
			return true
		}
	}
	return false
}
func responseMatchView(response *http.Response, body []byte) (string, error) {
	copy := *response
	copy.Header = response.Header.Clone()
	headers, err := httputil.DumpResponse(&copy, false)
	if err != nil || len(headers) > 32<<10 {
		return "", errors.New("response header view incomplete")
	}
	return string(headers) + string(body), nil
}

// Extracted values may include secrets. Persist only bounded digests and byte lengths.
func extractResponse(specs []ExtractionSpec, expressions []*regexp.Regexp, body []byte) []ExtractionEvidence {
	if len(specs) == 0 {
		return nil
	}
	evidence := make([]ExtractionEvidence, 0, len(specs))
	for i, spec := range specs {
		indexes := expressions[i].FindAllSubmatchIndex(body, 17)
		record := ExtractionEvidence{Name: spec.Name, PatternSHA256: hashBytes([]byte(spec.Value)), Truncated: len(indexes) > 16, Values: []ExtractedValue{}}
		if len(indexes) > 16 {
			indexes = indexes[:16]
		}
		seen := map[string]bool{}
		for _, index := range indexes {
			start, end := index[spec.Group*2], index[spec.Group*2+1]
			if start < 0 {
				continue
			}
			record.MatchCount++
			value := ExtractedValue{SHA256: hashBytes(body[start:end]), Bytes: end - start}
			if !seen[value.SHA256] {
				record.Values = append(record.Values, value)
				seen[value.SHA256] = true
			}
		}
		evidence = append(evidence, record)
	}
	return evidence
}
