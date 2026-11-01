package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type Exception struct {
	RuleID string `json:"ruleId"`
	Path   string `json:"path"`
	Param  string `json:"param"`
}
type PathRateLimit struct {
	Path          string `json:"path"`
	RatePerMinute int    `json:"ratePerMinute"`
}
type Policy struct {
	NginxIngress      bool            `json:"nginxIngress,omitempty"`
	PathRateLimits    []PathRateLimit `json:"pathRateLimits"`
	HealthCheckPath   string          `json:"healthCheckPath"`
	MaxBodyBytes      int64           `json:"maxBodyBytes"`
	RatePerMinute     int             `json:"ratePerMinute"`
	AllowCidrs        []string        `json:"allowCidrs"`
	DenyCidrs         []string        `json:"denyCidrs"`
	TrustedProxyCidrs []string        `json:"trustedProxyCidrs"`
	AllowedMethods    []string        `json:"allowedMethods"`
	DeniedPaths       []string        `json:"deniedPaths"`
	Exceptions        []Exception     `json:"exceptions"`
}
type Site struct {
	ID          string            `json:"id"`
	Name        string            `json:"name"`
	Hostname    string            `json:"hostname"`
	Upstream    string            `json:"upstream"`
	Mode        string            `json:"mode"`
	Enabled     bool              `json:"enabled"`
	Version     int               `json:"version"`
	Config      Policy            `json:"config"`
	RuleRelease *secSignedRelease `json:"ruleRelease,omitempty"`
}
type Config struct {
	Sites             []Site         `json:"sites"`
	SiteVersionFloors map[string]int `json:"siteVersionFloors,omitempty"`
}
type runtimeSite struct {
	Site
	proxy         *httputil.ReverseProxy
	rulePolicy    *secRuntimePolicy
	builtinSHA256 string
}
type counter struct {
	n     int
	until time.Time
}
type Event struct {
	Context    *requestTrace       `json:"context,omitempty"`
	ID         string              `json:"id"`
	SiteID     string              `json:"siteId"`
	RuleID     string              `json:"ruleId"`
	Path       string              `json:"path"`
	Method     string              `json:"method"`
	Action     string              `json:"action"`
	RemoteIP   string              `json:"remoteIp"`
	Timestamp  string              `json:"timestamp"`
	Inspection *secEventInspection `json:"inspection,omitempty"`
}
type engine struct {
	nodeID              string
	startedAt           string
	accessSeq           atomic.Uint64
	access              *accessLog
	accessPending       *accessQueue
	accessWriteTimings  *accessWriteDiagnostics
	totalRequests       atomic.Uint64
	blockedRequests     atomic.Uint64
	observedRequests    atomic.Uint64
	upstreamErrors      atomic.Uint64
	accessLogDropped    atomic.Uint64
	health              atomic.Value
	outbox              *outbox
	dropped             atomic.Uint64
	sites               atomic.Value
	mu                  sync.Mutex
	rates               map[string]counter
	events              chan Event
	seq                 atomic.Uint64
	rulePublicKey       ed25519.PublicKey
	rulePool            *secLangPool
	inspectionAdmission *secInspectionAdmission
	configMu            sync.Mutex
	siteVersionFloors   map[string]int
}

func newEngine() *engine {
	hostname, _ := os.Hostname()
	e := &engine{nodeID: env("WAF_NODE_ID", hostname), startedAt: time.Now().UTC().Format(time.RFC3339Nano), rates: map[string]counter{}, events: make(chan Event, 1024), inspectionAdmission: newSecInspectionAdmission()}
	if os.Getenv("WAF_DEVELOPMENT") == "true" {
		e.accessWriteTimings = &accessWriteDiagnostics{}
	}
	e.sites.Store(map[string]runtimeSite{})
	e.health.Store([]UpstreamHealth{})
	return e
}
func (e *engine) update(c Config) error {
	e.configMu.Lock()
	defer e.configMu.Unlock()
	floors := cloneSiteVersionFloors(e.siteVersionFloors)
	for id, version := range c.SiteVersionFloors {
		if id == "" || len(id) > 200 || version < 0 {
			return fmt.Errorf("invalid local site version history")
		}
		if version > floors[id] {
			floors[id] = version
		}
	}
	if len(floors) > 10000 {
		return fmt.Errorf("site version history exceeds budget")
	}
	m := map[string]runtimeSite{}
	if len(c.Sites) > 1000 {
		return fmt.Errorf("too many sites")
	}
	for _, s := range c.Sites {
		if s.Version < floors[s.ID] {
			return fmt.Errorf("site version predates retained history")
		}
		if len(e.rulePublicKey) > 0 && s.RuleRelease == nil {
			return fmt.Errorf("pinned rule trust requires a signed site policy")
		}
		for _, old := range e.sites.Load().(map[string]runtimeSite) {
			if old.ID == s.ID && s.Version < old.Version {
				return fmt.Errorf("older site version rejected")
			}
			if old.ID == s.ID && old.RuleRelease != nil && s.RuleRelease == nil {
				return fmt.Errorf("removing signed protection requires a signed rollback")
			}
		}
		rulePolicy, err := e.prepareRuntimePolicy(s)
		if err != nil {
			return err
		}
		u, err := url.Parse(s.Upstream)
		if err != nil || u.Host == "" || u.User != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Fragment != "" {
			return fmt.Errorf("invalid upstream")
		}
		s.Hostname = strings.ToLower(s.Hostname)
		if s.Hostname == "" || strings.ContainsAny(s.Hostname, "/ :") {
			return fmt.Errorf("invalid hostname")
		}
		if _, ok := m[s.Hostname]; ok {
			return fmt.Errorf("duplicate host")
		}
		if s.Mode != "BLOCK" && s.Mode != "OBSERVE" {
			return fmt.Errorf("invalid mode")
		}
		p := &s.Config
		if p.MaxBodyBytes == 0 {
			p.MaxBodyBytes = 1048576
		}
		if p.RatePerMinute == 0 {
			p.RatePerMinute = 120
		}
		if p.MaxBodyBytes < 1 || p.MaxBodyBytes > 8<<20 || p.RatePerMinute < 1 {
			return fmt.Errorf("invalid limits")
		}
		if p.HealthCheckPath == "" {
			p.HealthCheckPath = "/"
		}
		if !validPolicyPath(p.HealthCheckPath) {
			return fmt.Errorf("invalid health check path")
		}
		if len(p.PathRateLimits) > 100 {
			return fmt.Errorf("too many path limits")
		}
		seenPaths := map[string]bool{}
		for _, limit := range p.PathRateLimits {
			if !validPolicyPath(limit.Path) || limit.RatePerMinute < 1 || seenPaths[limit.Path] {
				return fmt.Errorf("invalid path rate limit")
			}
			seenPaths[limit.Path] = true
		}
		for _, list := range [][]string{p.AllowCidrs, p.DenyCidrs, p.TrustedProxyCidrs} {
			for _, v := range list {
				if _, _, err := net.ParseCIDR(v); err != nil {
					return err
				}
			}
		}
		for _, x := range p.Exceptions {
			if x.Path == "" || x.RuleID == "" {
				return fmt.Errorf("invalid exception")
			}
		}
		for _, old := range e.sites.Load().(map[string]runtimeSite) {
			if old.ID == s.ID && old.RuleRelease != nil && old.Version == s.Version && !reflect.DeepEqual(old.Site, s) {
				return fmt.Errorf("site content changed without a new version")
			}
		}
		proxy := httputil.NewSingleHostReverseProxy(u)
		originalDirector := proxy.Director
		proxy.Director = func(request *http.Request) {
			originalHost := request.Header.Get("X-Selfguard-Original-Host")
			peer, _, _ := net.SplitHostPort(request.RemoteAddr)
			originalDirector(request)
			request.Header.Del("X-Selfguard-Original-Host")
			if p.NginxIngress && net.ParseIP(peer).IsLoopback() && inCIDRs(peer, p.TrustedProxyCidrs) && validNginxOriginalHost(originalHost) {
				request.Host = originalHost
			}
		}
		proxy.Transport = &http.Transport{Proxy: nil, DialContext: (&net.Dialer{Timeout: 5 * time.Second}).DialContext, ResponseHeaderTimeout: 15 * time.Second, IdleConnTimeout: 60 * time.Second, MaxIdleConns: 100}
		proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
			e.upstreamErrors.Add(1)
			if trace, ok := r.Context().Value(requestTraceKey{}).(*requestTraceState); ok {
				trace.mu.Lock()
				trace.value.Outcome = "UPSTREAM_ERROR"
				trace.mu.Unlock()
			}
			http.Error(w, "upstream unavailable", 502)
		}
		m[s.Hostname] = runtimeSite{Site: s, proxy: proxy, rulePolicy: rulePolicy, builtinSHA256: builtinPolicyDigest(s.Config)}
		if s.Version > floors[s.ID] {
			floors[s.ID] = s.Version
		}
	}
	if len(floors) > 10000 {
		return fmt.Errorf("site version history exceeds budget")
	}
	e.siteVersionFloors = floors
	e.sites.Store(m)
	return nil
}
func contains(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}
func inCIDRs(ip string, xs []string) bool {
	v := net.ParseIP(ip)
	for _, x := range xs {
		_, n, _ := net.ParseCIDR(x)
		if n != nil && n.Contains(v) {
			return true
		}
	}
	return false
}

var patterns = []struct {
	id string
	r  *regexp.Regexp
}{{"SQLI", regexp.MustCompile(`(?i)(union\s+(all\s+)?select|or\s+['"0-9]+\s*=|sleep\s*\(|drop\s+table)`)}, {"XSS", regexp.MustCompile(`(?i)(<\s*script|javascript\s*:|on(error|load)\s*=)`)}, {"TRAVERSAL", regexp.MustCompile(`(\.\./|\.\.\\)`)}, {"COMMAND", regexp.MustCompile("(?i)(;\\s*(cat|curl|wget|sh|bash)\\b|\\$\\(|`)")}}

func inspect(s Site, path, param, value string) string {
	if v, err := url.QueryUnescape(value); err == nil {
		value = v
	}
	for _, p := range patterns {
		if p.r.MatchString(value) {
			skip := false
			for _, x := range s.Config.Exceptions {
				if x.RuleID == p.id && x.Path == path && (x.Param == "" || x.Param == param) {
					skip = true
				}
			}
			if !skip {
				return p.id
			}
		}
	}
	return ""
}
func (e *engine) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	e.totalRequests.Add(1)
	inspectionAdmitted := false
	var reservedInspectionBytes int64
	defer func() {
		if inspectionAdmitted {
			r.Body.Close()
			r.Body = http.NoBody
			e.inspectionAdmission.release(reservedInspectionBytes)
		}
	}()
	started := time.Now()
	requestID := fmt.Sprintf("%s:%s:%d", e.nodeID, e.startedAt, e.accessSeq.Add(1))
	trace := newRequestTrace(requestID, r)
	r = r.WithContext(context.WithValue(r.Context(), requestTraceKey{}, trace))
	tracked := &statusWriter{ResponseWriter: w, status: 200}
	w = tracked
	siteID := ""
	defer func() {
		if e.access != nil || e.accessPending != nil {
			var auditStarted time.Time
			if e.accessWriteTimings != nil {
				e.accessWriteTimings.observe(accessHandlerStage, time.Since(started), false)
				auditStarted = time.Now()
			}
			entry := AccessEntry{ID: requestID, Context: trace.snapshot(), SiteID: siteID, Method: safeMethod(r.Method), Path: retainedRequestPath(r), Status: tracked.status, Timestamp: started.UTC().Format(time.RFC3339Nano), DurationMicros: time.Since(started).Microseconds()}
			var queueErr, historyErr error
			if e.accessPending != nil && e.access != nil {
				// Both stores own immutable copies of this observation. Overlap
				// their independent writes, but wait for both before returning.
				pending := make(chan error, 1)
				go func() {
					pending <- e.accessWriteTimings.measure(accessQueueStage, func() error { return e.accessPending.append(entry) })
				}()
				historyErr = e.accessWriteTimings.measure(accessHistoryStage, func() error { return e.access.append(entry) })
				queueErr = <-pending
			} else if e.accessPending != nil {
				queueErr = e.accessWriteTimings.measure(accessQueueStage, func() error { return e.accessPending.append(entry) })
			} else if e.access != nil {
				historyErr = e.accessWriteTimings.measure(accessHistoryStage, func() error { return e.access.append(entry) })
			}
			if e.accessWriteTimings != nil {
				e.accessWriteTimings.observe(accessCompletionStage, time.Since(auditStarted), queueErr != nil || historyErr != nil)
			}
			if queueErr != nil {
				e.accessLogDropped.Add(1)
				log.Print("access queue rejected request record: ", queueErr)
			}
			if historyErr != nil {
				e.accessLogDropped.Add(1)
			}
		}
	}()
	if !validInboundProtocol(r) {
		http.Error(w, "invalid HTTP authority or request target", http.StatusBadRequest)
		return
	}
	host := strings.ToLower(r.Host)
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	s, ok := e.sites.Load().(map[string]runtimeSite)[host]
	if !ok || !s.Enabled {
		http.Error(w, "unknown site", 404)
		return
	}
	siteID = s.ID
	origin, _ := url.Parse(s.Upstream)
	trace.value.ConfiguredUpstream = origin.Scheme + "://" + origin.Host
	ip, _, _ := net.SplitHostPort(r.RemoteAddr)
	if inCIDRs(ip, s.Config.TrustedProxyCidrs) {
		chain := strings.Split(r.Header.Get("X-Forwarded-For"), ",")
		for i := len(chain) - 1; i >= 0; i-- {
			candidate := strings.TrimSpace(chain[i])
			if net.ParseIP(candidate) == nil {
				break
			}
			ip = candidate
			if !inCIDRs(ip, s.Config.TrustedProxyCidrs) {
				break
			}
		}
	}
	trace.value.ClientIP = ip
	if ip != trace.value.PeerIP && inCIDRs(trace.value.PeerIP, s.Config.TrustedProxyCidrs) {
		trace.value.SourceBasis = "TRUSTED_PROXY_CHAIN"
	}
	var observedHeaders http.Header
	if s.rulePolicy != nil {
		observedHeaders = r.Header.Clone()
	}
	r.Header.Del("X-Forwarded-For")
	r.Header.Del("X-Real-IP")
	r.Header.Del("Forwarded")
	rule := ""
	var liveInspection *secEventInspection
	blockStatus := http.StatusForbidden
	p := s.Config
	if inCIDRs(ip, p.DenyCidrs) || (len(p.AllowCidrs) > 0 && !inCIDRs(ip, p.AllowCidrs)) {
		rule = "IP"
	}
	if len(p.AllowedMethods) > 0 && !contains(p.AllowedMethods, r.Method) {
		rule = "METHOD"
	}
	if contains(p.DeniedPaths, r.URL.Path) {
		rule = "PATH"
	}
	if e.rateExceeded(s.ID+":"+ip, p.RatePerMinute) {
		rule = "RATE"
	}
	for _, limit := range p.PathRateLimits {
		if r.URL.Path == limit.Path && e.rateExceeded(s.ID+":"+ip+":path:"+limit.Path, limit.RatePerMinute) {
			rule = "RATE"
		}
	}

	if len(r.URL.RequestURI()) > 16384 {
		http.Error(w, "URI too long", 414)
		return
	}
	if s.rulePolicy != nil {
		if !e.inspectionAdmission.acquire(p.MaxBodyBytes) {
			liveInspection = secInspectionEvent(e.nodeID, s, secResult{}, errSecPoolCapacity)
			e.enqueueEvent(Event{ID: fmt.Sprintf("%d-%d", time.Now().UnixNano(), e.seq.Add(1)), SiteID: s.ID, RuleID: "INSPECTION_INCOMPLETE", Context: trace.event("INSPECTION_INCOMPLETE", "BLOCK"), Path: retainedRequestPath(r), Method: r.Method, Action: "BLOCK", RemoteIP: ip, Timestamp: time.Now().UTC().Format(time.RFC3339), Inspection: liveInspection})
			http.Error(w, "rule inspection capacity reached", http.StatusServiceUnavailable)
			return
		}
		inspectionAdmitted = true
		reservedInspectionBytes = p.MaxBodyBytes
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, p.MaxBodyBytes+1))
	if err != nil {
		http.Error(w, "invalid body", 400)
		return
	}
	if int64(len(body)) > p.MaxBodyBytes {
		http.Error(w, "body too large", 413)
		return
	}
	r.Body = io.NopCloser(bytes.NewReader(body))
	if s.rulePolicy != nil {
		encoding := strings.ToLower(strings.TrimSpace(r.Header.Get("Content-Encoding")))
		if encoding != "" && encoding != "identity" {
			http.Error(w, "unsupported encoded request body", http.StatusUnsupportedMediaType)
			return
		}
		wire := newSecLiveRequest(r, body)
		wire.Headers = observedHeaders
		wire.RemoteAddr = net.JoinHostPort(ip, "0")
		decision, err := e.rulePool.evaluatePolicy(r.Context(), s.rulePolicy.policy, secLangFixture{Request: wire, Threshold: s.rulePolicy.threshold})
		liveInspection = secInspectionEvent(e.nodeID, s, decision, err)
		if err != nil {
			e.enqueueEvent(Event{ID: fmt.Sprintf("%d-%d", time.Now().UnixNano(), e.seq.Add(1)), SiteID: s.ID, RuleID: "INSPECTION_INCOMPLETE", Context: trace.event("INSPECTION_INCOMPLETE", "BLOCK"), Path: retainedRequestPath(r), Method: r.Method, Action: "BLOCK", RemoteIP: ip, Timestamp: time.Now().UTC().Format(time.RFC3339), Inspection: liveInspection})
			http.Error(w, "rule inspection unavailable or incomplete", http.StatusServiceUnavailable)
			return
		}
		if rule == "" && decision.Blocked {
			rule = "RULE_POLICY"
			if len(decision.Matches) > 0 {
				rule = decision.Matches[len(decision.Matches)-1]
			}
			blockStatus = decision.Status
		}
	}
	if s.rulePolicy == nil {
		check := func(param, value, variable string) {
			if rule == "" {
				rule = inspect(s.Site, r.URL.Path, param, value)
				if rule != "" {
					if normalized, err := url.QueryUnescape(value); err == nil {
						value = normalized
					}
					liveInspection = secBuiltinInspection(e.nodeID, s, rule, variable, value)
				}
			}
		}
		check("", r.URL.Path, "REQUEST_FILENAME")
		for k, vs := range r.URL.Query() {
			check("", k, "ARGS_NAMES")
			for _, v := range vs {
				check(k, v, "ARGS:"+k)
			}
		}
		for k, vs := range r.Header {
			for _, v := range vs {
				check("header:"+k, v, "REQUEST_HEADERS:"+k)
			}
		}
		ct := r.Header.Get("Content-Type")
		encoding := strings.TrimSpace(strings.ToLower(r.Header.Get("Content-Encoding")))
		if encoding != "" && encoding != "identity" {
			rule = "ENCODING"
			ct = ""
		}
		if strings.Contains(ct, "application/x-www-form-urlencoded") {
			values, err := url.ParseQuery(string(body))
			if err != nil {
				http.Error(w, "invalid form", 400)
				return
			}
			for k, vs := range values {
				for _, v := range vs {
					check(k, v, "ARGS_POST:"+k)
				}
			}
		} else if strings.Contains(ct, "application/json") && len(body) > 0 {
			var value any
			if json.Unmarshal(body, &value) != nil {
				http.Error(w, "invalid JSON", 400)
				return
			}
			var walk func(any, string)
			walk = func(v any, key string) {
				switch x := v.(type) {
				case string:
					check(key, x, "JSON_FIELD:"+key)
				case []any:
					for _, item := range x {
						walk(item, key)
					}
				case map[string]any:
					for k, item := range x {
						check("", k, "JSON_FIELD_NAMES")
						walk(item, k)
					}
				}
			}
			walk(value, "body")
		} else {
			check("body", string(body), "REQUEST_BODY")
		}
	}
	if rule != "" {
		if liveInspection == nil || !contains(liveInspection.Matches, rule) {
			variable, value := "REMOTE_ADDR", ip
			switch rule {
			case "METHOD":
				variable, value = "REQUEST_METHOD", r.Method
			case "PATH":
				variable, value = "REQUEST_FILENAME", r.URL.Path
			case "ENCODING":
				variable, value = "REQUEST_HEADERS:Content-Encoding", r.Header.Get("Content-Encoding")
			}
			basis := secBuiltinInspection(e.nodeID, s, rule, variable, value)
			if liveInspection == nil {
				liveInspection = basis
			} else {
				if len(liveInspection.Matches) < 32 {
					liveInspection.Matches = append(liveInspection.Matches, rule)
				}
				if len(liveInspection.Evidence) < 8 {
					liveInspection.Evidence = append(liveInspection.Evidence, basis.Evidence[0])
				} else {
					liveInspection.OmittedEvidence++
				}
			}
		}
		action := "OBSERVE"
		if s.Mode == "BLOCK" {
			action = "BLOCK"
		}
		event := Event{ID: fmt.Sprintf("%d-%d", time.Now().UnixNano(), e.seq.Add(1)), SiteID: s.ID, RuleID: rule, Context: trace.event(rule, action), Path: retainedRequestPath(r), Method: r.Method, Action: action, RemoteIP: ip, Timestamp: time.Now().UTC().Format(time.RFC3339), Inspection: liveInspection}
		e.enqueueEvent(event)
		if action == "BLOCK" {
			e.blockedRequests.Add(1)
			http.Error(w, "request blocked", blockStatus)
			return
		}
		e.observedRequests.Add(1)
	}
	s.proxy.ServeHTTP(w, trace.forward(r))
}
func readConfig(data []byte) (Config, error) {
	var c Config
	err := json.Unmarshal(data, &c)
	return c, err
}
func env(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}
func main() {
	if len(os.Args) == 2 && os.Args[1] == "--test-seclang-diagnostics" {
		if err := applySecLangWorkerLimits(); err != nil {
			fmt.Fprintln(os.Stderr, "worker limits unavailable")
			os.Exit(1)
		}
		if err := runSecLangCLIOptions(os.Stdin, os.Stdout, true, false, true); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}
	if len(os.Args) == 2 && os.Args[1] == "--serve-seclang" {
		if err := applySecLangWorkerLimits(); err != nil {
			fmt.Fprintln(os.Stderr, "worker limits unavailable")
			os.Exit(1)
		}
		if err := runSecLangStream(os.Stdin, os.Stdout); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}
	if len(os.Args) == 2 && (os.Args[1] == "--check-seclang" || os.Args[1] == "--test-seclang" || os.Args[1] == "--index-seclang") {
		if err := applySecLangWorkerLimits(); err != nil {
			fmt.Fprintln(os.Stderr, "worker limits unavailable")
			os.Exit(1)
		}
		if err := runSecLangCLI(os.Stdin, os.Stdout, os.Args[1] == "--test-seclang", os.Args[1] == "--index-seclang"); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}

	e := newEngine()
	var trustErr error
	e.rulePublicKey, trustErr = loadSecRulePublicKey(os.Getenv("WAF_RULE_PUBLIC_KEY_FILE"))
	if trustErr != nil {
		log.Fatal(trustErr)
	}
	if len(e.rulePublicKey) > 0 {
		binary, err := os.Executable()
		if err != nil {
			log.Fatal("cannot locate isolated rule executor")
		}
		e.rulePool = newSecLangPool(binary, 3)
		defer e.rulePool.close()
	}
	var outboxErr error
	e.outbox, outboxErr = openOutbox(env("WAF_STATE_DIR", "waf-state"), 1024)
	if outboxErr != nil {
		log.Fatal("cannot load WAF event outbox: ", outboxErr)
	}
	e.access, outboxErr = openAccessLog(env("WAF_STATE_DIR", "waf-state"), 1024)
	if outboxErr != nil {
		log.Fatal("cannot load access log: ", outboxErr)
	}
	e.accessPending, outboxErr = openAccessQueue(env("WAF_STATE_DIR", "waf-state"), 100000)
	if outboxErr != nil {
		log.Fatal("cannot load access queue: ", outboxErr)
	}
	file := env("WAF_CONFIG", "config.json")
	load := func() {
		b, err := os.ReadFile(file)
		if err == nil {
			var c Config
			c, err = readConfig(b)
			if err == nil {
				err = e.update(c)
			}
		}
		if err != nil {
			log.Printf("config rejected: %v", err)
		}
	}
	load()
	var certificates *certificateStore
	if path := os.Getenv("WAF_TLS_CONFIG"); path != "" {
		certificates = &certificateStore{}
		if err := certificates.reload(path); err != nil {
			log.Fatal("TLS configuration rejected: ", err)
		}
	}
	remoteCertificates := os.Getenv("WAF_REMOTE_CERTIFICATES") == "true" && os.Getenv("WAF_TLS_CONFIG") == "" && os.Getenv("WAF_TLS_CERT") == ""
	if remoteCertificates {
		certificates = &certificateStore{}
		if len(os.Getenv("WAF_TOKEN")) < 32 {
			log.Fatal("remote certificates require WAF_TOKEN of at least 32 characters")
		}
		if err := certificates.loadRemoteCache(env("WAF_STATE_DIR", "waf-state"), os.Getenv("WAF_TOKEN")); err != nil {
			log.Print("encrypted certificate cache unavailable; TLS requires a successful management fetch")
		}
	}
	go func() {
		for {
			e.checkUpstreams()
			time.Sleep(10 * time.Second)
		}
	}()
	go func() {
		for range time.Tick(10 * time.Second) {
			if certificates != nil && !remoteCertificates {
				if err := certificates.reload(os.Getenv("WAF_TLS_CONFIG")); err != nil {
					log.Printf("TLS reload rejected: %v", err)
				}
			}
		}
	}()
	client := &http.Client{Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	base := strings.TrimRight(os.Getenv("WAF_API_URL"), "/")
	if base != "" {
		if err := validateManagementURL(base, os.Getenv("WAF_DEVELOPMENT") == "true"); err != nil {
			log.Fatal(err)
		}
	}
	token := os.Getenv("WAF_TOKEN")
	if remoteCertificates && base == "" {
		log.Fatal("remote certificates require WAF_API_URL")
	}
	if remoteCertificates {
		if err := certificates.syncRemote(client, base, token, env("WAF_STATE_DIR", "waf-state")); err != nil {
			log.Print("certificate refresh rejected; previous valid certificates retained: ", err)
		}
	}
	if addr := os.Getenv("WAF_TEST_LISTEN"); addr != "" {
		if len(token) < 32 {
			log.Fatal("policy testing requires WAF_TOKEN of at least 32 characters")
		}
		go func() { log.Fatal(startPolicyTestServer(e, addr, token)) }()
	}
	go func() {
		for range time.Tick(10 * time.Second) {
			if remoteCertificates {
				if err := certificates.syncRemote(client, base, token, env("WAF_STATE_DIR", "waf-state")); err != nil {
					log.Print("certificate refresh rejected; previous valid certificates retained: ", err)
				}
			}
			if base == "" {
				load()
				continue
			}
			func() {
				req, _ := http.NewRequest("GET", base+"/api/waf/config", nil)
				req.Header.Set("Authorization", "Bearer "+token)
				resp, err := client.Do(req)
				if err != nil {
					return
				}
				defer resp.Body.Close()
				b, err := io.ReadAll(io.LimitReader(resp.Body, (8<<20)+1))
				if err != nil || len(b) > 8<<20 || resp.StatusCode != 200 {
					return
				}
				if e.applyRemoteConfig(file, b) != nil {
					log.Print("remote configuration rejected; previous verified configuration retained")
				}
			}()
			b, _ := json.Marshal(e.heartbeatPayload())
			req, _ := http.NewRequest("POST", base+"/api/waf/heartbeat", bytes.NewReader(b))
			req.Header.Set("Authorization", "Bearer "+token)
			req.Header.Set("Content-Type", "application/json")
			resp, err := client.Do(req)
			if err == nil {
				resp.Body.Close()
			}
		}
	}()
	go func() {
		for range time.Tick(250 * time.Millisecond) {
			if base != "" {
				if err := e.accessPending.deliver(client, base, token, e.nodeID); err != nil {
					log.Print(err)
				}
				if err := e.outbox.deliver(client, base, token); err != nil {
					time.Sleep(time.Second)
				}
			}
		}
	}()

	srv := &http.Server{Addr: env("WAF_LISTEN", ":8081"), Handler: e, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 32768}
	if certificates != nil {
		srv.TLSConfig = certificates.tlsConfig()
		log.Fatal(srv.ListenAndServeTLS("", ""))
	}
	if cert := os.Getenv("WAF_TLS_CERT"); cert != "" {
		log.Fatal(srv.ListenAndServeTLS(cert, os.Getenv("WAF_TLS_KEY")))
	}
	log.Fatal(srv.ListenAndServe())
}

func validateManagementURL(raw string, development bool) error {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return fmt.Errorf("invalid management URL")
	}
	ip := net.ParseIP(u.Hostname())
	local := u.Hostname() == "localhost" || (ip != nil && ip.IsLoopback())
	if u.Scheme != "https" && !(u.Scheme == "http" && (local || development || os.Getenv("WAF_ALLOW_HTTP") == "true")) {
		return fmt.Errorf("management HTTP requires explicit WAF_ALLOW_HTTP; HTTPS remains the default")
	}
	return nil
}
func persistConfig(path string, b []byte) error {
	f, err := os.CreateTemp(filepath.Dir(path), ".waf-config-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err = f.Write(b); err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	return os.Rename(f.Name(), path)
}
