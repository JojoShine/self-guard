package main

import (
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"time"
)

type policyTestRequest struct {
	SiteID   string            `json:"siteId"`
	Method   string            `json:"method"`
	Path     string            `json:"path"`
	Headers  map[string]string `json:"headers"`
	Body     string            `json:"body"`
	RemoteIP string            `json:"remoteIp"`
	Repeat   int               `json:"repeat"`
}
type noUpstream struct{}

func (noUpstream) RoundTrip(r *http.Request) (*http.Response, error) {
	return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("")), Request: r}, nil
}

// Uses ServeHTTP's complete inspection pipeline on an isolated engine. The only
// proxy transport has no network operations, and counters/outboxes are local.
func (e *engine) policyTestHandler(token string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if token == "" || subtle.ConstantTimeCompare([]byte(r.Header.Get("Authorization")), []byte("Bearer "+token)) != 1 {
			http.Error(w, "component identity required", 401)
			return
		}
		if r.Method != "POST" {
			http.Error(w, "POST required", 405)
			return
		}
		var input policyTestRequest
		decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
		decoder.DisallowUnknownFields()
		if decoder.Decode(&input) != nil {
			http.Error(w, "invalid test request", 400)
			return
		}
		var extra any
		if decoder.Decode(&extra) != io.EOF {
			http.Error(w, "invalid test request", 400)
			return
		}
		u, err := url.ParseRequestURI(input.Path)
		if err != nil || !strings.HasPrefix(input.Path, "/") || strings.HasPrefix(input.Path, "//") || u.IsAbs() || len(input.Path) > 16384 || safeMethod(input.Method) == "OTHER" {
			http.Error(w, "invalid path or method", 400)
			return
		}
		if input.RemoteIP == "" {
			input.RemoteIP = "192.0.2.1"
		}
		if net.ParseIP(input.RemoteIP) == nil {
			http.Error(w, "invalid remote IP", 400)
			return
		}
		if input.Repeat == 0 {
			input.Repeat = 1
		}
		if input.Repeat < 1 || input.Repeat > 100 {
			http.Error(w, "repeat must be 1..100", 400)
			return
		}
		var site Site
		var active runtimeSite
		found := false
		for _, s := range e.sites.Load().(map[string]runtimeSite) {
			if s.ID == input.SiteID {
				site = s.Site
				active = s
				found = true
				break
			}
		}
		if !found {
			http.Error(w, "site unavailable", 404)
			return
		}
		isolated := newEngine()
		// The active snapshot already passed signature and exact source validation.
		// Clone its proxy before replacing transport; reuse only immutable policy.
		proxy := *active.proxy
		proxy.Transport = noUpstream{}
		active.proxy = &proxy
		isolated.rulePool = e.rulePool
		isolated.inspectionAdmission = e.inspectionAdmission
		isolated.sites.Store(map[string]runtimeSite{site.Hostname: active})
		results := []map[string]any{}
		for i := 0; i < input.Repeat; i++ {
			request, err := http.NewRequest(input.Method, "http://"+site.Hostname+input.Path, strings.NewReader(input.Body))
			if err != nil {
				http.Error(w, "invalid request", 400)
				return
			}
			request.Host = site.Hostname
			request.RequestURI = input.Path
			request.RemoteAddr = net.JoinHostPort(input.RemoteIP, "12345")
			for key, value := range input.Headers {
				request.Header.Set(key, value)
			}
			recorder := httptest.NewRecorder()
			isolated.ServeHTTP(recorder, request)
			result := map[string]any{"status": recorder.Code, "action": "ALLOW", "ruleId": ""}
			select {
			case event := <-isolated.events:
				result["action"] = event.Action
				result["ruleId"] = event.RuleID
				if event.Inspection != nil {
					result["inspection"] = event.Inspection
				}
			default:
				if recorder.Code != 200 {
					result["action"] = "REJECT"
				}
			}
			results = append(results, result)
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"siteId": site.ID, "version": site.Version, "results": results})
	})
}
func startPolicyTestServer(e *engine, addr, token string) error {
	if len(token) < 32 {
		return fmt.Errorf("policy testing requires WAF_TOKEN of at least 32 characters")
	}
	mux := http.NewServeMux()
	mux.Handle("/", e.policyTestHandler(token))
	binary, err := os.Executable()
	if err != nil {
		return err
	}
	check, evaluate := newSecLangManagementHandlers(token, binary)
	defer evaluate.Close()
	mux.Handle("/seclang/check", check)
	mux.Handle("/seclang/test", evaluate)
	mux.Handle("/seclang/pool", e.rulePoolHandler(token))
	srv := &http.Server{Addr: addr, Handler: mux, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 15 * time.Second, MaxHeaderBytes: 32768}
	return srv.ListenAndServe()
}
