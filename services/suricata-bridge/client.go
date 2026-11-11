package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

type Config struct {
	Schema             string `json:"schema"`
	Server             string `json:"server"`
	SensorID           string `json:"sensorId"`
	AssetID            string `json:"assetId"`
	Token              string `json:"token"`
	EVEPath            string `json:"evePath"`
	RuleFile           string `json:"ruleFile,omitempty"`
	ExpectedRuleSHA256 string `json:"expectedRuleSha256,omitempty"`
	CACertificate      string `json:"caCertificate,omitempty"`
	IdentityPath       string `json:"identityPath"`
	StateDir           string `json:"stateDir"`
	ReadFromStart      bool   `json:"readFromStart"`
}
type client struct {
	http                       *http.Client
	base, token, sensor, asset string
}
type rejection struct{ status int }

func (e *rejection) Error() string { return fmt.Sprintf("platform response %d", e.status) }
func newClient(c Config, local bool) (*client, error) {
	u, e := url.Parse(c.Server)
	if e != nil || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return nil, errors.New("invalid platform URL")
	}
	if u.Scheme != "https" {
		ip := net.ParseIP(u.Hostname())
		if u.Scheme != "http" || !local || ip == nil || !ip.IsLoopback() {
			return nil, errors.New("HTTPS required")
		}
	}
	tc := &tls.Config{MinVersion: tls.VersionTLS12}
	if c.CACertificate != "" {
		pem, e := os.ReadFile(c.CACertificate)
		if e != nil {
			return nil, errors.New("CA unavailable")
		}
		roots, e := x509.SystemCertPool()
		if e != nil {
			roots = x509.NewCertPool()
		}
		if !roots.AppendCertsFromPEM(pem) {
			return nil, errors.New("invalid CA")
		}
		tc.RootCAs = roots
	}
	return &client{http: &http.Client{Timeout: 20 * time.Second, Transport: &http.Transport{TLSClientConfig: tc}, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("redirect prohibited") }}, base: strings.TrimRight(c.Server, "/") + "/api/sensor-ingest/" + url.PathEscape(c.SensorID), token: c.Token, sensor: c.SensorID, asset: c.AssetID}, nil
}
func (c *client) request(path string, body any, out any) error {
	var r io.Reader
	method := "GET"
	if body != nil {
		b, e := json.Marshal(body)
		if e != nil {
			return e
		}
		r = bytes.NewReader(b)
		method = "POST"
	}
	req, e := http.NewRequest(method, c.base+path, r)
	if e != nil {
		return errors.New("request invalid")
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Content-Type", "application/json")
	resp, e := c.http.Do(req)
	if e != nil {
		return errors.New("platform unavailable")
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return &rejection{resp.StatusCode}
	}
	d := json.NewDecoder(io.LimitReader(resp.Body, 65536))
	if e = d.Decode(out); e != nil {
		return errors.New("platform response invalid")
	}
	return nil
}
func (c *client) check() error {
	var result struct {
		SensorID string          `json:"sensorId"`
		AssetID  string          `json:"assetId"`
		Enabled  bool            `json:"enabled"`
		Version  json.RawMessage `json:"version"`
	}
	if e := c.request("/config", nil, &result); e != nil {
		return e
	}
	if result.SensorID != c.sensor || result.AssetID != c.asset || !result.Enabled || len(result.Version) == 0 {
		return errors.New("source disabled or binding mismatch")
	}
	return nil
}
func deliver(c *client, dir string, st *State) error {
	if st.Pending == nil {
		return nil
	}
	p := st.Pending
	var ack struct {
		SensorID  string `json:"sensorId"`
		BatchID   string `json:"batchId"`
		Persisted bool   `json:"persisted"`
		Accepted  *int   `json:"accepted"`
	}
	if e := c.request("/batches", p.Batch, &ack); e != nil {
		return e
	}
	if ack.SensorID != c.sensor || ack.BatchID != p.Batch.BatchID || !ack.Persisted || ack.Accepted == nil || (*ack.Accepted < 0 || *ack.Accepted > len(p.Batch.Events)) {
		return errors.New("batch acknowledgement mismatch")
	}
	next := *st
	next.Cursor = p.Next
	next.Pending = nil
	if e := saveState(dir, next); e != nil {
		return e
	}
	*st = next
	return nil
}
