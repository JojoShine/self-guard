package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
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

type ProbeLocalConfig struct {
	MaxQueueBytes    int64              `json:"maxQueueBytes,omitempty"`
	Installation     *ProbeInstallation `json:"installation,omitempty"`
	CaptureStatsPath string             `json:"captureStatsPath,omitempty"`
	Server           string             `json:"server"`
	SourceID         string             `json:"sourceId"`
	Token            string             `json:"token"`
	StateDir         string             `json:"stateDir"`
	CACertificate    string             `json:"caCertificate,omitempty"`
	AllowHTTP        bool               `json:"allowHTTP"`
	PlaintextSocket  string             `json:"plaintextSocket,omitempty"`
}
type probeClient struct {
	http        *http.Client
	base, token string
}
type probeHTTPError struct{ status int }

func (e *probeHTTPError) Error() string {
	return fmt.Sprintf("platform rejected probe request (%d)", e.status)
}
func newProbeClient(c ProbeLocalConfig) (*probeClient, error) {
	u, err := url.Parse(c.Server)
	if err != nil || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return nil, errors.New("platform URL invalid")
	}
	if u.Scheme != "https" {
		ip := net.ParseIP(u.Hostname())
		if u.Scheme != "http" || !c.AllowHTTP || ip == nil || !ip.IsLoopback() {
			return nil, errors.New("probe requires HTTPS; explicit loopback HTTP only for local tests")
		}
	}
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
	if c.CACertificate != "" {
		pem, err := os.ReadFile(c.CACertificate)
		if err != nil {
			return nil, errors.New("CA certificate unavailable")
		}
		roots, err := x509.SystemCertPool()
		if err != nil {
			roots = x509.NewCertPool()
		}
		if !roots.AppendCertsFromPEM(pem) {
			return nil, errors.New("CA certificate invalid")
		}
		tlsConfig.RootCAs = roots
	}
	return &probeClient{base: strings.TrimRight(c.Server, "/") + "/api/access-probe", token: c.Token, http: &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{TLSClientConfig: tlsConfig, MaxIdleConnsPerHost: 2}, CheckRedirect: func(req *http.Request, via []*http.Request) error { return errors.New("probe redirects prohibited") }}}, nil
}
func (c *probeClient) request(path string, body, out any) error {
	var reader io.Reader
	method := "GET"
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return err
		}
		reader = bytes.NewReader(raw)
		method = "POST"
	}
	req, err := http.NewRequest(method, c.base+path, reader)
	if err != nil {
		return errors.New("probe request invalid")
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Content-Type", "application/json")
	response, err := c.http.Do(req)
	if err != nil {
		return errors.New("platform connection unavailable")
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
		return &probeHTTPError{status: response.StatusCode}
	}
	if out == nil {
		_, err = io.Copy(io.Discard, io.LimitReader(response.Body, 1<<20))
		return err
	}
	if err = json.NewDecoder(io.LimitReader(response.Body, 2<<20)).Decode(out); err != nil {
		return errors.New("platform acknowledgement invalid")
	}
	return nil
}

type eventAcknowledgement struct {
	Accepted bool   `json:"accepted"`
	EventID  string `json:"eventId"`
	ID       string `json:"id"`
}

func acceptEvent(c *probeClient, e *Exchange) error {
	var ack eventAcknowledgement
	if err := c.request("/events", e, &ack); err != nil {
		return err
	}
	if !ack.Accepted || ack.EventID != e.EventID || ack.ID == "" {
		return errors.New("platform acknowledgement not bound to access")
	}
	return nil
}
func deliverPending(c *probeClient, q *Queue) error {
	files, err := q.pending()
	if err != nil {
		return err
	}
	var rejected error
events:
	for _, name := range files {
		e, err := q.load(name)
		if err != nil {
			return err
		}
		err = acceptEvent(c, e)
		if err == nil {
			if err = q.ack(name, e.EventID); err != nil {
				return err
			}
			continue
		}
		var failure *probeHTTPError
		if errors.As(err, &failure) && (failure.status == 400 || failure.status == 413 || failure.status == 422) {
			if err = q.quarantine(name); err != nil {
				return err
			}
			rejected = errors.New("permanent probe rejection quarantined; encrypted evidence retained")
			continue
		}
		if !errors.As(err, &failure) || failure.status != 409 {
			return err
		}
		expired := false
		for _, part := range e.Chunks {
			at, err := time.Parse(time.RFC3339Nano, part.CapturedAt)
			if err != nil {
				return errors.New("chunk capture time invalid")
			}
			if !time.Now().Before(at.Add(7 * 24 * time.Hour)) {
				expired = true
				break
			}
		}
		if expired {
			copy := *e
			copy.Chunks = []Chunk{}
			copy.gap("EVIDENCE_EXPIRED")
			if err = acceptEvent(c, &copy); err != nil {
				return err
			}
			if err = q.ack(name, e.EventID); err != nil {
				return err
			}
			continue
		}
		for _, part := range e.Chunks {
			data, err := q.chunk(e.EventID, part)
			if err != nil {
				return err
			}
			var ack struct {
				Persisted bool   `json:"persisted"`
				EventID   string `json:"eventId"`
				SHA256    string `json:"sha256"`
				Sequence  int    `json:"sequence"`
				Direction string `json:"direction"`
			}
			body := map[string]any{"eventId": e.EventID, "direction": part.Direction, "sequence": part.Sequence, "capturedAt": part.CapturedAt, "sha256": part.SHA256, "data": base64.StdEncoding.EncodeToString(data)}
			if err = c.request("/chunks", body, &ack); err != nil {
				var failure *probeHTTPError
				if errors.As(err, &failure) && (failure.status == 400 || failure.status == 409 || failure.status == 413 || failure.status == 422) {
					if err = q.quarantine(name); err != nil {
						return err
					}
					rejected = errors.New("permanent chunk rejection quarantined; encrypted evidence retained")
					continue events
				}
				return err
			}
			if !ack.Persisted || ack.EventID != e.EventID || ack.SHA256 != part.SHA256 || ack.Direction != part.Direction || ack.Sequence != part.Sequence {
				return errors.New("chunk acknowledgement not bound to evidence")
			}
		}
		if err = acceptEvent(c, e); err != nil {
			var failure *probeHTTPError
			if errors.As(err, &failure) && (failure.status == 400 || failure.status == 409 || failure.status == 413 || failure.status == 422) {
				if err = q.quarantine(name); err != nil {
					return err
				}
				rejected = errors.New("permanent probe rejection quarantined; encrypted evidence retained")
				continue
			}
			return err
		}
		if err = q.ack(name, e.EventID); err != nil {
			return err
		}
	}
	return rejected
}
