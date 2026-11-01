package main

import (
	"errors"
	"net/http"
	"net/url"
)

// Internal transport from the HTTP server to the isolated rule process. Do not
// rebuild a raw request: doing so can change its protocol, duplicate headers,
// chunked framing metadata or the client address observed by the proxy.
type secLiveRequest struct {
	Method           string      `json:"method"`
	URI              string      `json:"uri"`
	Protocol         string      `json:"protocol"`
	Host             string      `json:"host"`
	RemoteAddr       string      `json:"remoteAddr"`
	Headers          http.Header `json:"headers"`
	TransferEncoding []string    `json:"transferEncoding,omitempty"`
	ContentLength    int64       `json:"contentLength"`
	Body             []byte      `json:"body"`
}

func newSecLiveRequest(r *http.Request, body []byte) *secLiveRequest {
	return &secLiveRequest{r.Method, r.RequestURI, r.Proto, r.Host, r.RemoteAddr, r.Header.Clone(), append([]string(nil), r.TransferEncoding...), r.ContentLength, append([]byte(nil), body...)}
}

func (wire *secLiveRequest) state() (*secRequestState, error) {
	if len(wire.Method) == 0 || len(wire.Method) > 64 || len(wire.Host) > 256 || len(wire.RemoteAddr) > 256 || len(wire.Body) > 1<<20 || len(wire.URI) > 1<<20 {
		return nil, errors.New("observed HTTP request exceeds field budget")
	}
	major, minor, ok := http.ParseHTTPVersion(wire.Protocol)
	u, err := url.ParseRequestURI(wire.URI)
	if !ok || err != nil {
		return nil, errors.New("invalid observed HTTP protocol or target")
	}
	r := &http.Request{Method: wire.Method, RequestURI: wire.URI, Proto: wire.Protocol, ProtoMajor: major, ProtoMinor: minor, URL: u, Host: wire.Host, RemoteAddr: wire.RemoteAddr, Header: wire.Headers, TransferEncoding: wire.TransferEncoding, ContentLength: wire.ContentLength}
	return &secRequestState{request: r, body: wire.Body}, nil
}

func secFixtureRequestCount(input secLangFixture) int {
	count := 0
	if input.Variables != nil {
		count++
	}
	if input.RequestBase64 != "" {
		count++
	}
	if input.Request != nil {
		count++
	}
	return count
}
