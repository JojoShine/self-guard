package main

import (
	"bufio"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestProxyRejectsInvalidWireProtocolBeforeUpstream(t *testing.T) {
	var forwarded atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		forwarded.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()
	e := newEngine()
	if err := e.update(Config{Sites: []Site{{ID: "protocol", Hostname: "localhost", Upstream: upstream.URL, Mode: "OBSERVE", Enabled: true}}}); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(e)
	defer server.Close()
	for _, fixture := range []struct {
		request string
		status  int
	}{
		{"CONNECT www.coreruleset.org HTTP/1.1\r\nHost: localhost\r\n", 400},
		{"GET /get/index.html:80?I=Like&Apples=Today#tag HTTP/1.1\r\nHost: localhost\r\n", 400},
		{"GET /?test=test1 HTTP/1.1\r\nHost: localhost%00\r\n", 400},
		{"GET / HTTP/0.9\r\nHost: localhost\r\n", 505},
		{"GET / HTTP/1.1\r\nHost:\r\n", 400},
		{"GET / HTTP/0.8\r\nHost: localhost\r\n", 505},
		{"GET /#fragment HTTP/1.1\r\nHost: localhost\r\n", 400},
		{"GET / \r\nHost: localhost\r\n", 400},
	} {
		request := fixture.request
		t.Run(strings.Split(request, "\r\n")[0], func(t *testing.T) {
			connection, err := net.DialTimeout("tcp", server.Listener.Addr().String(), time.Second)
			if err != nil {
				t.Fatal(err)
			}
			defer connection.Close()
			_ = connection.SetDeadline(time.Now().Add(2 * time.Second))
			if _, err = fmt.Fprint(connection, request+"Connection: close\r\n\r\n"); err != nil {
				t.Fatal(err)
			}
			response, err := http.ReadResponse(bufio.NewReader(connection), nil)
			if err != nil {
				t.Fatal(err)
			}
			response.Body.Close()
			if response.StatusCode != fixture.status {
				t.Fatalf("wire response = %d, want %d", response.StatusCode, fixture.status)
			}
		})
	}
	if forwarded.Load() != 0 {
		t.Fatalf("invalid requests reached upstream: %d", forwarded.Load())
	}
	for _, target := range []string{"/hello", "/literal%23fragment", "/?q=%23tag"} {
		request := httptest.NewRequest("GET", target, nil)
		request.Host = "localhost"
		response := httptest.NewRecorder()
		e.ServeHTTP(response, request)
		if response.Code != 200 {
			t.Fatalf("valid target %s rejected: %d", target, response.Code)
		}
	}
}
