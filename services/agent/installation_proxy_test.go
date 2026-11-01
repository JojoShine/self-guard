package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestInstallationClientUsesExplicitProxyWithoutCredentials(t *testing.T) {
	calls := 0
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.URL.Host != "not-resolvable.invalid" || r.Header.Get("Proxy-Authorization") != "" {
			t.Error("proxy binding or credentials changed")
		}
		w.Write([]byte("proxied"))
	}))
	defer proxy.Close()
	client, err := installationClient("", proxy.URL)
	if err != nil {
		t.Fatal(err)
	}
	response, err := client.Get("http://not-resolvable.invalid/profile-test")
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, _ := io.ReadAll(response.Body)
	if calls != 1 || string(body) != "proxied" {
		t.Fatal("configured proxy was ignored")
	}
	if _, err = installationClient("", "http://user:secret@proxy.invalid"); err == nil {
		t.Fatal("proxy credentials accepted")
	}
}
