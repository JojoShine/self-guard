package main

import (
	"net/http"
	"testing"
)

func TestManagedProxyModesDoNotSilentlyInheritEnvironment(t *testing.T) {
	direct, err := clientForConfig(Config{ProxyMode: "DIRECT"})
	if err != nil {
		t.Fatal(err)
	}
	if direct.Transport.(*http.Transport).Proxy != nil {
		t.Fatal("direct mode still inherits service proxy environment")
	}
	inherited, err := clientForConfig(Config{ProxyMode: "ENVIRONMENT"})
	if err != nil || inherited.Transport.(*http.Transport).Proxy == nil {
		t.Fatal("environment mode unavailable", err)
	}
	explicit, err := clientForConfig(Config{ProxyMode: "EXPLICIT", ProxyURL: "http://proxy.example:3128"})
	if err != nil {
		t.Fatal(err)
	}
	request, _ := http.NewRequest("GET", "https://guard.example", nil)
	proxy, err := explicit.Transport.(*http.Transport).Proxy(request)
	if err != nil || proxy.String() != "http://proxy.example:3128" {
		t.Fatal("explicit proxy not bound", proxy, err)
	}
	for _, c := range []Config{{ProxyMode: "EXPLICIT"}, {ProxyMode: "DIRECT", ProxyURL: "http://proxy.example:3128"}, {ProxyMode: "unexpected"}} {
		if _, err = clientForConfig(c); err == nil {
			t.Fatal("invalid proxy mode accepted", c)
		}
	}
}
