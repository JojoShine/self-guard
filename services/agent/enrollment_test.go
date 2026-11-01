package main

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

type lostResponse struct {
	base http.RoundTripper
	lost bool
}

func (t *lostResponse) RoundTrip(r *http.Request) (*http.Response, error) {
	resp, e := t.base.RoundTrip(r)
	if e == nil && !t.lost {
		t.lost = true
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		return nil, errors.New("lost response")
	}
	return resp, e
}
func TestEnrollmentLostResponse(t *testing.T) {
	var secret string
	calls := 0
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var b map[string]string
		json.NewDecoder(r.Body).Decode(&b)
		calls++
		if len(b["credential"]) < 32 {
			t.Error("missing recovery credential")
		}
		if secret != "" && secret != b["credential"] {
			t.Error("changed recovery secret")
		}
		secret = b["credential"]
		json.NewEncoder(w).Encode(map[string]string{"assetId": "asset", "token": secret})
	}))
	defer s.Close()
	c := Config{Server: s.URL, StateDir: t.TempDir()}
	a, _ := New(c)
	a.Client.Transport = &lostResponse{base: http.DefaultTransport}
	if a.enroll() == nil {
		t.Fatal("expected lost response")
	}
	b, _ := New(c)
	if e := b.enroll(); e != nil {
		t.Fatal(e)
	}
	if calls != 2 || b.Identity.AssetID != "asset" || b.Identity.Token != secret {
		t.Fatal("not recovered")
	}
	if e := b.enroll(); e != nil || calls != 2 {
		t.Fatal("enrolled again")
	}
}
