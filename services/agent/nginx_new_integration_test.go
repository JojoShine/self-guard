package main

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

func TestActualNginxNewBusinessThroughWafAndRollback(t *testing.T) {
	binary := os.Getenv("NGINX_WAF_BINARY")
	if binary == "" {
		t.Skip("explicit real Nginx and WAF process fixture")
	}
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "owned-business-health") }))
	defer upstream.Close()
	for _, mode := range []string{"OBSERVE", "BLOCK"} {
		t.Run(mode, func(t *testing.T) {
			root := t.TempDir()
			os.Mkdir(filepath.Join(root, "logs"), 0700)
			sites := filepath.Join(root, "vhosts")
			os.Mkdir(sites, 0700)
			state := filepath.Join(root, "waf")
			os.Mkdir(state, 0700)
			wafPort, entryPort, otherPort := networkTestPort(t), networkTestPort(t), networkTestPort(t)
			config := fmt.Sprintf(`{"sites":[{"id":"owned-new","hostname":"new.example","upstream":%q,"enabled":true,"mode":%q,"version":1,"config":{"trustedProxyCidrs":["127.0.0.1/32"],"nginxIngress":true}}]}`, upstream.URL, mode)
			os.WriteFile(filepath.Join(state, "config.json"), []byte(config), 0600)
			waf := exec.Command(binary)
			waf.Env = append(os.Environ(), "WAF_CONFIG="+filepath.Join(state, "config.json"), "WAF_STATE_DIR="+state, "WAF_LISTEN=127.0.0.1:"+strconv.Itoa(wafPort), "WAF_API_URL=", "WAF_TEST_LISTEN=")
			var logs networkProcessLog
			waf.Stderr = &logs
			if err := waf.Start(); err != nil {
				t.Fatal(err)
			}
			defer func() { waf.Process.Kill(); waf.Wait() }()
			original := []byte(fmt.Sprintf("server {listen 127.0.0.1:%d;server_name other.example;location / {proxy_pass %s;}}", otherPort, upstream.URL))
			other := filepath.Join(sites, "other.conf")
			os.WriteFile(other, original, 0644)
			main := filepath.Join(root, "nginx.conf")
			os.WriteFile(main, []byte("events {}\nhttp {access_log off; include "+sites+"/*.conf;}\n"), 0644)
			pid := filepath.Join(root, "nginx.pid")
			nginx := exec.Command("/usr/sbin/nginx", "-c", main, "-p", root, "-g", "daemon off;pid "+pid+";")
			nginx.Stderr = &logs
			if err := nginx.Start(); err != nil {
				t.Fatal(err)
			}
			defer func() { nginx.Process.Kill(); nginx.Wait() }()
			otherAddress := fmt.Sprintf("http://127.0.0.1:%d/", otherPort)
			ready := false
			for i := 0; i < 60; i++ {
				response, err := http.Get(otherAddress)
				if err == nil {
					response.Body.Close()
					ready = true
					break
				}
				time.Sleep(50 * time.Millisecond)
			}
			if !ready {
				t.Fatal("nginx startup", logs.String())
			}
			p := HostWafPlan{SiteID: "owned-new", Hostname: "new.example", Upstream: upstream.URL, EntryURL: fmt.Sprintf("http://127.0.0.1:%d/", entryPort), ListenPort: entryPort, HealthPath: "/", Mode: mode, BusinessMode: "NEW"}
			source, err := newNginxSite(p)
			if err != nil {
				t.Fatal(err)
			}
			after, err := planNginxOnboarding(source, p.Hostname, p.Upstream, fmt.Sprintf("127.0.0.1:%d", wafPort))
			if err != nil {
				t.Fatal(err)
			}
			before, err := probeBusinessUpstream(p)
			if err != nil {
				t.Fatal(err)
			}
			runner := func(args ...string) error {
				return exec.Command("/usr/sbin/nginx", append([]string{"-c", main, "-p", root, "-g", "pid " + pid + ";"}, args...)...).Run()
			}
			target := filepath.Join(sites, "new.conf")
			transaction := filepath.Join(root, "transaction")
			if err = applyNewNginxTransaction(target, transaction, after, func() error { return verifyHostWafIngress(state, p, before, "owned-new-"+mode) }, runner); err != nil {
				t.Fatal(err, logs.String())
			}
			response, err := http.Get(otherAddress)
			if err != nil {
				t.Fatal(err)
			}
			body, _ := io.ReadAll(response.Body)
			response.Body.Close()
			if string(body) != "owned-business-health" {
				t.Fatal("existing business changed")
			}
			if err = rollbackNginxTransaction(transaction, runner); err != nil {
				t.Fatal(err)
			}
			if _, err = os.Stat(target); !os.IsNotExist(err) {
				t.Fatal("new configuration remains", err)
			}
			if actual, _ := os.ReadFile(other); !bytes.Equal(actual, original) {
				t.Fatal("other vhost changed")
			}
		})
	}
}
