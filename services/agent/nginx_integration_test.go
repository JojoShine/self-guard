//go:build linux

package main

import (
	"bytes"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
	"time"
)

type networkProcessLog struct {
	mu   sync.Mutex
	body bytes.Buffer
}

func (b *networkProcessLog) Write(data []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.body.Write(data)
}
func (b *networkProcessLog) String() string { b.mu.Lock(); defer b.mu.Unlock(); return b.body.String() }

func networkTestPort(t *testing.T) int {
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	l.Close()
	return port
}
func TestNginxActualWafIngressAndRollback(t *testing.T) {
	binary := os.Getenv("SELFGUARD_TEST_WAF_BINARY")
	if binary == "" {
		t.Skip("isolated nginx+WAF process test only")
	}
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "healthy-owned-business") }))
	defer upstream.Close()
	for _, mode := range []string{"OBSERVE", "BLOCK"} {
		t.Run(mode, func(t *testing.T) {
			dir := t.TempDir()
			os.Mkdir(filepath.Join(dir, "logs"), 0700)
			wafState := filepath.Join(dir, "waf")
			os.Mkdir(wafState, 0700)
			wafPort, entryPort := networkTestPort(t), networkTestPort(t)
			config := fmt.Sprintf(`{"sites":[{"id":"site-owned","name":"Owned fixture","hostname":"fixture.example","upstream":%q,"enabled":true,"mode":%q,"version":1,"config":{"trustedProxyCidrs":["127.0.0.1/32"],"nginxIngress":true}}]}`, upstream.URL, mode)
			os.WriteFile(filepath.Join(wafState, "config.json"), []byte(config), 0600)
			waf := exec.Command(binary)
			waf.Env = append(os.Environ(), "WAF_CONFIG="+filepath.Join(wafState, "config.json"), "WAF_STATE_DIR="+wafState, "WAF_LISTEN=127.0.0.1:"+strconv.Itoa(wafPort), "WAF_API_URL=", "WAF_REMOTE_CERTIFICATES=false", "WAF_TEST_LISTEN=")
			var wafLog networkProcessLog
			waf.Stderr = &wafLog
			if err := waf.Start(); err != nil {
				t.Fatal(err)
			}
			defer func() { waf.Process.Kill(); waf.Wait() }()
			sitePath := filepath.Join(dir, "site.conf")
			source := []byte(fmt.Sprintf("server {listen 127.0.0.1:%d;server_name fixture.example;location / {proxy_pass %s;}}", entryPort, upstream.URL))
			os.WriteFile(sitePath, source, 0644)
			main := filepath.Join(dir, "nginx.conf")
			os.WriteFile(main, []byte("events {}\nhttp {access_log off; include "+sitePath+";}\n"), 0644)
			nginx := exec.Command("/usr/sbin/nginx", "-c", main, "-p", dir, "-g", "daemon off;pid "+filepath.Join(dir, "nginx.pid")+";")
			var nginxLog networkProcessLog
			nginx.Stderr = &nginxLog
			if err := nginx.Start(); err != nil {
				t.Fatal(err)
			}
			defer func() { nginx.Process.Kill(); nginx.Wait() }()
			runner := func(args ...string) error {
				all := append([]string{"-c", main, "-p", dir, "-g", "pid " + filepath.Join(dir, "nginx.pid") + ";"}, args...)
				return exec.Command("/usr/sbin/nginx", all...).Run()
			}
			p := HostWafPlan{SiteID: "site-owned", Hostname: "fixture.example", EntryURL: fmt.Sprintf("http://127.0.0.1:%d/", entryPort), HealthPath: "/", Mode: mode}
			var before ingressProbe
			var err error
			for i := 0; i < 40; i++ {
				before, err = probeIngress(p, "")
				if err == nil {
					break
				}
				time.Sleep(50 * time.Millisecond)
			}
			if err != nil {
				t.Fatal(err, nginxLog.String())
			}
			after, err := planNginxOnboarding(source, p.Hostname, upstream.URL, fmt.Sprintf("127.0.0.1:%d", wafPort))
			if err != nil {
				t.Fatal(err)
			}
			verify := func() error { return verifyHostWafIngress(wafState, p, before, "owned-"+mode) }
			if err = applyNginxTransaction(sitePath, filepath.Join(dir, "transaction"), after, contentDigest(source), verify, runner); err != nil {
				t.Fatal(err, wafLog.String(), nginxLog.String())
			}
			if err = rollbackNginxTransaction(filepath.Join(dir, "transaction"), runner); err != nil {
				t.Fatal(err)
			}
			restored, _ := os.ReadFile(sitePath)
			if !bytes.Equal(restored, source) {
				t.Fatal("original configuration not restored")
			}
		})
	}
}
