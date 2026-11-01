//go:build pcre2 && cgo

package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"testing"
	"time"
)

func TestFrozenCRSUsesRealWarmWorkersForAttackAndBenignRequests(t *testing.T) {
	file := os.Getenv("WAF_CRS_INPUT")
	if file == "" {
		t.Skip("requires explicitly frozen local CRS files and profile")
	}
	raw, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	var fixture secLangFixture
	if json.Unmarshal(raw, &fixture) != nil {
		t.Fatal("invalid frozen CRS input")
	}
	profile, err := os.ReadFile(os.Getenv("WAF_CRS_PROFILE"))
	if err != nil {
		t.Fatal(err)
	}
	fixture.Files = append(fixture.Files, secLangFile{Name: "crs-setup.conf", Source: string(profile)})
	policy, err := prepareSecPoolPolicy(fixture.Files)
	if err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(t.TempDir(), "waf-native-pcre")
	if out, err := exec.Command("go", "build", "-tags", "pcre2", "-o", binary, ".").CombinedOutput(); err != nil {
		t.Fatalf("%s %v", out, err)
	}
	pool := newSecLangPool(binary, 3)
	defer pool.close()
	samples := []string{"GET / HTTP/1.1\r\nHost: protected.example\r\nUser-Agent: SelfGuard-Acceptance\r\nAccept: */*\r\n\r\n", "GET /?q=%3Cscript%3Ealert(1)%3C/script%3E HTTP/1.1\r\nHost: protected.example\r\nUser-Agent: SelfGuard-Acceptance\r\nAccept: */*\r\n\r\n"}
	timings := []float64{}
	started := time.Now()
	for n := 0; n < 50; n++ {
		sample := samples[n%2]
		begin := time.Now()
		result, err := pool.evaluatePolicy(context.Background(), policy, secLangFixture{RequestBase64: base64.StdEncoding.EncodeToString([]byte(sample)), Threshold: 5})
		if err != nil || result.Blocked != (n%2 == 1) {
			t.Fatalf("request %d: %+v %v", n, result, err)
		}
		timings = append(timings, float64(time.Since(begin).Microseconds())/1000)
	}
	sort.Float64s(timings)
	t.Logf("frozen CRS files=%d calls=50 workerStarts=%d total=%s p50=%.3fms p95=%.3fms (local sequential acceptance, not production throughput)", len(fixture.Files), pool.stats(), time.Since(started), timings[24], timings[47])
	if pool.stats() >= 10 {
		t.Fatal("full CRS unexpectedly spawned a worker per request")
	}
}
