package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestNativePreparedAndRedisCoverage(t *testing.T) {
	root := os.Getenv("SELFGUARD_NATIVE_COVERAGE")
	if root == "" {
		t.Skip("requires isolated real database transcripts")
	}
	for _, engine := range []struct{ name, protocol string }{{"mysql", "MYSQL"}, {"redis", "REDIS"}} {
		request, err := os.ReadFile(filepath.Join(root, engine.name+"-request.bin"))
		if err != nil {
			t.Fatal(err)
		}
		response, err := os.ReadFile(filepath.Join(root, engine.name+"-response.bin"))
		if err != nil {
			t.Fatal(err)
		}
		events, err := decodeExchange(engine.protocol, request, response)
		if err != nil {
			t.Fatalf("%s native decoding: %v", engine.name, err)
		}
		var allRequest, allResponse []byte
		matched := 0
		for _, e := range events {
			allRequest = append(allRequest, e.Request...)
			allResponse = append(allResponse, e.Response...)
			if e.Completeness != "COMPLETE" {
				t.Fatalf("%s %s incomplete: %v", engine.name, e.Operation, e.Gaps)
			}
			if engine.name == "mysql" && e.Operation == "SELECT" {
				matched++
				if e.Result != "SUCCESS" || len(e.Objects) == 0 || e.Objects[0].Table != "users" {
					t.Fatal("prepared select object/result missing")
				}
			}
			if engine.name == "redis" && e.Operation == "MGET" {
				matched++
				if e.DatabaseUser != "default" || len(e.Objects) != 2 || e.Objects[1].Table != "secret:*" {
					t.Fatal("RESP3 multi-key association missing")
				}
			}
		}
		if !bytes.Equal(request, allRequest) || !bytes.Equal(response, allResponse) {
			t.Fatalf("%s native wire bytes were lost or reassigned", engine.name)
		}
		expected := 1
		if engine.name == "mysql" {
			expected = 2
		}
		if matched != expected {
			t.Fatalf("%s operation count %d expected %d", engine.name, matched, expected)
		}
	}
}
