package main

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
)

func redisCommand(args ...string) []byte {
	var b bytes.Buffer
	fmt.Fprintf(&b, "*%d\r\n", len(args))
	for _, arg := range args {
		fmt.Fprintf(&b, "$%d\r\n%s\r\n", len(arg), arg)
	}
	return b.Bytes()
}
func TestRedisMultiKeyClassificationNeverIndexesValues(t *testing.T) {
	for _, args := range [][]string{{"MGET", "public:1", "secret:1"}, {"MSET", "public:1", "password:must-not-be-object", "secret:1", "token:must-not-be-object"}, {"DEL", "public:1", "secret:1"}} {
		events, err := decodeExchange("REDIS", redisCommand(args...), []byte("+OK\r\n"))
		if err != nil || len(events) != 1 || len(events[0].Objects) != 2 || events[0].Objects[1].Table != "secret:*" {
			t.Fatalf("multi-key object coverage: %v %+v", err, events)
		}
		for _, obj := range events[0].Objects {
			if obj.Table == "password:*" || obj.Table == "token:*" {
				t.Fatal("value leaked into classification")
			}
		}
	}
}
func TestRedisHelloAuthTracksAccountAndDoesNotTreatHelloAsDataAccess(t *testing.T) {
	request := append(redisCommand("HELLO", "3", "AUTH", "app", "synthetic-password"), redisCommand("GET", "secret:1")...)
	response := []byte("%1\r\n+proto\r\n:3\r\n$1\r\nx\r\n")
	events, err := decodeExchange("REDIS", request, response)
	if err != nil || len(events) != 2 || events[0].Authentication != "SUCCESS" || events[1].DatabaseUser != "app" {
		t.Fatalf("HELLO account lost: %v %+v", err, events)
	}
}
func TestRedisUncapturedKeysAreMarkedAsCoverageGap(t *testing.T) {
	args := []string{"MGET"}
	for i := 0; i < 300; i++ {
		args = append(args, fmt.Sprintf("namespace%d:key", i))
	}
	events, err := decodeExchange("REDIS", redisCommand(args...), []byte("+OK\r\n"))
	if err != nil || len(events) != 1 || events[0].Completeness != "PARTIAL" {
		t.Fatalf("bounded objects must mark missing coverage: %v %+v", err, events)
	}
}

func TestRedisHelloConsumesOptionValuesBeforeInterpretingAUTH(t *testing.T) {
	request := append(redisCommand("HELLO", "3", "SETNAME", "AUTH", "AUTH", "actualuser", "synthetic-password"), redisCommand("GET", "secret:1")...)
	events, err := decodeExchange("REDIS", request, []byte("%1\r\n+proto\r\n:3\r\n$1\r\nx\r\n"))
	if err != nil || len(events) != 2 || events[0].DatabaseUser != "actualuser" || events[1].DatabaseUser != "actualuser" {
		t.Fatal("SETNAME value was treated as AUTH option")
	}
}
func TestRedisOverlongNamespaceReportsMissingClassificationCoverage(t *testing.T) {
	for _, size := range []int{120, 130} {
		key := strings.Repeat("x", size) + ":1"
		events, err := decodeExchange("REDIS", redisCommand("MGET", "public:1", key), []byte("+OK\r\n"))
		if err != nil || len(events) != 1 || events[0].Completeness != "PARTIAL" {
			t.Fatal("overlong namespace silently dropped")
		}
	}
}
