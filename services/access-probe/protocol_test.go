package main

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"regexp"
	"strings"
	"testing"
)

type capturedExchange struct {
	*Exchange
	Request, Response []byte
}

func decodeExchange(protocol string, request, response []byte) ([]capturedExchange, error) {
	var events []capturedExchange
	err := decodeStreams(protocol, bytes.NewReader(request), bytes.NewReader(response), func() *Exchange { return newExchange(new(bytes.Buffer), new(bytes.Buffer)) }, func(e *Exchange) error {
		events = append(events, capturedExchange{e, append([]byte{}, e.request.(*bytes.Buffer).Bytes()...), append([]byte{}, e.response.(*bytes.Buffer).Bytes()...)})
		return nil
	})
	return events, err
}

func TestHTTPPairsEveryActualRequestAndPreservesBinaryLargeResponse(t *testing.T) {
	payload := bytes.Repeat([]byte{0, 255, 1, 2}, 100000)
	request := []byte("GET /api/orders?token=synthetic HTTP/1.1\r\nHost: fixture\r\n\r\n")
	response := append([]byte(fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n", len(payload))), payload...)
	events, err := decodeExchange("HTTP", append(append([]byte{}, request...), request...), append(append([]byte{}, response...), response...))
	if err != nil || len(events) != 2 {
		t.Fatalf("two real accesses required, got %d %v", len(events), err)
	}
	for _, e := range events {
		if e.Route != "/api/orders" || !bytes.Equal(e.Request, request) || !bytes.Equal(e.Response, response) || e.Result != "SUCCESS" {
			t.Fatal("request/response mismatch or query leaked to path index")
		}
	}
}
func TestHTTPFailureAndChunkedAndMissingResponse(t *testing.T) {
	request := []byte("POST /login HTTP/1.1\r\nHost: fixture\r\nContent-Length: 2\r\n\r\n{}")
	response := []byte("HTTP/1.1 403 Forbidden\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nbad\r\n0\r\n\r\n")
	events, err := decodeExchange("HTTP", request, response)
	if err != nil || len(events) != 1 || events[0].Permission != "UNKNOWN" || events[0].Authentication != "UNKNOWN" || events[0].Result != "FAILURE" || !bytes.Equal(events[0].Response, response) {
		t.Fatal("failed request must remain auditable", err)
	}
	events, _ = decodeExchange("HTTP", request, nil)
	if len(events) != 1 || events[0].Completeness != "PARTIAL" {
		t.Fatal("missing response cannot be called complete")
	}
}
func TestRedisPipelineSeparatesPushesAndPreservesErrorsAndRepeatedCommands(t *testing.T) {
	request := []byte("*2\r\n$3\r\nGET\r\n$3\r\nkey\r\n*2\r\n$3\r\nGET\r\n$3\r\nkey\r\n")
	response := []byte(">2\r\n+notice\r\n+hello\r\n$3\r\none\r\n-NOPERM denied\r\n")
	events, err := decodeExchange("REDIS", request, response)
	if err != nil || len(events) != 3 {
		t.Fatal("push must be separate from two accesses", len(events), err)
	}
	if events[0].Operation != "PUSH" || len(events[0].Request) != 0 || events[1].Operation != "GET" || string(events[1].Response) != "$3\r\none\r\n" || len(events[1].Request) == 0 || events[2].Permission != "DENIED" {
		t.Fatal("pipeline response pairing incorrect")
	}
}
func TestEncryptedAndUnsupportedStreamsAreNeverComplete(t *testing.T) {
	events, _ := decodeExchange("HTTP", []byte{0x16, 3, 3, 0, 5, 1, 2, 3, 4, 5}, nil)
	if len(events) != 1 || events[0].Completeness != "UNSUPPORTED" || events[0].Gaps[0] != "TLS_NO_PLAINTEXT" {
		t.Fatal("TLS evidence needs explicit gap")
	}
	events, _ = decodeExchange("ORACLE", []byte("opaque"), nil)
	if len(events) != 1 || events[0].Completeness != "UNSUPPORTED" {
		t.Fatal("unimplemented protocol cannot claim coverage")
	}
}
func pgMessage(kind byte, payload []byte) []byte {
	b := make([]byte, 5)
	b[0] = kind
	binary.BigEndian.PutUint32(b[1:], uint32(len(payload)+4))
	return append(b, payload...)
}
func mysqlPacket(sequence byte, payload []byte) []byte {
	return append([]byte{byte(len(payload)), byte(len(payload) >> 8), byte(len(payload) >> 16), sequence}, payload...)
}
func TestPostgresRetainsLoginRepeatedQueryAndPermissionFailure(t *testing.T) {
	startup := append([]byte{0, 0, 0, 0, 0, 3, 0, 0}, []byte("user\x00app\x00database\x00db\x00\x00")...)
	binary.BigEndian.PutUint32(startup, uint32(len(startup)))
	query := pgMessage('Q', []byte("SELECT 1\x00"))
	request := append(append(append([]byte{}, startup...), query...), query...)
	login := append(pgMessage('R', []byte{0, 0, 0, 0}), pgMessage('Z', []byte{'I'})...)
	first := append(pgMessage('D', []byte{0, 1, 0, 0, 0, 1, '1'}), pgMessage('C', []byte("SELECT 1\x00"))...)
	first = append(first, pgMessage('Z', []byte{'I'})...)
	last := append(pgMessage('E', []byte("SERROR\x00C42501\x00Mpermission denied\x00\x00")), pgMessage('Z', []byte{'I'})...)
	events, err := decodeExchange("POSTGRESQL", request, append(append(login, first...), last...))
	if err != nil || len(events) != 3 {
		t.Fatal("PG access boundary", len(events), err)
	}
	if events[0].Authentication != "SUCCESS" || events[0].DatabaseUser != "app" || events[1].Result != "SUCCESS" || !bytes.Equal(events[1].Response, first) || events[2].Permission != "DENIED" || events[2].Result != "FAILURE" {
		t.Fatal("PG response semantics incorrect")
	}
}
func TestMySQLRetainsLoginAndTwoRealResultSets(t *testing.T) {
	hello := mysqlPacket(0, []byte("\x0a5.7-fixture\x00"))
	credentials := make([]byte, 32)
	binary.LittleEndian.PutUint32(credentials, 0x200)
	credentials = append(credentials, []byte("app\x00\x00")...)
	login := mysqlPacket(1, credentials)
	query := mysqlPacket(0, append([]byte{3}, []byte("SELECT 1")...))
	request := append(append(login, query...), query...)
	auth := mysqlPacket(2, []byte{0, 0, 0, 2, 0, 0, 0})
	end := []byte{0xfe, 0, 0, 2, 0}
	result := mysqlPacket(1, []byte{1})
	for sequence, payload := range [][]byte{[]byte("\x03def\x02db\x05users\x05users\x02id\x02id"), end, []byte{1, '1'}, end} {
		result = append(result, mysqlPacket(byte(sequence+2), payload)...)
	}
	events, err := decodeExchange("MYSQL", request, append(append(append(hello, auth...), result...), result...))
	if err != nil || len(events) != 3 {
		t.Fatal("MySQL access boundary", len(events), err)
	}
	if events[0].Authentication != "SUCCESS" || events[0].DatabaseUser != "app" || events[1].Operation != "SELECT" || events[1].Result != "SUCCESS" || !bytes.Equal(events[1].Response, result) || !bytes.Equal(events[2].Response, result) {
		t.Fatal("MySQL result framing incorrect")
	}
}
func TestRedisQueuedCommandIsNotReportedAsExecutedAndObjectsUseNamespaces(t *testing.T) {
	request := []byte("*1\r\n$5\r\nMULTI\r\n*2\r\n$3\r\nGET\r\n$9\r\nsg:user:1\r\n*1\r\n$4\r\nEXEC\r\n")
	events, err := decodeExchange("REDIS", request, []byte("+OK\r\n+QUEUED\r\n*1\r\n$3\r\none\r\n"))
	if err != nil || len(events) != 3 {
		t.Fatal("transaction capture", err)
	}
	if events[1].Result != "UNKNOWN" {
		t.Fatal("QUEUED is not execution success")
	}
	if len(events[1].Objects) != 1 || events[1].Objects[0].Table != "sg:*" {
		t.Fatal("namespace object missing")
	}
}
func TestMySQLQueryAttributesWithoutParametersDoNotLoseOperation(t *testing.T) {
	hello := mysqlPacket(0, []byte("\x0a8.4-fixture\x00"))
	credentials := make([]byte, 32)
	binary.LittleEndian.PutUint32(credentials, 0x08000200)
	credentials = append(credentials, []byte("app\x00\x00")...)
	request := append(mysqlPacket(1, credentials), mysqlPacket(0, append([]byte{3, 0, 1}, []byte("SELECT 1")...))...)
	auth := mysqlPacket(2, []byte{0, 0, 0, 2, 0, 0, 0})
	response := append(append(hello, auth...), mysqlPacket(1, []byte{0, 0, 0, 2, 0, 0, 0})...)
	events, err := decodeExchange("MYSQL", request, response)
	if err != nil || len(events) != 2 || events[1].Operation != "SELECT" || events[1].Completeness != "COMPLETE" {
		t.Fatal("zero-attribute query must decode normally", err)
	}
}

func TestHTTPMethodsAndAsteriskTargetCannotPoisonTheEvidenceQueue(t *testing.T) {
	for _, request := range []string{"M-SEARCH /service HTTP/1.1\r\nHost: fixture\r\n\r\n", "get /service HTTP/1.1\r\nHost: fixture\r\n\r\n", "OPTIONS * HTTP/1.1\r\nHost: fixture\r\n\r\n"} {
		events, err := decodeExchange("HTTP", []byte(request), []byte("HTTP/1.1 204 No Content\r\n\r\n"))
		if err != nil || len(events) != 1 {
			t.Fatal("valid method lost", err)
		}
		if !regexp.MustCompile(`^[A-Z][A-Z0-9_]{0,31}$`).MatchString(events[0].Operation) {
			t.Fatal("operation violates ingest contract", events[0].Operation)
		}
		if events[0].Route != "" && !strings.HasPrefix(events[0].Route, "/") {
			t.Fatal("non-path request target indexed as path")
		}
	}
}

func TestRedisInvalidCommandIsStillDeliverableEvidence(t *testing.T) {
	events, err := decodeExchange("REDIS", []byte("*1\r\n$7\r\nBAD-CMD\r\n"), []byte("-ERR unknown command\r\n"))
	if err != nil || len(events) != 1 {
		t.Fatal(err)
	}
	if !accessOperationPattern.MatchString(events[0].Operation) || events[0].Result != "FAILURE" || !bytes.Contains(events[0].Request, []byte("BAD-CMD")) {
		t.Fatal("invalid command poisons delivery", events[0].Operation)
	}
}

type longUnterminatedLine struct {
	read    int
	maximum int
}

func (r *longUnterminatedLine) Read(out []byte) (int, error) {
	if r.read >= r.maximum {
		return 0, io.EOF
	}
	n := min(len(out), r.maximum-r.read)
	for i := 0; i < n; i++ {
		out[i] = 'X'
	}
	r.read += n
	return n, nil
}
func TestProtocolLimitsStopReadingBeforeAccumulatingUnboundedLines(t *testing.T) {
	source := &longUnterminatedLine{maximum: 1 << 20}
	_, _ = wireBody(bufio.NewReaderSize(source, 4096), io.Discard, 0, true)
	if source.read > 12288 {
		t.Fatal("chunk line consumed beyond its bounded allocation", source.read)
	}
	source = &longUnterminatedLine{maximum: 1 << 20}
	_, _, _ = respFrame(bufio.NewReaderSize(io.MultiReader(strings.NewReader("$"), source), 4096), io.Discard, 0)
	if source.read > maxHeader+4096 {
		t.Fatal("RESP line consumed without a bound", source.read)
	}
}

func TestOversizedHTTPPathRemainsUnknownRatherThanInventingRoot(t *testing.T) {
	path := "/" + strings.Repeat("a", 2048)
	events, err := decodeExchange("HTTP", []byte("GET "+path+" HTTP/1.1\r\nHost: fixture\r\n\r\n"), []byte("HTTP/1.1 204 No Content\r\n\r\n"))
	if err != nil || len(events) != 1 {
		t.Fatal(err)
	}
	if events[0].Route != "" || !bytes.Contains(events[0].Request, []byte(path)) || events[0].Completeness != "PARTIAL" {
		t.Fatal("oversized observed path replaced or lost", events[0].Route)
	}
}
