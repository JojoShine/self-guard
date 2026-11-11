package main

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const maxHeader = 65536

var accessOperationPattern = regexp.MustCompile(`^[A-Z][A-Z0-9_]{0,31}$`)

var errProtocol = errors.New("protocol framing unsupported")

type Object struct {
	Database string   `json:"database"`
	Schema   string   `json:"schema,omitempty"`
	Table    string   `json:"table,omitempty"`
	Columns  []string `json:"columns"`
}
type PostgresRelation struct {
	Database        string `json:"database"`
	RelationOID     uint32 `json:"relationOid"`
	AttributeNumber int    `json:"attributeNumber"`
}
type Fragment struct {
	Offset uint64 `json:"offset"`
	Bytes  int    `json:"bytes"`
	CallID string `json:"callId"`
}
type Exchange struct {
	EventID           string             `json:"eventId"`
	StartedAt         string             `json:"startedAt"`
	EndedAt           string             `json:"endedAt"`
	SessionID         string             `json:"sessionId"`
	Operation         string             `json:"operation"`
	Route             string             `json:"route,omitempty"`
	SourceIP          string             `json:"sourceIp,omitempty"`
	SourcePort        int                `json:"sourcePort,omitempty"`
	DatabaseUser      string             `json:"databaseUser,omitempty"`
	Database          string             `json:"database,omitempty"`
	Authentication    string             `json:"authentication"`
	Permission        string             `json:"permission"`
	Result            string             `json:"result"`
	Transaction       string             `json:"transaction"`
	StatusCode        int                `json:"statusCode,omitempty"`
	TLS               *bool              `json:"tls,omitempty"`
	Completeness      string             `json:"completeness"`
	Gaps              []string           `json:"gaps"`
	RequestBytes      int64              `json:"requestBytes"`
	ResponseBytes     int64              `json:"responseBytes"`
	Objects           []Object           `json:"objects"`
	Relations         []PostgresRelation `json:"relations,omitempty"`
	Chunks            []Chunk            `json:"chunks"`
	Fragments         []Fragment         `json:"fragments,omitempty"`
	request, response io.Writer
	captureTime       func(string) time.Time
}

func uuid() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic("secure random unavailable")
	}
	b[6] = b[6]&15 | 64
	b[8] = b[8]&63 | 128
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[:4], b[4:6], b[6:8], b[8:10], b[10:])
}
func newExchange(request, response io.Writer) *Exchange {
	return &Exchange{EventID: uuid(), StartedAt: time.Now().UTC().Format(time.RFC3339Nano), SessionID: uuid(), Operation: "UNKNOWN", Authentication: "UNKNOWN", Permission: "UNKNOWN", Result: "UNKNOWN", Transaction: "UNKNOWN", Completeness: "COMPLETE", Gaps: []string{}, Objects: []Object{}, Chunks: []Chunk{}, request: request, response: response}
}
func (e *Exchange) gap(code string) {
	if e.Completeness != "UNSUPPORTED" {
		e.Completeness = "PARTIAL"
	}
	for _, g := range e.Gaps {
		if g == code {
			return
		}
	}
	e.Gaps = append(e.Gaps, code)
}
func (e *Exchange) finish() { e.EndedAt = time.Now().UTC().Format(time.RFC3339Nano) }
func decodeStreams(protocol string, client, server io.Reader, factory func() *Exchange, emit func(*Exchange) error) error {
	c, s := bufio.NewReaderSize(client, maxHeader), bufio.NewReaderSize(server, maxHeader)
	switch protocol {
	case "HTTP":
		return decodeHTTP(c, s, factory, emit)
	case "REDIS":
		return decodeRedis(c, s, factory, emit)
	case "POSTGRESQL":
		return decodePostgres(c, s, factory, emit)
	case "MYSQL":
		return decodeMySQL(c, s, factory, emit)
	default:
		return decodeOpaque(c, s, "PROTOCOL_UNSUPPORTED", factory, emit)
	}
}
func decodeOpaque(c, s *bufio.Reader, gap string, factory func() *Exchange, emit func(*Exchange) error) error {
	e := factory()
	e.Operation = "CONNECTION"
	e.Completeness = "UNSUPPORTED"
	e.gap(gap)
	var err error
	e.RequestBytes, err = io.Copy(e.request, io.LimitReader(c, 262144))
	if err != nil {
		if errors.Is(err, errLineLimit) {
			e.gap("RESOURCE_LIMIT")
		}
		e.gap("DISCONNECTED")
	}
	e.ResponseBytes, err = io.Copy(e.response, io.LimitReader(s, 262144))
	if err != nil {
		if errors.Is(err, errLineLimit) {
			e.gap("RESOURCE_LIMIT")
		}
		e.gap("DISCONNECTED")
	}
	e.gap("RESOURCE_LIMIT")
	e.finish()
	return emit(e)
}
func header(r *bufio.Reader) ([]byte, error) {
	var out []byte
	for len(out) <= maxHeader {
		line, err := r.ReadSlice('\n')
		out = append(out, line...)
		if err != nil {
			return out, err
		}
		if bytes.Equal(line, []byte("\r\n")) {
			return out, nil
		}
	}
	return out, errProtocol
}
func writeBytes(w io.Writer, b []byte) (int64, error) {
	n, err := w.Write(b)
	if err == nil && n != len(b) {
		err = io.ErrShortWrite
	}
	return int64(n), err
}

var errLineLimit = errors.New("RESOURCE_LIMIT")

func boundedLine(r *bufio.Reader, limit int) (string, error) {
	out := make([]byte, 0, min(limit, 4096))
	for len(out) < limit {
		part, err := r.ReadSlice('\n')
		remaining := limit - len(out)
		if len(part) > remaining {
			out = append(out, part[:remaining]...)
			return string(out), errLineLimit
		}
		out = append(out, part...)
		if err == bufio.ErrBufferFull {
			continue
		}
		return string(out), err
	}
	return string(out), errLineLimit
}
func wireBody(r *bufio.Reader, w io.Writer, length int64, chunked bool) (int64, error) {
	if !chunked {
		return io.CopyN(w, r, max(length, 0))
	}
	var total int64
	for {
		line, err := boundedLine(r, 8192)
		n, e := io.WriteString(w, line)
		total += int64(n)
		if e != nil {
			return total, e
		}
		if err != nil {
			return total, err
		}
		size, err := strconv.ParseInt(strings.TrimSpace(strings.SplitN(line, ";", 2)[0]), 16, 64)
		if err != nil || size < 0 {
			return total, errProtocol
		}
		if size == 0 {
			for {
				trailer, err := boundedLine(r, 8192)
				n, e := io.WriteString(w, trailer)
				total += int64(n)
				if e != nil {
					return total, e
				}
				if err != nil {
					return total, err
				}
				if trailer == "\r\n" {
					return total, nil
				}
			}
		}
		n64, err := io.CopyN(w, r, size)
		total += n64
		if err != nil {
			return total, err
		}
		var crlf [2]byte
		if _, err = io.ReadFull(r, crlf[:]); err != nil {
			return total, err
		}
		n64, err = writeBytes(w, crlf[:])
		total += n64
		if err != nil || crlf != [2]byte{'\r', '\n'} {
			return total, errProtocol
		}
	}
}
func decodeHTTP(c, s *bufio.Reader, factory func() *Exchange, emit func(*Exchange) error) error {
	for {
		peek, err := c.Peek(1)
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			return nil
		}
		if err != nil {
			return err
		}
		if peek[0] == 0x16 || peek[0] == 0x17 {
			return decodeOpaque(c, s, "TLS_NO_PLAINTEXT", factory, emit)
		}
		e := factory()
		h, err := header(c)
		e.RequestBytes, _ = writeBytes(e.request, h)
		if err != nil {
			if errors.Is(err, errLineLimit) {
				e.gap("RESOURCE_LIMIT")
			}
			e.gap("PARSE_ERROR")
			e.finish()
			if x := emit(e); x != nil {
				return x
			}
			return nil
		}
		req, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(h)))
		if err != nil {
			e.Completeness = "UNSUPPORTED"
			e.gap("PROTOCOL_UNSUPPORTED")
			e.finish()
			if x := emit(e); x != nil {
				return x
			}
			return nil
		}
		e.Operation = strings.ToUpper(req.Method)
		if !accessOperationPattern.MatchString(e.Operation) {
			e.Operation = "UNKNOWN"
			e.gap("PROTOCOL_UNSUPPORTED")
		}
		e.Route = req.URL.EscapedPath()
		if !strings.HasPrefix(e.Route, "/") {
			e.Route = ""
		}
		if len(e.Route) > 2048 {
			e.Route = ""
			e.gap("RESOURCE_LIMIT")
		}
		n, err := wireBody(c, e.request, req.ContentLength, len(req.TransferEncoding) > 0)
		e.RequestBytes += n
		if err != nil {
			if errors.Is(err, errLineLimit) {
				e.gap("RESOURCE_LIMIT")
			}
			e.gap("DISCONNECTED")
			e.finish()
			if x := emit(e); x != nil {
				return x
			}
			return err
		}
		for {
			h, err = header(s)
			n, writeErr := writeBytes(e.response, h)
			e.ResponseBytes += n
			if err != nil || writeErr != nil {
				if errors.Is(err, errLineLimit) {
					e.gap("RESOURCE_LIMIT")
				}
				e.gap("DISCONNECTED")
				break
			}
			resp, parseErr := http.ReadResponse(bufio.NewReader(bytes.NewReader(h)), req)
			if parseErr != nil {
				if errors.Is(err, errLineLimit) {
					e.gap("RESOURCE_LIMIT")
				}
				e.gap("PARSE_ERROR")
				break
			}
			if resp.StatusCode >= 100 && resp.StatusCode < 200 && resp.StatusCode != 101 {
				continue
			}
			e.StatusCode = resp.StatusCode
			e.Result = "SUCCESS"
			if resp.StatusCode >= 400 {
				e.Result = "FAILURE"
			}
			if resp.StatusCode == 101 || (req.Method == "CONNECT" && resp.StatusCode/100 == 2) {
				e.gap("PROTOCOL_UNSUPPORTED")
				break
			}
			if strings.ToUpper(req.Method) != "HEAD" && resp.StatusCode != 204 && resp.StatusCode != 304 {
				if resp.ContentLength < 0 && len(resp.TransferEncoding) == 0 {
					n, err = io.Copy(e.response, s)
				} else {
					n, err = wireBody(s, e.response, resp.ContentLength, len(resp.TransferEncoding) > 0)
				}
				e.ResponseBytes += n
				if err != nil {
					if errors.Is(err, errLineLimit) {
						e.gap("RESOURCE_LIMIT")
					}
					e.gap("DISCONNECTED")
				}
			}
			break
		}
		e.finish()
		if x := emit(e); x != nil {
			return x
		}
		if e.Completeness != "COMPLETE" {
			return nil
		}
	}
}

type respValue struct {
	kind               byte
	text               string
	arguments          []string
	argumentsTruncated bool
	shortened          bool
	argumentShortened  []bool
}

func respFrame(r *bufio.Reader, w io.Writer, depth int) (respValue, int64, error) {
	var v respValue
	if depth > 32 {
		return v, 0, errProtocol
	}
	line, err := boundedLine(r, maxHeader)
	n, e := io.WriteString(w, line)
	count := int64(n)
	if e != nil {
		return v, count, e
	}
	if err != nil {
		return v, count, err
	}
	if len(line) < 3 || !strings.HasSuffix(line, "\r\n") {
		return v, count, errProtocol
	}
	v.kind = line[0]
	v.text = strings.TrimSuffix(line[1:], "\r\n")
	switch v.kind {
	case '+', '-', ':', ',', '(', '#', '_':
		return v, count, nil
	case '$', '!', '=':
		size, err := strconv.ParseInt(v.text, 10, 64)
		if err != nil || size < -1 || size > 1<<30 {
			return v, count, errProtocol
		}
		if size < 0 {
			return v, count, nil
		}
		prefix := make([]byte, min(size, 128))
		got, err := io.ReadFull(r, prefix)
		if err != nil {
			return v, count, err
		}
		n, e := w.Write(prefix[:got])
		count += int64(n)
		if e != nil {
			return v, count, e
		}
		rest, err := io.CopyN(w, r, size-int64(got))
		count += rest
		if err != nil {
			return v, count, err
		}
		var end [2]byte
		if _, err = io.ReadFull(r, end[:]); err != nil {
			return v, count, err
		}
		written, err := w.Write(end[:])
		count += int64(written)
		if err != nil || end != [2]byte{'\r', '\n'} {
			return v, count, errProtocol
		}
		v.text = string(prefix)
		v.shortened = size > int64(len(prefix))
		return v, count, nil
	case '*', '%', '~', '>', '|':
		size, err := strconv.ParseInt(v.text, 10, 64)
		if err != nil || size < -1 || size > 1000000 {
			return v, count, errProtocol
		}
		if v.kind == '%' || v.kind == '|' {
			size *= 2
		}
		for i := int64(0); i < size; i++ {
			item, n, err := respFrame(r, w, depth+1)
			count += n
			if err != nil {
				return v, count, err
			}
			if len(v.arguments) < 256 {
				v.arguments = append(v.arguments, item.text)
				v.argumentShortened = append(v.argumentShortened, item.shortened)
			} else {
				v.argumentsTruncated = true
			}
		}
		return v, count, nil
	default:
		return v, count, errProtocol
	}
}
func decodeRedis(c, s *bufio.Reader, factory func() *Exchange, emit func(*Exchange) error) error {
	database, user := "0", ""
	for {
		peek, err := c.Peek(1)
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			return nil
		}
		if err != nil {
			return err
		}
		if peek[0] == 0x16 || peek[0] == 0x17 {
			return decodeOpaque(c, s, "TLS_NO_PLAINTEXT", factory, emit)
		}
		e := factory()
		e.Database = database
		e.DatabaseUser = user
		request, n, err := respFrame(c, e.request, 0)
		e.RequestBytes = n
		if err != nil {
			if errors.Is(err, errLineLimit) {
				e.gap("RESOURCE_LIMIT")
			}
			e.gap("PARSE_ERROR")
			e.finish()
			if x := emit(e); x != nil {
				return x
			}
			return nil
		}
		if len(request.arguments) == 0 {
			e.gap("PROTOCOL_UNSUPPORTED")
		} else {
			e.Operation = strings.ToUpper(request.arguments[0])
			if !accessOperationPattern.MatchString(e.Operation) {
				e.Operation = "UNKNOWN"
				e.gap("PROTOCOL_UNSUPPORTED")
			}
		}

		redisObjects(e, request, database)

		if e.Operation == "SELECT" {
			e.Operation = "SELECT_DB"
		}
		for {
			peek, pErr := s.Peek(1)
			if pErr != nil {
				if errors.Is(err, errLineLimit) {
					e.gap("RESOURCE_LIMIT")
				}
				e.gap("DISCONNECTED")
				err = pErr
				break
			}
			if peek[0] == '>' {
				push := factory()
				push.Operation = "PUSH"
				_, push.ResponseBytes, pErr = respFrame(s, push.response, 0)
				push.gap("CORRELATION_UNKNOWN")
				push.finish()
				if x := emit(push); x != nil {
					return x
				}
				if pErr != nil {
					if errors.Is(err, errLineLimit) {
						e.gap("RESOURCE_LIMIT")
					}
					e.gap("DISCONNECTED")
					err = pErr
					break
				}
				continue
			}
			var response respValue
			response, n, err = respFrame(s, e.response, 0)
			e.ResponseBytes += n
			if err != nil {
				if errors.Is(err, errLineLimit) {
					e.gap("RESOURCE_LIMIT")
				}
				e.gap("DISCONNECTED")
				break
			}
			if response.kind == '|' {
				continue
			}
			e.Result = "SUCCESS"
			if response.kind == '-' || response.kind == '!' {
				e.Result = "FAILURE"
				if strings.HasPrefix(response.text, "NOPERM") {
					e.Permission = "DENIED"
				}
				if strings.HasPrefix(response.text, "WRONGPASS") || strings.HasPrefix(response.text, "NOAUTH") {
					e.Authentication = "FAILURE"
				}
			}
			if response.kind == '+' && response.text == "QUEUED" {
				e.Result = "UNKNOWN"
			}
			if e.Operation == "AUTH" {
				e.Authentication = e.Result
				if e.Result == "SUCCESS" {
					user = "default"
					if len(request.arguments) > 2 {
						user = request.arguments[1]
					}
					e.DatabaseUser = user
				}
			}
			if e.Operation == "HELLO" {
				account, auth, known := redisHelloAccount(request)
				if !known {
					e.gap("RESOURCE_LIMIT")
					if e.Result == "SUCCESS" {
						user = ""
						e.DatabaseUser = ""
					}
				} else if auth {
					e.Authentication = e.Result
					if e.Result == "SUCCESS" {
						user = account
						e.DatabaseUser = user
					}
				}
			}
			if e.Operation == "SELECT_DB" && e.Result == "SUCCESS" && len(request.arguments) > 1 {
				database = request.arguments[1]
			}
			if e.Operation == "EXEC" {
				e.gap("CORRELATION_UNKNOWN")
				e.Result = "UNKNOWN"
			}
			break
		}
		e.finish()
		if x := emit(e); x != nil {
			return x
		}
		if err != nil {
			return nil
		}
	}
}
