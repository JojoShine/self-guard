package main

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"io"
	"strings"
)

type protocolFrame struct {
	kind     byte
	prefix   []byte
	length   int64
	sequence byte
	written  int64
}

func pgRead(r *bufio.Reader, w io.Writer, startup bool) (protocolFrame, error) {
	var f protocolFrame
	headerSize := 5
	if startup {
		headerSize = 4
	}
	h := make([]byte, headerSize)
	if _, err := io.ReadFull(r, h); err != nil {
		return f, err
	}
	written, writeErr := writeBytes(w, h)
	f.written = written
	if writeErr != nil {
		return f, writeErr
	}
	offset := 1
	if startup {
		offset = 0
	} else {
		f.kind = h[0]
	}
	size := int64(binary.BigEndian.Uint32(h[offset:]))
	if size < 4 || size > 1<<30 {
		return f, errProtocol
	}
	f.length = size - 4
	f.prefix = make([]byte, min(f.length, 65536))
	n, err := io.ReadFull(r, f.prefix)
	if n > 0 {
		written, e := writeBytes(w, f.prefix[:n])
		f.written += written
		if e != nil {
			return f, e
		}
	}
	if err != nil {
		return f, err
	}
	rest, err := io.CopyN(w, r, f.length-int64(n))
	f.written += rest
	return f, err
}
func pgResultReferences(e *Exchange, payload []byte, length int64) {
	if int64(len(payload)) != length || len(payload) < 2 {
		e.gap("PARSE_ERROR")
		return
	}
	count := int(binary.BigEndian.Uint16(payload))
	payload = payload[2:]
	if count > 128 {
		e.gap("RESOURCE_LIMIT")
		return
	}
	for i := 0; i < count; i++ {
		end := bytes.IndexByte(payload, 0)
		if end < 0 || len(payload) < end+19 {
			e.gap("PARSE_ERROR")
			return
		}
		field := payload[end+1:]
		oid := binary.BigEndian.Uint32(field)
		attribute := int(int16(binary.BigEndian.Uint16(field[4:])))
		payload = field[18:]
		if oid == 0 || attribute <= 0 || e.Database == "" {
			e.gap("CORRELATION_UNKNOWN")
			continue
		}
		reference := PostgresRelation{Database: e.Database, RelationOID: oid, AttributeNumber: attribute}
		duplicate := false
		for _, prior := range e.Relations {
			if prior == reference {
				duplicate = true
				break
			}
		}
		if !duplicate {
			if len(e.Relations) >= 128 {
				e.gap("RESOURCE_LIMIT")
			} else {
				e.Relations = append(e.Relations, reference)
			}
		}
	}
	if len(payload) != 0 {
		e.gap("PARSE_ERROR")
	}
}
func pgError(e *Exchange, payload []byte) {
	e.Result = "FAILURE"
	for len(payload) > 1 {
		kind := payload[0]
		at := bytes.IndexByte(payload[1:], 0)
		if at < 0 {
			break
		}
		field := string(payload[1 : 1+at])
		if kind == 'C' {
			if field == "42501" {
				e.Permission = "DENIED"
			}
			if strings.HasPrefix(field, "28") {
				e.Authentication = "FAILURE"
			}
		}
		payload = payload[at+2:]
	}
}
func pgServerUntilReady(c, s *bufio.Reader, e *Exchange, login bool) error {
	for {
		f, err := pgRead(s, e.response, false)
		e.ResponseBytes += f.written
		if err != nil {
			return err
		}
		switch f.kind {
		case 'T':
			pgResultReferences(e, f.prefix, f.length)
		case 'R':
			if len(f.prefix) < 4 {
				return errProtocol
			}
			code := binary.BigEndian.Uint32(f.prefix)
			if code == 0 {
				e.Authentication = "SUCCESS"
				e.Result = "SUCCESS"
			} else if code != 12 {
				client, err := pgRead(c, e.request, false)
				e.RequestBytes += client.written
				if err != nil {
					return err
				}
				if client.kind != 'p' {
					e.gap("PROTOCOL_UNSUPPORTED")
					return errProtocol
				}
			}
		case 'E':
			pgError(e, f.prefix)
			if login {
				return nil
			}
		case 'C':
			if e.Result != "FAILURE" {
				e.Result = "SUCCESS"
			}
			tag := strings.SplitN(strings.TrimRight(string(f.prefix), "\x00"), " ", 2)[0]
			if tag == "COMMIT" {
				e.Transaction = "COMMITTED"
			}
			if tag == "ROLLBACK" {
				e.Transaction = "ROLLED_BACK"
			}
			if e.Operation == "QUERY" && tag != "" && len(tag) <= 32 {
				e.Operation = tag
			}
		case 'I':
			if e.Result != "FAILURE" {
				e.Result = "SUCCESS"
			}
		case 'Z':
			return nil
		case 'G':
			for {
				part, err := pgRead(c, e.request, false)
				e.RequestBytes += part.written
				if err != nil {
					return err
				}
				if part.kind == 'c' || part.kind == 'f' {
					break
				}
				if part.kind != 'd' {
					return errProtocol
				}
			}
		case 'W':
			e.gap("PROTOCOL_UNSUPPORTED")
			return errProtocol
		}
	}
}
func decodePostgres(c, s *bufio.Reader, factory func() *Exchange, emit func(*Exchange) error) error {
	user, database := "", ""
	peek, err := c.Peek(1)
	if err == io.EOF {
		return nil
	}
	if err != nil {
		return err
	}
	if peek[0] == 0x16 || peek[0] == 0x17 {
		return decodeOpaque(c, s, "TLS_NO_PLAINTEXT", factory, emit)
	}
	if peek[0] == 0 {
		e := factory()
		e.Operation = "LOGIN"
		startup, err := pgRead(c, e.request, true)
		e.RequestBytes += startup.written
		if err != nil {
			e.gap("PARSE_ERROR")
			e.finish()
			if x := emit(e); x != nil {
				return x
			}
			return nil
		}
		if len(startup.prefix) < 4 {
			return errProtocol
		}
		version := binary.BigEndian.Uint32(startup.prefix)
		if version == 80877103 {
			b, err := s.ReadByte()
			if err != nil {
				return err
			}
			n, err := e.response.Write([]byte{b})
			e.ResponseBytes += int64(n)
			if err != nil {
				return err
			}
			if b == 'S' {
				e.Completeness = "UNSUPPORTED"
				e.gap("TLS_NO_PLAINTEXT")
				e.finish()
				if x := emit(e); x != nil {
					return x
				}
				return decodeOpaque(c, s, "TLS_NO_PLAINTEXT", factory, emit)
			}
			if b != 'N' {
				return errProtocol
			}
			startup, err = pgRead(c, e.request, true)
			e.RequestBytes += startup.written
			if err != nil {
				return err
			}
			if len(startup.prefix) < 4 {
				return errProtocol
			}
			version = binary.BigEndian.Uint32(startup.prefix)
		}
		if version != 196608 {
			e.Completeness = "UNSUPPORTED"
			e.gap("PROTOCOL_UNSUPPORTED")
			e.finish()
			return emit(e)
		}
		fields := bytes.Split(startup.prefix[4:], []byte{0})
		for i := 0; i+1 < len(fields); i += 2 {
			if string(fields[i]) == "user" && len(fields[i+1]) <= 128 {
				user = string(fields[i+1])
			}
			if string(fields[i]) == "database" && len(fields[i+1]) <= 128 {
				database = string(fields[i+1])
			}
		}
		e.DatabaseUser = user
		e.Database = database
		if err = pgServerUntilReady(c, s, e, true); err != nil {
			e.gap("DISCONNECTED")
		}
		e.finish()
		if x := emit(e); x != nil {
			return x
		}
		if err != nil || e.Authentication == "FAILURE" {
			return nil
		}
	}
	for {
		_, err := c.Peek(1)
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		e := factory()
		e.DatabaseUser = user
		e.Database = database
		e.Operation = "QUERY"
		request, err := pgRead(c, e.request, false)
		e.RequestBytes += request.written
		if err != nil {
			e.gap("DISCONNECTED")
			e.finish()
			if x := emit(e); x != nil {
				return x
			}
			return nil
		}
		if request.kind == 'X' {
			e.Operation = "DISCONNECT"
			e.Result = "UNKNOWN"
			e.finish()
			return emit(e)
		}
		if request.kind != 'Q' {
			e.Operation = "EXTENDED_BATCH"
			e.gap("CORRELATION_UNKNOWN")
			for request.kind != 'S' {
				request, err = pgRead(c, e.request, false)
				e.RequestBytes += request.written
				if err != nil {
					break
				}
			}
		}
		if err == nil {
			err = pgServerUntilReady(c, s, e, false)
		}
		if err != nil {
			e.gap("DISCONNECTED")
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
