package main

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"io"
	"strings"
)

func mysqlRead(r *bufio.Reader, w io.Writer) (protocolFrame, error) {
	var f protocolFrame
	for {
		var h [4]byte
		if _, err := io.ReadFull(r, h[:]); err != nil {
			return f, err
		}
		length := int64(h[0]) | int64(h[1])<<8 | int64(h[2])<<16
		if f.length == 0 {
			f.sequence = h[3]
		}
		n, err := writeBytes(w, h[:])
		f.written += n
		if err != nil {
			return f, err
		}
		prefix := make([]byte, min(length, int64(max(0, 65536-len(f.prefix)))))
		read, err := io.ReadFull(r, prefix)
		if read > 0 {
			n, e := writeBytes(w, prefix[:read])
			f.written += n
			f.prefix = append(f.prefix, prefix[:read]...)
			if e != nil {
				return f, e
			}
		}
		if err != nil {
			return f, err
		}
		n, err = io.CopyN(w, r, length-int64(read))
		f.written += n
		f.length += length
		if err != nil {
			return f, err
		}
		if length != 0xffffff {
			return f, nil
		}
	}
}
func mysqlLenenc(b []byte) (uint64, int, bool) {
	if len(b) == 0 {
		return 0, 0, false
	}
	switch b[0] {
	case 0xfc:
		if len(b) < 3 {
			return 0, 0, false
		}
		return uint64(binary.LittleEndian.Uint16(b[1:])), 3, true
	case 0xfd:
		if len(b) < 4 {
			return 0, 0, false
		}
		return uint64(b[1]) | uint64(b[2])<<8 | uint64(b[3])<<16, 4, true
	case 0xfe:
		if len(b) < 9 {
			return 0, 0, false
		}
		return binary.LittleEndian.Uint64(b[1:]), 9, true
	case 0xfb, 0xff:
		return 0, 1, false
	default:
		return uint64(b[0]), 1, true
	}
}
func mysqlStatus(f protocolFrame) (uint16, bool) {
	b := f.prefix
	if len(b) == 0 {
		return 0, false
	}
	if b[0] == 0xfe && f.length < 9 {
		if len(b) < 5 {
			return 0, false
		}
		return binary.LittleEndian.Uint16(b[3:]), true
	}
	if b[0] != 0 && b[0] != 0xfe {
		return 0, false
	}
	_, n, ok := mysqlLenenc(b[1:])
	if !ok {
		return 0, false
	}
	offset := 1 + n
	if offset >= len(b) {
		return 0, false
	}
	_, n, ok = mysqlLenenc(b[offset:])
	offset += n
	if !ok || offset+2 > len(b) {
		return 0, false
	}
	return binary.LittleEndian.Uint16(b[offset:]), true
}
func mysqlError(e *Exchange, f protocolFrame) {
	e.Result = "FAILURE"
	if len(f.prefix) < 3 {
		return
	}
	code := binary.LittleEndian.Uint16(f.prefix[1:])
	if code == 1045 {
		e.Authentication = "FAILURE"
	}
	if code == 1044 || code == 1142 || code == 1143 || code == 1227 {
		e.Permission = "DENIED"
	}
}
func mysqlResponse(s *bufio.Reader, e *Exchange, capabilities uint32) error {
	for {
		f, err := mysqlRead(s, e.response)
		e.ResponseBytes += f.written
		if err != nil {
			return err
		}
		if len(f.prefix) == 0 {
			return errProtocol
		}
		if f.prefix[0] == 0xff {
			mysqlError(e, f)
			return nil
		}
		if f.prefix[0] == 0 {
			e.Result = "SUCCESS"
			status, ok := mysqlStatus(f)
			if !ok {
				return errProtocol
			}
			if status&8 != 0 {
				continue
			}
			return nil
		}
		if f.prefix[0] == 0xfb {
			e.gap("PROTOCOL_UNSUPPORTED")
			return errProtocol
		}
		columns, _, ok := mysqlLenenc(f.prefix)
		if !ok || columns > 4096 {
			return errProtocol
		}
		for i := uint64(0); i < columns; i++ {
			column, err := mysqlRead(s, e.response)
			e.ResponseBytes += column.written
			if err != nil {
				return err
			}
			mysqlColumn(e, column.prefix)
		}
		if capabilities&0x01000000 == 0 {
			end, err := mysqlRead(s, e.response)
			e.ResponseBytes += end.written
			if err != nil {
				return err
			}
			if len(end.prefix) == 0 || end.prefix[0] != 0xfe || end.length >= 9 {
				return errProtocol
			}
		}
		for {
			row, err := mysqlRead(s, e.response)
			e.ResponseBytes += row.written
			if err != nil {
				return err
			}
			if len(row.prefix) == 0 {
				return errProtocol
			}
			if row.prefix[0] == 0xff {
				mysqlError(e, row)
				return nil
			}
			if row.prefix[0] == 0xfe && row.length < 0xffffff {
				status, ok := mysqlStatus(row)
				if !ok {
					return errProtocol
				}
				e.Result = "SUCCESS"
				if status&8 != 0 {
					break
				}
				return nil
			}
		}
	}
}
func mysqlColumn(e *Exchange, b []byte) {
	fields := make([]string, 0, 6)
	for i := 0; i < 6; i++ {
		length, n, ok := mysqlLenenc(b)
		if !ok || length > 128 || uint64(len(b)-n) < length {
			return
		}
		fields = append(fields, string(b[n:n+int(length)]))
		b = b[n+int(length):]
	}
	if fields[1] == "" || fields[3] == "" {
		return
	}
	object := Object{Database: fields[1], Table: fields[3], Columns: []string{}}
	if fields[5] != "" {
		object.Columns = []string{fields[5]}
	}
	for i := range e.Objects {
		if e.Objects[i].Database == object.Database && e.Objects[i].Table == object.Table {
			if len(e.Objects[i].Columns) < 128 {
				e.Objects[i].Columns = append(e.Objects[i].Columns, object.Columns...)
			}
			return
		}
	}
	if len(e.Objects) < 32 {
		e.Objects = append(e.Objects, object)
	}
}

// Prepared metadata is consumed independently from normal result sets.
func mysqlPrepareResponse(s *bufio.Reader, e *Exchange, capabilities uint32) (uint32, error) {
	f, err := mysqlRead(s, e.response)
	e.ResponseBytes += f.written
	if err != nil {
		return 0, err
	}
	if len(f.prefix) > 0 && f.prefix[0] == 0xff {
		mysqlError(e, f)
		return 0, nil
	}
	if len(f.prefix) < 12 || f.prefix[0] != 0 {
		return 0, errProtocol
	}
	id := binary.LittleEndian.Uint32(f.prefix[1:])
	columns, params := int(binary.LittleEndian.Uint16(f.prefix[5:])), int(binary.LittleEndian.Uint16(f.prefix[7:]))
	if columns > 4096 || params > 4096 {
		return 0, errProtocol
	}
	for group, count := range []int{params, columns} {
		for i := 0; i < count; i++ {
			field, err := mysqlRead(s, e.response)
			e.ResponseBytes += field.written
			if err != nil {
				return 0, err
			}
			if len(field.prefix) == 0 || field.prefix[0] == 0xff {
				return 0, errProtocol
			}
			if group == 1 {
				mysqlColumn(e, field.prefix)
			}
		}
		if count > 0 && capabilities&0x01000000 == 0 {
			end, err := mysqlRead(s, e.response)
			e.ResponseBytes += end.written
			if err != nil {
				return 0, err
			}
			if _, ok := mysqlStatus(end); !ok || len(end.prefix) == 0 || end.prefix[0] != 0xfe || end.length >= 9 {
				return 0, errProtocol
			}
		}
	}
	e.Result = "SUCCESS"
	return id, nil
}
func mysqlQueryOperation(query []byte) string {
	fields := strings.Fields(string(query))
	if len(fields) == 0 {
		return "QUERY"
	}
	op := strings.ToUpper(strings.TrimSuffix(fields[0], ";"))
	for _, known := range []string{"SELECT", "INSERT", "UPDATE", "DELETE", "CREATE", "ALTER", "DROP", "GRANT", "REVOKE", "COMMIT", "ROLLBACK", "BEGIN", "SHOW", "SET", "USE", "EXPLAIN"} {
		if op == known {
			return op
		}
	}
	return "QUERY"
}
func decodeMySQL(c, s *bufio.Reader, factory func() *Exchange, emit func(*Exchange) error) error {
	user := ""
	statements := map[uint32]string{}
	var capabilities uint32
	head, err := s.Peek(5)
	if err == io.EOF {
		return nil
	}
	if err != nil {
		return err
	}
	if head[3] == 0 && head[4] == 0x0a {
		e := factory()
		e.Operation = "LOGIN"
		greeting, err := mysqlRead(s, e.response)
		e.ResponseBytes += greeting.written
		if err != nil {
			return err
		}
		hello, err := mysqlRead(c, e.request)
		e.RequestBytes += hello.written
		if err != nil {
			return err
		}
		if len(hello.prefix) < 4 {
			return errProtocol
		}
		capabilities = binary.LittleEndian.Uint32(hello.prefix)
		if capabilities&0x800 != 0 && hello.length == 32 {
			e.Completeness = "UNSUPPORTED"
			e.gap("TLS_NO_PLAINTEXT")
			e.finish()
			if x := emit(e); x != nil {
				return x
			}
			return decodeOpaque(c, s, "TLS_NO_PLAINTEXT", factory, emit)
		}
		if len(hello.prefix) > 32 {
			end := bytes.IndexByte(hello.prefix[32:], 0)
			if end >= 0 && end <= 128 {
				user = string(hello.prefix[32 : 32+end])
			}
		}
		e.DatabaseUser = user
		if capabilities&(0x20|0x04000000|0x02000000) != 0 {
			e.Completeness = "UNSUPPORTED"
			e.gap("PROTOCOL_UNSUPPORTED")
			e.finish()
			if x := emit(e); x != nil {
				return x
			}
			return decodeOpaque(c, s, "PROTOCOL_UNSUPPORTED", factory, emit)
		}
		for {
			auth, err := mysqlRead(s, e.response)
			e.ResponseBytes += auth.written
			if err != nil {
				e.gap("DISCONNECTED")
				break
			}
			if len(auth.prefix) == 0 {
				return errProtocol
			}
			if auth.prefix[0] == 0 {
				e.Authentication = "SUCCESS"
				e.Result = "SUCCESS"
				break
			}
			if auth.prefix[0] == 0xff {
				mysqlError(e, auth)
				break
			}
			if auth.prefix[0] == 1 && len(auth.prefix) > 1 && auth.prefix[1] == 3 {
				continue
			}
			reply, err := mysqlRead(c, e.request)
			e.RequestBytes += reply.written
			if err != nil {
				e.gap("DISCONNECTED")
				break
			}
		}
		e.finish()
		if x := emit(e); x != nil {
			return x
		}
		if e.Authentication != "SUCCESS" {
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
		e.Operation = "MYSQL_COMMAND"
		request, err := mysqlRead(c, e.request)
		e.RequestBytes += request.written
		if err != nil || len(request.prefix) == 0 {
			e.gap("DISCONNECTED")
			e.finish()
			if x := emit(e); x != nil {
				return x
			}
			return nil
		}
		command := request.prefix[0]
		switch command {
		case 3:
			e.Operation = "QUERY"
			query := request.prefix[1:]
			if capabilities&0x08000000 != 0 {
				count, n, ok := mysqlLenenc(query)
				if ok && count == 0 && len(query) > n && query[n] == 1 {
					query = query[n+1:]
				} else {
					query = nil
					e.gap("PROTOCOL_UNSUPPORTED")
				}
			}
			if len(query) > 0 {
				e.Operation = mysqlQueryOperation(query)
			}
		case 0x17:
			e.Operation = "EXECUTE"
			if len(request.prefix) >= 10 {
				if op, ok := statements[binary.LittleEndian.Uint32(request.prefix[1:])]; ok {
					e.Operation = op
				} else {
					e.gap("CORRELATION_UNKNOWN")
				}
				if request.prefix[5]&7 != 0 {
					e.gap("PROTOCOL_UNSUPPORTED")
					err = errProtocol
				}
			} else {
				e.gap("PARSE_ERROR")
				err = errProtocol
			}
		case 0x16:
			e.Operation = "PREPARE"
		case 1:
			e.Operation = "DISCONNECT"
		case 0x19:
			e.Operation = "STMT_CLOSE"
			if len(request.prefix) >= 5 {
				delete(statements, binary.LittleEndian.Uint32(request.prefix[1:]))
			} else {
				e.gap("PARSE_ERROR")
			}
		case 0x18:
			e.Operation = "STMT_LONG_DATA"
		case 0x11:
			clear(statements)
			user = ""
			e.DatabaseUser = ""
			e.Operation = "CHANGE_USER"
			e.gap("PROTOCOL_UNSUPPORTED")
			err = errProtocol
		case 0x1f:
			e.Operation = "RESET_CONNECTION"
		case 0x1c:
			e.Operation = "FETCH"
			e.gap("PROTOCOL_UNSUPPORTED")
			err = errProtocol
		}

		if err != nil {
			e.finish()
			if x := emit(e); x != nil {
				return x
			}
			return decodeOpaque(c, s, "PROTOCOL_UNSUPPORTED", factory, emit)
		}
		if command == 0x16 {
			var id uint32
			id, err = mysqlPrepareResponse(s, e, capabilities)
			if err == nil && e.Result == "SUCCESS" {
				if len(statements) < 1024 || statements[id] != "" {
					statements[id] = mysqlQueryOperation(request.prefix[1:])
				} else {
					e.gap("RESOURCE_LIMIT")
				}
			}
		} else if command != 1 && command != 0x19 && command != 0x18 {
			err = mysqlResponse(s, e, capabilities)
		}
		if err != nil {
			e.gap("PARSE_ERROR")
		}
		if command == 0x1f && e.Result == "SUCCESS" {
			clear(statements)
		}
		if e.Result == "SUCCESS" && e.Operation == "COMMIT" {
			e.Transaction = "COMMITTED"
		}
		if e.Result == "SUCCESS" && e.Operation == "ROLLBACK" {
			e.Transaction = "ROLLED_BACK"
		}
		e.finish()
		if x := emit(e); x != nil {
			return x
		}
		if err != nil || command == 1 {
			return nil
		}
	}
}
