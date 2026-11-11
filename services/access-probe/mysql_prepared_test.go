package main

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func preparedOK(id uint32, columns, params uint16) []byte {
	b := make([]byte, 12)
	binary.LittleEndian.PutUint32(b[1:], id)
	binary.LittleEndian.PutUint16(b[5:], columns)
	binary.LittleEndian.PutUint16(b[7:], params)
	return mysqlPacket(1, b)
}
func executePacket(id uint32) []byte {
	b := make([]byte, 10)
	b[0] = 0x17
	binary.LittleEndian.PutUint32(b[1:], id)
	b[6] = 1
	return mysqlPacket(0, b)
}
func TestMySQLPreparedQueryRetainsFramesAndAssociatesOperation(t *testing.T) {
	prepare := mysqlPacket(0, append([]byte{0x16}, []byte("SELECT id FROM db.users WHERE id=?")...))
	execute := executePacket(7)
	request := append(append([]byte{}, prepare...), execute...)
	column := []byte("\x03def\x02db\x05users\x05users\x02id\x02id")
	end := []byte{0xfe, 0, 0, 2, 0}
	preparation := preparedOK(7, 1, 1)
	for _, b := range [][]byte{column, end, column, end} {
		preparation = append(preparation, mysqlPacket(2, b)...)
	}
	result := mysqlPacket(1, []byte{1})
	for _, b := range [][]byte{column, end, {0, 0, 42, 0, 0, 0}, end} {
		result = append(result, mysqlPacket(2, b)...)
	}
	events, err := decodeExchange("MYSQL", request, append(append([]byte{}, preparation...), result...))
	if err != nil || len(events) != 2 {
		t.Fatalf("prepare+execute: %v %d", err, len(events))
	}
	if events[0].Operation != "PREPARE" || events[0].Result != "SUCCESS" || events[1].Operation != "SELECT" || events[1].Completeness != "COMPLETE" || events[1].Result != "SUCCESS" || !bytes.Equal(events[0].Response, preparation) || !bytes.Equal(events[1].Response, result) || len(events[1].Objects) != 1 {
		t.Fatalf("framing/operation mismatch: %+v %+v", events[0].Exchange, events[1].Exchange)
	}
}
func TestMySQLStatementCloseAndResetRemoveStaleAssociations(t *testing.T) {
	for _, reset := range []bool{false, true} {
		prepare := mysqlPacket(0, append([]byte{0x16}, []byte("UPDATE users SET id=?")...))
		request := append([]byte{}, prepare...)
		response := preparedOK(9, 0, 0)
		if reset {
			request = append(request, mysqlPacket(0, []byte{0x1f})...)
			response = append(response, mysqlPacket(1, []byte{0, 0, 0, 2, 0, 0, 0})...)
		} else {
			request = append(request, mysqlPacket(0, []byte{0x19, 9, 0, 0, 0})...)
		}
		request = append(request, executePacket(9)...)
		response = append(response, mysqlPacket(1, []byte{0, 0, 0, 2, 0, 0, 0})...)
		events, err := decodeExchange("MYSQL", request, response)
		if err != nil || len(events) != 3 {
			t.Fatalf("close/reset: %v %d", err, len(events))
		}
		last := events[2]
		if last.Operation != "EXECUTE" || last.Completeness != "PARTIAL" {
			t.Fatalf("stale SQL operation reused: %+v", last.Exchange)
		}
	}
}
func TestMySQLPrepareErrorDoesNotStopLaterQueries(t *testing.T) {
	request := append(mysqlPacket(0, []byte{0x16, 'x'}), mysqlPacket(0, []byte{3, 'S', 'E', 'L', 'E', 'C', 'T', ' ', '1'})...)
	response := append(mysqlPacket(1, []byte{0xff, 0x28, 0x04}), mysqlPacket(1, []byte{0, 0, 0, 2, 0, 0, 0})...)
	events, err := decodeExchange("MYSQL", request, response)
	if err != nil || len(events) != 2 || events[0].Result != "FAILURE" || events[1].Operation != "SELECT" {
		t.Fatalf("prepare failure loses following requests: %v %+v", err, events)
	}
}

func TestMySQLChangeUserDoesNotReuseOldStatementIdentity(t *testing.T) {
	request := append(mysqlPacket(0, append([]byte{0x16}, []byte("UPDATE users SET id=1")...)), mysqlPacket(0, []byte{0x11, 'u', 0})...)
	request = append(request, executePacket(9)...)
	response := append(preparedOK(9, 0, 0), mysqlPacket(1, []byte{0, 0, 0, 2, 0, 0, 0})...)
	response = append(response, mysqlPacket(1, []byte{0xff, 0xdb, 4})...)
	events, err := decodeExchange("MYSQL", request, response)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range events {
		if e.Operation == "UPDATE" {
			t.Fatal("old statement operation survived change-user")
		}
	}
}
