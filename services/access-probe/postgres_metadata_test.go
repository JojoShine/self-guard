package main

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"testing"
)

func TestPostgresResultReferencesUseRealRelationAndAttributeRatherThanAliases(t *testing.T) {
	startup := []byte{0, 3, 0, 0}
	startup = append(startup, []byte("user\x00app\x00database\x00crm\x00\x00")...)
	request := append(pgMessage(0, startup)[1:], pgMessage('Q', []byte("SELECT phone AS misleading_alias FROM customers\x00"))...)
	field := append([]byte{0, 1}, []byte("misleading_alias\x00")...)
	fixed := make([]byte, 18)
	binary.BigEndian.PutUint32(fixed, 123)
	binary.BigEndian.PutUint16(fixed[4:], 2)
	binary.BigEndian.PutUint32(fixed[6:], 25)
	field = append(field, fixed...)
	response := append(pgMessage('R', []byte{0, 0, 0, 0}), pgMessage('Z', []byte{'I'})...)
	result := append(pgMessage('T', field), pgMessage('C', []byte("SELECT 1\x00"))...)
	result = append(result, pgMessage('Z', []byte{'I'})...)
	response = append(response, result...)
	events, err := decodeExchange("POSTGRESQL", request, response)
	if err != nil || len(events) != 2 {
		t.Fatalf("decode: %d %v", len(events), err)
	}
	raw, _ := json.Marshal(events[1].Exchange)
	var snapshot struct {
		Relations []struct {
			Database    string
			RelationOID uint32 `json:"relationOid"`
			Attribute   int    `json:"attributeNumber"`
		}
	}
	if err = json.Unmarshal(raw, &snapshot); err != nil {
		t.Fatal(err)
	}
	if len(snapshot.Relations) != 1 || snapshot.Relations[0].Database != "crm" || snapshot.Relations[0].RelationOID != 123 || snapshot.Relations[0].Attribute != 2 {
		t.Fatalf("missing actual references: %s", raw)
	}
	if !bytes.Equal(events[1].Response, result) {
		t.Fatal("metadata extraction changed the raw response")
	}
}

func TestPostgresUnknownAndTruncatedMetadataNeverCreatesAnObjectReference(t *testing.T) {
	for _, payload := range [][]byte{{0}, {0, 1, 'x', 0, 0, 0}, {0, 1, 'x', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 25, 0, 0, 0, 0, 0, 0, 0, 0}} {
		event := newExchange(new(bytes.Buffer), new(bytes.Buffer))
		event.Database = "crm"
		pgResultReferences(event, payload, int64(len(payload)))
		if len(event.Relations) != 0 || event.Completeness == "COMPLETE" {
			t.Fatal("invalid or zero object metadata must remain a visible gap")
		}
	}
}
