package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
)

const secStreamRequestLimit = 64

type secStreamResponse struct {
	Kind     string     `json:"kind"`
	Digest   string     `json:"digest,omitempty"`
	Engine   string     `json:"engine,omitempty"`
	Sequence int        `json:"sequence,omitempty"`
	Status   string     `json:"status,omitempty"`
	Message  string     `json:"message,omitempty"`
	Result   *secResult `json:"result,omitempty"`
}

func readSecFrame(reader io.Reader, limit uint32) ([]byte, error) {
	var header [4]byte
	if _, err := io.ReadFull(reader, header[:]); err != nil {
		return nil, err
	}
	size := binary.BigEndian.Uint32(header[:])
	if size == 0 || size > limit {
		return nil, errors.New("worker frame exceeds budget")
	}
	body := make([]byte, size)
	_, err := io.ReadFull(reader, body)
	return body, err
}
func writeSecFrame(writer io.Writer, body []byte) error {
	if len(body) == 0 || len(body) > 4<<20 {
		return errors.New("worker frame exceeds budget")
	}
	var header [4]byte
	binary.BigEndian.PutUint32(header[:], uint32(len(body)))
	if _, err := io.Copy(writer, bytes.NewReader(header[:])); err != nil {
		return err
	}
	_, err := io.Copy(writer, bytes.NewReader(body))
	return err
}
func decodeSecFixture(raw []byte) (secLangFixture, error) {
	var fixture secLangFixture
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&fixture); err != nil {
		return fixture, err
	}
	if decoder.Decode(new(any)) != io.EOF {
		return fixture, errors.New("trailing content after rule envelope")
	}
	return fixture, nil
}
func writeSecResponse(writer io.Writer, response secStreamResponse) error {
	raw, err := json.Marshal(response)
	if err != nil {
		return err
	}
	if len(raw) > 2<<20 {
		return errors.New("worker result exceeds budget")
	}
	return writeSecFrame(writer, raw)
}
func runSecLangStream(reader io.Reader, writer io.Writer) error {
	initial, err := readSecFrame(reader, 4<<20)
	if err != nil {
		return err
	}
	input, err := decodeSecFixture(initial)
	if err != nil {
		return err
	}
	if secFixtureRequestCount(input) != 0 || input.Threshold != 0 {
		return errors.New("worker initialization requires rules only")
	}
	rules, err := parseSecLangFiles(input.Files)
	if err != nil {
		return err
	}
	plan, err := prepareSecLangPlan(rules)
	if err != nil {
		return err
	}
	sum := sha256.Sum256(initial)
	if err = writeSecResponse(writer, secStreamResponse{Kind: "READY", Digest: hex.EncodeToString(sum[:]), Engine: "selfguard-seclang-v1"}); err != nil {
		return err
	}
	// Retain the existing two-second lifetime CPU limit. Recycle after a bounded
	// number of transactions; the supervisor also enforces each wall deadline.
	for sequence := 1; sequence <= secStreamRequestLimit; sequence++ {
		raw, e := readSecFrame(reader, 4<<20)
		if e == io.EOF {
			return nil
		}
		if e != nil {
			return e
		}
		fixture, e := decodeSecFixture(raw)
		if e == nil && len(fixture.Files) > 0 {
			e = errors.New("requests cannot replace worker rules")
		}
		if e == nil && secFixtureRequestCount(fixture) != 1 {
			e = errors.New("request requires exactly one HTTP sample, observed request or variable fixture")
		}

		var result secResult
		if e == nil {
			result, e = evaluateSecLangRequest(plan, fixture)
		}
		response := secStreamResponse{Kind: "RESULT", Sequence: sequence, Status: "COMPLETED", Result: &result}
		if e != nil {
			message := e.Error()
			if len(message) > 1000 {
				message = message[:1000]
			}
			response = secStreamResponse{Kind: "ERROR", Sequence: sequence, Status: "INCOMPLETE", Message: message}
		} else if len(result.Incomplete) > 0 {
			response.Status = "INCOMPLETE"
		}
		if err = writeSecResponse(writer, response); err != nil {
			return err
		}
	}
	return nil
}
