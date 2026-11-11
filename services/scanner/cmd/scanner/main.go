// The scanner receives one approved check and requests every HTTP allowance from
// its supervising process. It never substitutes an independent local rate limit.
package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"reflect"
	"selfguard/scanner"
)

type command struct {
	Kind          string                 `json:"kind"`
	Target        scanner.Target         `json:"target"`
	BlockedRanges []string               `json:"blockedRanges"`
	Method        string                 `json:"method"`
	Path          string                 `json:"path"`
	Rule          scanner.HTTPRule       `json:"rule"`
	Sample        *scanner.RuleSample    `json:"sample,omitempty"`
	NetworkRule   *scanner.NetworkRule   `json:"networkRule,omitempty"`
	NetworkSample *scanner.NetworkSample `json:"networkSample,omitempty"`
}
type budgetResponse struct {
	Kind      string `json:"kind"`
	RequestID string `json:"requestId"`
	Allowed   bool   `json:"allowed"`
}
type wireBudget struct {
	reader  *bufio.Reader
	encoder *json.Encoder
}

func frame(reader *bufio.Reader, maximum int) ([]byte, error) {
	var data []byte
	for {
		part, err := reader.ReadSlice('\n')
		if len(data)+len(part) > maximum {
			return nil, errors.New("frame exceeds budget")
		}
		data = append(data, part...)
		if err == nil {
			return data, nil
		}
		if err != bufio.ErrBufferFull {
			return nil, errors.New("incomplete frame")
		}
	}
}
func decode(data []byte, value any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		return err
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF {
		return errors.New("extra frame content")
	}
	return nil
}
func (b *wireBudget) Acquire(ctx context.Context, keys []string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return err
	}
	id := hex.EncodeToString(nonce[:])
	if err := b.encoder.Encode(struct {
		Kind      string   `json:"kind"`
		RequestID string   `json:"requestId"`
		Keys      []string `json:"keys"`
	}{"BUDGET_REQUEST", id, keys}); err != nil {
		return err
	}
	received := make(chan error, 1)
	go func() {
		data, err := frame(b.reader, 4096)
		if err == nil {
			var response budgetResponse
			err = decode(data, &response)
			if err == nil && (response.Kind != "BUDGET_RESPONSE" || response.RequestID != id || !response.Allowed) {
				err = errors.New("allowance not granted")
			}
		}
		received <- err
	}()
	select {
	case err := <-received:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}
func run(input io.Reader, output io.Writer) error {
	reader := bufio.NewReaderSize(input, 64<<10)
	data, err := frame(reader, 2<<20)
	if err != nil {
		return err
	}
	var cmd command
	if err = decode(data, &cmd); err != nil {
		return err
	}
	httpPayload := cmd.Method != "" || cmd.Path != "" || !reflect.DeepEqual(cmd.Rule, scanner.HTTPRule{})
	if cmd.Kind == "CHECK_NETWORK_RULE" {
		if cmd.NetworkRule == nil || cmd.NetworkSample == nil || cmd.Sample != nil || httpPayload || len(cmd.BlockedRanges) != 0 || !reflect.DeepEqual(cmd.Target, scanner.Target{}) {
			return errors.New("offline network sample cannot include a target or HTTP request")
		}
		result, err := scanner.CheckNetworkRule(*cmd.NetworkRule, *cmd.NetworkSample)
		if err != nil {
			return err
		}
		return json.NewEncoder(output).Encode(struct {
			Kind   string                    `json:"kind"`
			Result scanner.NetworkEvaluation `json:"result"`
		}{"NETWORK_RULE_RESULT", result})
	}
	if cmd.NetworkSample != nil || cmd.Kind != "CHECK_NETWORK" && cmd.NetworkRule != nil {
		return errors.New("network fields cannot cross command boundaries")
	}
	if cmd.Kind == "COMPILE_NATIVE_RULE" {
		if cmd.Sample != nil || cmd.Path != "" || len(cmd.BlockedRanges) > 0 || !reflect.DeepEqual(cmd.Target, scanner.Target{}) {
			return errors.New("compile cannot include targets or samples")
		}
		result, err := scanner.CompileNativeRule(cmd.Method, cmd.Rule)
		if err != nil {
			return err
		}
		return json.NewEncoder(output).Encode(struct {
			Kind   string                     `json:"kind"`
			Result scanner.NativeCompileProof `json:"result"`
		}{"NATIVE_COMPILE_RESULT", result})
	}
	if cmd.Kind == "CHECK_RULE" {
		if cmd.Sample == nil || cmd.Path != "" || len(cmd.BlockedRanges) > 0 || cmd.Target.Hostname != "" || cmd.Target.Port != 0 || cmd.Target.Protocol != "" || len(cmd.Target.Addresses) > 0 || len(cmd.Target.AllowedPaths) > 0 || len(cmd.Target.ExcludedPaths) > 0 {
			return errors.New("offline rule cannot include a network target")
		}
		result, err := scanner.CheckRule(cmd.Method, cmd.Rule, *cmd.Sample)
		if err != nil {
			return err
		}
		return json.NewEncoder(output).Encode(struct {
			Kind   string                 `json:"kind"`
			Result scanner.RuleEvaluation `json:"result"`
		}{"RULE_RESULT", result})
	}
	if cmd.Sample != nil {
		return errors.New("offline sample is only valid for CHECK_RULE")
	}
	if cmd.Kind != "CHECK_HTTP" && cmd.Kind != "CHECK_SCOPE" && cmd.Kind != "CHECK_NETWORK" {
		return errors.New("unsupported command")
	}
	if cmd.Kind == "CHECK_NETWORK" && (cmd.NetworkRule == nil || httpPayload) {
		return errors.New("network check requires only its explicit network rule")
	}
	policy, err := scanner.NewPolicy(cmd.Target, cmd.BlockedRanges)
	if err != nil {
		return errors.New("invalid approved scope")
	}
	encoder := json.NewEncoder(output)
	if cmd.Kind == "CHECK_SCOPE" {
		if cmd.Method != "" || cmd.Path != "" || cmd.Rule.ID != "" || cmd.Rule.Description != "" || cmd.Rule.Operator != "" || len(cmd.Rule.Conditions) > 0 || len(cmd.Rule.Groups) > 0 || cmd.Rule.MaxRedirects != nil || len(cmd.Rule.Extractors) > 0 || cmd.Rule.ResponseMode != "" || cmd.Rule.NativeTemplate != nil {
			return errors.New("scope preflight cannot include a request")
		}
		target, err := policy.Validate(context.Background())
		if err != nil {
			return err
		}
		return encoder.Encode(struct {
			Kind   string         `json:"kind"`
			Target scanner.Target `json:"target"`
		}{"SCOPE_RESULT", target})
	}
	engine, err := scanner.NewEngine(policy, &wireBudget{reader, encoder})
	if err != nil {
		return err
	}
	if cmd.Kind == "CHECK_NETWORK" {
		result := engine.Network(context.Background(), *cmd.NetworkRule)
		return encoder.Encode(struct {
			Kind   string                `json:"kind"`
			Result scanner.NetworkResult `json:"result"`
		}{"NETWORK_RESULT", result})
	}
	result := engine.HTTP(context.Background(), cmd.Method, cmd.Path, cmd.Rule)
	return encoder.Encode(struct {
		Kind   string             `json:"kind"`
		Result scanner.HTTPResult `json:"result"`
	}{"CHECK_RESULT", result})
}
func main() {
	if err := run(os.Stdin, os.Stdout); err != nil {
		os.Stderr.WriteString("Scanner input, scope or supervising channel is invalid.\n")
		os.Exit(2)
	}
}
