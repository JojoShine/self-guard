package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os/exec"
	"path/filepath"
	"selfguard/scanner"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestFramesAreBoundedStrictAndComplete(t *testing.T) {
	for _, data := range []string{"{}", "{}{}\n", strings.Repeat("x", 4097) + "\n"} {
		reader := bufio.NewReaderSize(strings.NewReader(data), 32)
		raw, err := frame(reader, 4096)
		if err == nil {
			var value budgetResponse
			err = decode(raw, &value)
		}
		if err == nil {
			t.Fatal("invalid frame accepted")
		}
	}
	var reply budgetResponse
	if decode([]byte(`{"kind":"BUDGET_RESPONSE","allowed":true,"unknown":1}`), &reply) == nil {
		t.Fatal("unknown acknowledgment field accepted")
	}
}
func TestCancelledBudgetNeverStartsARead(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var output bytes.Buffer
	budget := wireBudget{bufio.NewReader(strings.NewReader("")), json.NewEncoder(&output)}
	if budget.Acquire(ctx, []string{"10.0.0.1:80"}) == nil || output.Len() != 0 {
		t.Fatal("cancelled request emitted an allowance")
	}
}
func TestRealProcessRequiresSupervisedAllowanceBeforeActualTraffic(t *testing.T) {
	addresses, err := net.InterfaceAddrs()
	if err != nil {
		t.Fatal(err)
	}
	var host string
	for _, address := range addresses {
		prefix, err := netip.ParsePrefix(address.String())
		if err == nil && prefix.Addr().Is4() && prefix.Addr().IsPrivate() && !prefix.Addr().IsLoopback() {
			host = prefix.Addr().String()
			break
		}
	}
	if host == "" {
		t.Skip("requires an isolated non-loopback private fixture interface")
	}
	listener, err := net.Listen("tcp", net.JoinHostPort(host, "0"))
	if err != nil {
		t.Fatal(err)
	}
	var requests atomic.Int32
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { requests.Add(1); fmt.Fprint(w, "owned-fixture-only") }), ReadHeaderTimeout: time.Second}
	go server.Serve(listener)
	defer server.Close()
	port := listener.Addr().(*net.TCPAddr).Port
	binary := filepath.Join(t.TempDir(), "scanner")
	build := exec.Command("go", "build", "-o", binary, ".")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatal(err, string(output))
	}
	command := command{Kind: "CHECK_HTTP", Target: scanner.Target{Hostname: host, Port: port, Protocol: "http", Addresses: []string{host}, AllowedPaths: []string{"/public"}}, Method: "GET", Path: "/public", Rule: scanner.HTTPRule{ID: "owned-fixture", Description: "An explicitly configured fixture response", Operator: "ALL", Conditions: []scanner.Condition{{Kind: "STATUS", Status: 200}, {Kind: "BODY_CONTAINS", Value: "owned-fixture-only"}}}}
	scopeCommand := command
	scopeCommand.Kind = "CHECK_SCOPE"
	scopeCommand.Method = ""
	scopeCommand.Path = ""
	scopeCommand.Rule = scanner.HTTPRule{}
	scopeInput, _ := json.Marshal(scopeCommand)
	scopeChild := exec.Command(binary)
	scopeChild.Stdin = bytes.NewReader(append(scopeInput, '\n'))
	scopeOutput, err := scopeChild.CombinedOutput()
	if err != nil {
		t.Fatal("scope validation failed", err, string(scopeOutput))
	}
	var validated struct {
		Kind   string
		Target scanner.Target
	}
	if json.Unmarshal(scopeOutput, &validated) != nil || validated.Kind != "SCOPE_RESULT" || validated.Target.Addresses[0] != host || requests.Load() != 0 {
		t.Fatal("scope preflight generated traffic or invalid data", string(scopeOutput))
	}
	for _, allow := range []bool{false, true} {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		child := exec.CommandContext(ctx, binary)
		input, _ := child.StdinPipe()
		output, _ := child.StdoutPipe()
		var diagnostics bytes.Buffer
		child.Stderr = &diagnostics
		if err := child.Start(); err != nil {
			t.Fatal(err)
		}
		writer := json.NewEncoder(input)
		writer.Encode(command)
		reader := bufio.NewReader(output)
		data, err := frame(reader, 8192)
		if err != nil {
			t.Fatal(err)
		}
		var request struct {
			Kind, RequestID string
			Keys            []string
		}
		if json.Unmarshal(data, &request) != nil || request.Kind != "BUDGET_REQUEST" || len(request.RequestID) != 32 || len(request.Keys) != 1 || request.Keys[0] != listener.Addr().String() {
			t.Fatal("unexpected budget request", string(data))
		}
		before := requests.Load()
		writer.Encode(budgetResponse{Kind: "BUDGET_RESPONSE", RequestID: request.RequestID, Allowed: allow})
		data, err = frame(reader, 256<<10)
		if err != nil {
			t.Fatal(err)
		}
		var result struct {
			Kind   string
			Result scanner.HTTPResult
		}
		if json.Unmarshal(data, &result) != nil || result.Kind != "CHECK_RESULT" {
			t.Fatal(string(data))
		}
		if allow {
			if result.Result.Outcome != "CONFIRMED" || requests.Load() != before+1 || len(result.Result.Evidence.ConnectedPeers) != 1 {
				t.Fatal(result)
			}
		} else if result.Result.Outcome != "INCONCLUSIVE" || requests.Load() != before {
			t.Fatal("traffic occurred without allowance", result)
		}
		input.Close()
		io.Copy(io.Discard, reader)
		if err = child.Wait(); err != nil {
			t.Fatal(err, diagnostics.String())
		}
		cancel()
	}
}

func TestOfflineRuleProtocolDoesNotNeedAScopeOrAllowance(t *testing.T) {
	input := `{"kind":"CHECK_RULE","method":"GET","rule":{"id":"offline","description":"Explicit sample","operator":"ALL","conditions":[{"kind":"STATUS","status":200},{"kind":"BODY_CONTAINS","value":"exposed"}]},"sample":{"status":200,"headers":{},"body":"exposed"}}`
	var output bytes.Buffer
	if err := run(strings.NewReader(input+"\n"), &output); err != nil {
		t.Fatal(err)
	}
	var result struct {
		Kind   string
		Result scanner.RuleEvaluation
	}
	if json.Unmarshal(output.Bytes(), &result) != nil || result.Kind != "RULE_RESULT" || !result.Result.Matched || strings.Contains(output.String(), "BUDGET_REQUEST") {
		t.Fatal(output.String())
	}
	var value map[string]any
	json.Unmarshal([]byte(input), &value)
	value["target"] = map[string]any{"hostname": "10.1.2.3"}
	raw, _ := json.Marshal(value)
	if run(bytes.NewReader(append(raw, '\n')), &bytes.Buffer{}) == nil {
		t.Fatal("offline sample accepted a network target")
	}
}

func TestNetworkOfflineProtocolCannotCarryTargetOrHTTPPayload(t *testing.T) {
	for _, sample := range []struct {
		body  string
		valid bool
	}{
		{`{"kind":"CHECK_NETWORK_RULE","networkRule":{"id":"owned-banner","description":"Owned offline service marker","kind":"TCP_BANNER","value":"legacy"},"networkSample":{"connected":true,"banner":"owned legacy\r\n"}}`, true},
		{`{"kind":"CHECK_NETWORK_RULE","networkRule":{"id":"owned-connect","description":"Owned offline connect","kind":"TCP_CONNECT"},"networkSample":{"connected":false}}`, true},
		{`{"kind":"CHECK_NETWORK_RULE","target":{"hostname":"10.20.0.8","port":80,"protocol":"tcp","addresses":["10.20.0.8"]},"networkRule":{"id":"owned","description":"No network permitted","kind":"TCP_CONNECT"},"networkSample":{"connected":true}}`, false},
		{`{"kind":"CHECK_SCOPE","target":{"hostname":"10.20.0.8","port":80,"protocol":"tcp","addresses":["10.20.0.8"]},"networkRule":{"id":"owned","description":"No hidden check in preflight","kind":"TCP_CONNECT"}}`, false},
	} {
		var output bytes.Buffer
		err := run(strings.NewReader(sample.body+"\n"), &output)
		if sample.valid {
			if err != nil {
				t.Fatal(err)
			}
			var result struct {
				Kind   string
				Result scanner.NetworkEvaluation
			}
			if json.Unmarshal(output.Bytes(), &result) != nil || result.Kind != "NETWORK_RULE_RESULT" {
				t.Fatal("offline network result missing", output.String())
			}
		} else if err == nil {
			t.Fatal("network/sample payload crossed protocol boundary")
		}
	}
}

func TestRealNetworkProcessNeedsSharedAllowanceBeforeSocket(t *testing.T) {
	addresses, err := net.InterfaceAddrs()
	if err != nil {
		t.Fatal(err)
	}
	host := ""
	for _, address := range addresses {
		prefix, err := netip.ParsePrefix(address.String())
		if err == nil && prefix.Addr().Is4() && prefix.Addr().IsPrivate() && !prefix.Addr().IsLoopback() {
			host = prefix.Addr().String()
			break
		}
	}
	if host == "" {
		t.Skip("requires isolated private fixture interface")
	}
	listener, err := net.Listen("tcp", net.JoinHostPort(host, "0"))
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	var connections, applicationBytes atomic.Int32
	go func() {
		for {
			connection, err := listener.Accept()
			if err != nil {
				return
			}
			connections.Add(1)
			go func() {
				defer connection.Close()
				connection.SetReadDeadline(time.Now().Add(time.Second))
				buffer := make([]byte, 1)
				n, _ := connection.Read(buffer)
				applicationBytes.Add(int32(n))
			}()
		}
	}()
	binary := filepath.Join(t.TempDir(), "scanner")
	if output, err := exec.Command("go", "build", "-o", binary, ".").CombinedOutput(); err != nil {
		t.Fatal(err, string(output))
	}
	request := map[string]any{"kind": "CHECK_NETWORK", "target": scanner.Target{Hostname: host, Port: listener.Addr().(*net.TCPAddr).Port, Protocol: "tcp", Addresses: []string{host}}, "networkRule": scanner.NetworkRule{ID: "owned-connect", Description: "Explicit controlled connection observation", Kind: "TCP_CONNECT"}}
	for _, allow := range []bool{false, true} {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		child := exec.CommandContext(ctx, binary)
		input, _ := child.StdinPipe()
		output, _ := child.StdoutPipe()
		if err := child.Start(); err != nil {
			t.Fatal(err)
		}
		writer := json.NewEncoder(input)
		writer.Encode(request)
		reader := bufio.NewReader(output)
		raw, err := frame(reader, 8192)
		if err != nil {
			t.Fatal(err)
		}
		var allowance struct {
			Kind, RequestID string
			Keys            []string
		}
		if json.Unmarshal(raw, &allowance) != nil || allowance.Kind != "BUDGET_REQUEST" || len(allowance.Keys) != 1 || allowance.Keys[0] != listener.Addr().String() {
			t.Fatal("wrong connection allowance", string(raw))
		}
		before := connections.Load()
		if before != 0 {
			t.Fatal("traffic preceded first grant")
		}
		writer.Encode(budgetResponse{Kind: "BUDGET_RESPONSE", RequestID: allowance.RequestID, Allowed: allow})
		raw, err = frame(reader, 256<<10)
		if err != nil {
			t.Fatal(err)
		}
		var result struct {
			Kind   string
			Result scanner.NetworkResult
		}
		if json.Unmarshal(raw, &result) != nil || result.Kind != "NETWORK_RESULT" {
			t.Fatal("invalid network result", string(raw))
		}
		if allow {
			if result.Result.Outcome != "OBSERVED" || len(result.Result.Evidence.Connections) != 1 || result.Result.Evidence.Connections[0].Destination != listener.Addr().String() {
				t.Fatal(result)
			}
		} else if result.Result.Outcome != "INCONCLUSIVE" || connections.Load() != before {
			t.Fatal("ungranted network traffic", result)
		}
		input.Close()
		if err := child.Wait(); err != nil {
			t.Fatal(err)
		}
		cancel()
	}
	if applicationBytes.Load() != 0 {
		t.Fatal("connect check sent application commands")
	}
}
