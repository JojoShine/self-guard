// Local test transport. Each input is evaluated by a fresh existing WAF worker,
// preserving its CPU bound and transaction isolation without shell byte reads.
package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"runtime/debug"
	"strings"
	"time"
)

type cappedFrame struct {
	bytes.Buffer
	overflow bool
}

func (w *cappedFrame) Write(data []byte) (int, error) {
	size := len(data)
	if w.Len()+size > 8<<20 {
		w.overflow = true
		return size, nil
	}
	_, err := w.Buffer.Write(data)
	return size, err
}
func failureKind(diagnostic string, timedOut bool) string {
	if timedOut {
		return "WORKER_DEADLINE"
	}
	switch strings.TrimSpace(diagnostic) {
	case "malformed HTTP sample", "incomplete HTTP body", "trailing or pipelined HTTP sample":
		return "HTTP_PARSE_REJECTED"
	case "malformed content type", "malformed cookie", "malformed quoted cookie":
		return "REQUEST_FIELD_INCOMPLETE"
	case "malformed UTF-8; Unicode transformation incomplete":
		return "TRANSFORMATION_INCOMPLETE"
	}
	if strings.HasPrefix(strings.TrimSpace(diagnostic), "PCRE2 compilation or execution budget failure") {
		return "INSPECTION_BUDGET"
	}
	return "WORKER_FAILURE"
}
func main() {
	debug.SetMemoryLimit(64 << 20)
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Buffer(make([]byte, 64<<10), (4<<20)+1)
	writer := bufio.NewWriter(os.Stdout)
	for scanner.Scan() {
		ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
		argument := "--test-seclang"
		if os.Getenv("WAF_CORPUS_DIAGNOSTICS") == "true" {
			argument = "--test-seclang-diagnostics"
		}
		command := exec.CommandContext(ctx, "/waf", argument)
		command.Stdin = bytes.NewReader(scanner.Bytes())
		var diagnostic, output cappedFrame
		command.Stderr = &diagnostic
		command.Stdout = &output
		err := command.Run()
		timedOut := ctx.Err() != nil
		cancel()
		os.Stderr.Write(diagnostic.Bytes())
		if err != nil || output.overflow || !json.Valid(output.Bytes()) {
			encoded, _ := json.Marshal(map[string]any{"workerError": true, "failureKind": failureKind(diagnostic.String(), timedOut)})
			writer.Write(encoded)
			writer.WriteByte('\n')
		} else {
			writer.Write(bytes.TrimSpace(output.Bytes()))
			writer.WriteByte('\n')
		}
		writer.Flush()
	}
	if scanner.Err() != nil {
		fmt.Fprintln(os.Stderr, "fixture transport input exceeds frame limit")
		os.Exit(1)
	}
}
