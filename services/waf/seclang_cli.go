package main

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/textproto"
	"path"
	"sort"
	"strings"
)

type secLangFile struct {
	Name   string `json:"name"`
	Source string `json:"source"`
}
type secLangFixture struct {
	Files         []secLangFile       `json:"files"`
	Variables     map[string][]string `json:"variables,omitempty"`
	Threshold     int                 `json:"threshold,omitempty"`
	RequestBase64 string              `json:"requestBase64,omitempty"`
	Request       *secLiveRequest     `json:"request,omitempty"`
}

func runSecLangCLI(reader io.Reader, writer io.Writer, evaluate bool, index ...bool) error {
	return runSecLangCLIOptions(reader, writer, evaluate, len(index) > 0 && index[0], false)
}
func runSecLangCLIOptions(reader io.Reader, writer io.Writer, evaluate, index, diagnostic bool) error {
	raw, err := io.ReadAll(io.LimitReader(reader, (4<<20)+1))
	if err != nil || len(raw) > 4<<20 {
		return errors.New("rule package exceeds 4 MiB")
	}
	var input secLangFixture
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.DisallowUnknownFields()
	if err = decoder.Decode(&input); err != nil {
		return err
	}
	if err = decoder.Decode(new(any)); err != io.EOF {
		return errors.New("trailing content after rule envelope")
	}
	rules, err := parseSecLangFiles(input.Files)
	if err != nil {
		return err
	}
	if !evaluate {
		if index {
			return json.NewEncoder(writer).Encode(map[string]any{"compatibility": secLangCompatibility(rules), "rules": secLangRuleIndex(rules)})
		}
		return json.NewEncoder(writer).Encode(secLangCompatibility(rules))
	}
	plan, err := prepareSecLangPlan(rules)
	if err != nil {
		return err
	}
	var observe secMatchObserver
	var logs []string
	logBytes := 0
	truncated := false
	if diagnostic {
		observe = func(rule secRule, variable secVariable, message, data string) {
			line := fmt.Sprintf("[id %q] [msg %q] [data %q] [variable %q]", rule.ID, message, data, variable.name)
			if len(line) > 4096 {
				line = line[:4096]
				truncated = true
			}
			if len(logs) >= 100 || logBytes+len(line) > 65536 {
				truncated = true
				return
			}
			logs = append(logs, line)
			logBytes += len(line)
		}
	}
	result, err := evaluateSecLangRequest(plan, input, observe)
	if err != nil {
		return err
	}
	if diagnostic {
		if result.ProcessorError != "" {
			line := fmt.Sprintf("[processor] %q", result.ProcessorError)
			if len(line) <= 4096 && len(logs) < 100 && logBytes+len(line) <= 65536 {
				logs = append(logs, line)
			} else {
				truncated = true
			}
		}
		result.DiagnosticEnabled = true
		result.DiagnosticLog = logs
		result.DiagnosticTruncated = truncated || result.OmittedEvidence > 0
	}
	return json.NewEncoder(writer).Encode(result)
}
func parseSecLangFiles(files []secLangFile) ([]secRule, error) {
	if len(files) == 0 || len(files) > 200 {
		return nil, errors.New("invalid rule file count")
	}

	// The management digest canonicalizes filenames; execution must use the same order.
	files = append([]secLangFile(nil), files...)
	sort.Slice(files, func(i, j int) bool { return files[i].Name < files[j].Name })
	data := map[string]string{}
	seenFiles := map[string]bool{}
	for _, file := range files {
		if file.Name == "" || strings.Contains(file.Name, "..") || strings.HasPrefix(file.Name, "/") || seenFiles[file.Name] {
			return nil, errors.New("invalid or duplicate virtual filename")
		}
		seenFiles[file.Name] = true
		if strings.HasSuffix(file.Name, ".data") {
			data[file.Name] = file.Source
		}
	}
	var bindData func(*secRule) error
	bindData = func(r *secRule) error {
		if r.Operator == "pmfromfile" {
			if len(strings.Fields(r.Operand)) == 0 {
				return errors.New("phrase filename required")
			}
			r.Phrases = []string{}
			for _, name := range strings.Fields(r.Operand) {
				if strings.Contains(name, "..") || strings.HasPrefix(name, "/") || !strings.HasSuffix(name, ".data") {
					return errors.New("phrase references must remain inside the versioned package")
				}
				source, ok := data[path.Join(path.Dir(r.File), name)]
				if !ok {
					return errors.New("phrase file dependency missing")
				}
				for _, line := range strings.Split(strings.ReplaceAll(source, "\r\n", "\n"), "\n") {
					phrase := strings.TrimSpace(line)
					if phrase != "" && !strings.HasPrefix(phrase, "#") {
						r.Phrases = append(r.Phrases, phrase)
					}
				}
			}
			r.PhraseDataLoaded = true
		}
		for i := range r.Chain {
			if err := bindData(&r.Chain[i]); err != nil {
				return err
			}
		}
		return nil
	}
	rules := []secRule{}
	ids := map[string]bool{}
	names := map[string]bool{}
	for _, file := range files {
		if file.Name == "" || strings.Contains(file.Name, "..") || strings.HasPrefix(file.Name, "/") || names[file.Name] {
			return nil, errors.New("invalid virtual rule filename")
		}
		names[file.Name] = true
		if strings.HasSuffix(file.Name, ".data") {
			continue
		}
		if !strings.HasSuffix(file.Name, ".conf") {
			return nil, errors.New("only conf and data files are accepted")
		}
		parsed, err := parseSecLang(file.Name, file.Source)
		if err != nil {
			return nil, err
		}
		for i := range parsed {
			if err := bindData(&parsed[i]); err != nil {
				return nil, err
			}
			r := parsed[i]
			if r.ID != "" {
				if ids[r.ID] {
					return nil, errors.New("duplicate rule ID across files")
				}
				ids[r.ID] = true
			}
		}
		rules = append(rules, parsed...)
	}
	return rules, nil
}

func evaluateSecLangRequest(plan *secLangPlan, input secLangFixture, observers ...secMatchObserver) (secResult, error) {
	if input.Threshold == 0 {
		input.Threshold = 5
	}
	var requestState *secRequestState
	if secFixtureRequestCount(input) > 1 {
		return secResult{}, errors.New("HTTP samples, observed requests and injected variables are mutually exclusive")
	}
	if input.Request != nil {
		var err error
		requestState, err = input.Request.state()
		if err != nil {
			return secResult{}, err
		}
		input.Variables, err = secRequestInputOptions(requestState.request, requestState.body, "", false)
		if err != nil {
			return secResult{}, err
		}
	}
	if input.RequestBase64 != "" {
		if len(input.Variables) > 0 {
			return secResult{}, errors.New("raw requests and injected variables are mutually exclusive")
		}
		raw, err := base64.StdEncoding.Strict().DecodeString(input.RequestBase64)
		if err != nil || base64.StdEncoding.EncodeToString(raw) != input.RequestBase64 {
			return secResult{}, errors.New("canonical base64 request required")
		}
		reader := bufio.NewReader(bytes.NewReader(raw))
		request, err := http.ReadRequest(reader)
		if err != nil {
			return secResult{}, errors.New("malformed HTTP sample")
		}
		body, err := io.ReadAll(io.LimitReader(request.Body, (1<<20)+1))
		request.Body.Close()
		if err != nil {
			return secResult{}, errors.New("incomplete HTTP body")
		}
		if _, err := reader.Peek(1); err != io.EOF {
			return secResult{}, errors.New("trailing or pipelined HTTP sample")
		}
		// net/http consumes Host and Transfer-Encoding while framing the body.
		// After it validates framing, retain the original header collection for
		// protocol rules (including the distinction between absent and empty).
		headers := textproto.NewReader(bufio.NewReader(bytes.NewReader(raw)))
		if _, err := headers.ReadLine(); err != nil {
			return secResult{}, errors.New("malformed HTTP request line")
		}
		wireHeaders, err := headers.ReadMIMEHeader()
		if err != nil {
			return secResult{}, errors.New("malformed HTTP headers")
		}
		request.Header = http.Header(wireHeaders)
		request.RemoteAddr = "192.0.2.1:12345"
		requestState = &secRequestState{request: request, body: body}
		input.Variables, err = secRequestInputOptions(request, body, "", false)
		if err != nil {
			return secResult{}, err
		}
	}
	var loaders []secBodyLoader
	if requestState != nil {
		unique := input.Variables["UNIQUE_ID"]
		loaders = append(loaders, func(processor string, force bool) (map[string][]string, error) {
			next, err := requestState.load(processor, force)
			if next != nil {
				next["UNIQUE_ID"] = unique
			}
			return next, err
		})
	}
	var observe secMatchObserver
	if len(observers) > 0 {
		observe = observers[0]
	}
	result, err := evaluateSecLangObserved(plan, input.Variables, input.Threshold, observe, loaders...)
	if err != nil {
		return secResult{}, err
	}
	return result, nil
}
