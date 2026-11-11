package scanner

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unicode/utf8"
)

const nativeEngineVersion = "3.11.1"

type NativeTemplate struct {
	Raw           string `json:"raw"`
	SHA256        string `json:"sha256"`
	EngineVersion string `json:"engineVersion"`
}
type NativeEvidence struct {
	TemplateSHA256 string `json:"templateSha256"`
	EngineVersion  string `json:"engineVersion"`
}
type NativeCompileProof struct {
	Passed         bool     `json:"passed"`
	ValidationKind string   `json:"validationKind"`
	EngineVersion  string   `json:"engineVersion"`
	TemplateSHA256 string   `json:"templateSha256"`
	Samples        []string `json:"samples"`
	Meaning        string   `json:"meaning"`
}
type nativeMatcher struct {
	Type            string   `json:"type"`
	Name            string   `json:"name,omitempty"`
	Part            string   `json:"part,omitempty"`
	Condition       string   `json:"condition,omitempty"`
	Negative        bool     `json:"negative,omitempty"`
	Words           []string `json:"words,omitempty"`
	Regex           []string `json:"regex,omitempty"`
	DSL             []string `json:"dsl,omitempty"`
	Status          []int    `json:"status,omitempty"`
	Binary          []string `json:"binary,omitempty"`
	Size            []int    `json:"size,omitempty"`
	CaseInsensitive bool     `json:"case-insensitive,omitempty"`
	Encoding        string   `json:"encoding,omitempty"`
}
type nativeRequest struct {
	Method    string          `json:"method"`
	Path      []string        `json:"path"`
	Matchers  []nativeMatcher `json:"matchers"`
	Condition string          `json:"matchers-condition,omitempty"`
}
type nativeDocument struct {
	ID   string `json:"id"`
	Info struct {
		Name     string   `json:"name"`
		Author   string   `json:"author"`
		Severity string   `json:"severity"`
		Tags     []string `json:"tags,omitempty"`
	} `json:"info"`
	HTTP []nativeRequest `json:"http"`
}

var nativeStrings = regexp.MustCompile(`"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'`)
var nativeIdentifiers = regexp.MustCompile(`[A-Za-z_][A-Za-z_0-9]*`)
var nativeFunction = regexp.MustCompile(`^\s*\(`)

func nativeDSLAllowed(input string) bool {
	if strings.Contains(input, "{{") || len(input) > 4096 {
		return false
	}
	code := nativeStrings.ReplaceAllString(input, " ")
	if strings.ContainsAny(code, "{};[]") {
		return false
	}
	functions := " contains contains_all contains_any to_lower to_upper tolower toupper len regex regex_all trim trim_left trim_right trim_space starts_with ends_with base64_decode hex_decode md5 sha1 sha256 sha512 mmh3 compare_versions version_compare equals_any equals_all substring index_of to_string to_number "
	variables := " body status_code content_length all_headers response true false "
	for _, indices := range nativeIdentifiers.FindAllStringIndex(code, -1) {
		name := code[indices[0]:indices[1]]
		allowed := variables
		if nativeFunction.MatchString(code[indices[1]:]) {
			allowed = functions
		}
		if !strings.Contains(allowed, " "+name+" ") {
			return false
		}
	}
	return true
}
func validateNative(rule HTTPRule, method string) error {
	n := rule.NativeTemplate
	if n == nil || n.EngineVersion != nativeEngineVersion || !utf8.ValidString(n.Raw) || len(n.Raw) > 65536 || hashBytes([]byte(n.Raw)) != n.SHA256 || len(rule.Conditions) > 0 || len(rule.Groups) > 0 || len(rule.Extractors) > 0 || rule.MaxRedirects == nil || *rule.MaxRedirects != 0 || rule.ResponseMode != "" {
		return errors.New("invalid native rule contract")
	}
	var doc nativeDocument
	decoder := json.NewDecoder(strings.NewReader(n.Raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&doc) != nil || decoder.Decode(new(any)) != io.EOF || len(doc.HTTP) != 1 || doc.ID == "" || doc.Info.Name == "" || doc.Info.Author != "selfguard" || strings.Contains(doc.ID, "{{") || strings.Contains(doc.Info.Name, "{{") {
		return errors.New("invalid normalized native document")
	}
	for _, tag := range doc.Info.Tags {
		if strings.Contains(" rce dos fuzz bruteforce ssrf xxe sqli deserialization file-upload upload file-write intrusive token-spray credential-stuffing ", " "+strings.ToLower(tag)+" ") {
			return errors.New("intrusive native profile unsupported")
		}
	}
	r := doc.HTTP[0]
	if r.Method != "GET" && r.Method != "HEAD" || method != r.Method || len(r.Path) != 1 || r.Path[0] != "{{BaseURL}}" || len(r.Matchers) < 1 || len(r.Matchers) > 32 || r.Condition != "" && r.Condition != "and" && r.Condition != "or" {
		return errors.New("unsupported native request")
	}
	for _, m := range r.Matchers {
		switch m.Type {
		case "word", "regex", "dsl", "status", "binary", "size":
		default:
			return errors.New("unsupported native matcher")
		}
		switch m.Part {
		case "", "body", "header", "all_headers", "response", "all":
		default:
			return errors.New("unsupported native part")
		}
		if m.Condition != "" && m.Condition != "and" && m.Condition != "or" {
			return errors.New("unsupported matcher condition")
		}
		for _, expr := range m.DSL {
			if !nativeDSLAllowed(expr) {
				return errors.New("unsafe native DSL")
			}
		}
		if m.Type == "dsl" && len(m.DSL) == 0 {
			return errors.New("empty native DSL")
		}
		for _, values := range [][]string{m.Words, m.Regex, m.Binary, m.DSL, []string{m.Name, m.Encoding}} {
			for _, value := range values {
				if len(value) > 4096 || strings.Contains(value, "{{") {
					return errors.New("dynamic native matcher")
				}
			}
		}
	}
	return nil
}

type nativeOutput struct {
	bytes.Buffer
	limit int
}

func (w *nativeOutput) Write(p []byte) (int, error) {
	if w.Len()+len(p) > w.limit {
		return 0, errors.New("native output budget exceeded")
	}
	return w.Buffer.Write(p)
}
func nativeCommand(ctx context.Context, dir string, args ...string) ([]byte, []byte, error) {
	binary := os.Getenv("NUCLEI_BINARY")
	if binary == "" || !filepath.IsAbs(binary) {
		return nil, nil, errors.New("trusted native binary required")
	}
	cmd := exec.CommandContext(ctx, binary, args...)
	cmd.Dir = dir
	cmd.Env = []string{"HOME=" + dir, "XDG_CONFIG_HOME=" + dir, "XDG_CACHE_HOME=" + dir, "TMPDIR=" + dir, "GOMEMLIMIT=192MiB", "GOMAXPROCS=1", "DISABLE_NUCLEI_TEMPLATES_PUBLIC_DOWNLOAD=true", "DISABLE_NUCLEI_TEMPLATES_GITHUB_DOWNLOAD=true"}
	out, stderr := &nativeOutput{limit: 2 << 20}, &nativeOutput{limit: 64 << 10}
	cmd.Stdout = out
	cmd.Stderr = stderr
	err := cmd.Run()
	return out.Bytes(), stderr.Bytes(), err
}
func nativeRun(parent context.Context, rule HTTPRule, sample *RuleSample) (bool, *NativeEvidence, error) {
	interrupted, stop := signal.NotifyContext(parent, os.Interrupt, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithTimeout(interrupted, 6*time.Second)
	defer cancel()
	dir, err := os.MkdirTemp("", "selfguard-native-")
	if err != nil {
		return false, nil, err
	}
	defer os.RemoveAll(dir)
	version, stderr, err := nativeCommand(ctx, dir, "-version")
	if err != nil || !regexp.MustCompile(`(?m)Nuclei Engine Version: v?3\.11\.1(?:\s|$)`).Match(append(version, stderr...)) {
		return false, nil, errors.New("native engine version mismatch")
	}
	template := filepath.Join(dir, "template.yaml")
	config := filepath.Join(dir, "config.yaml")
	if err = os.WriteFile(template, []byte(rule.NativeTemplate.Raw), 0600); err != nil {
		return false, nil, err
	}
	if err = os.WriteFile(config, []byte("{}\n"), 0600); err != nil {
		return false, nil, err
	}
	args := []string{"-passive", "-t", template, "-config", config, "-duc", "-ni", "-no-stdin", "-no-color", "-silent", "-jsonl", "-omit-raw", "-omit-template", "-c", "1", "-bs", "1", "-tlc", "1", "-dr", "-nh", "-timeout", "1", "-retries", "0", "-matcher-status"}
	var document nativeDocument
	if json.Unmarshal([]byte(rule.NativeTemplate.Raw), &document) != nil || len(document.HTTP) != 1 {
		return false, nil, errors.New("native document invalid")
	}
	isHead := document.HTTP[0].Method == "HEAD"
	expectedResponse := ""
	if sample == nil {
		args = append(args, "-validate")
	} else {
		if rawLength := sample.Headers.Get("Content-Length"); rawLength != "" {
			length, err := strconv.Atoi(rawLength)
			if err != nil || (!isHead && length != len(sample.Body)) {
				return false, nil, errors.New("native response framing cannot be represented exactly")
			}
		}
		var response bytes.Buffer
		proto, status := sample.responseProto, sample.responseStatus
		if proto == "" {
			proto = "HTTP/1.1"
		}
		if status == "" {
			status = strconv.Itoa(sample.Status) + " " + http.StatusText(sample.Status)
		}
		fmt.Fprintf(&response, "%s %s\r\n", proto, status)
		for key, values := range sample.Headers {
			if strings.EqualFold(key, "Transfer-Encoding") || strings.EqualFold(key, "Content-Encoding") && strings.Join(values, "") != "identity" {
				return false, nil, errors.New("native response encoding cannot be represented exactly")
			}
			for _, value := range values {
				fmt.Fprintf(&response, "%s: %s\r\n", key, value)
			}
		}
		if sample.Headers.Get("Content-Length") == "" {
			response.WriteString("Content-Length: " + strconv.Itoa(len(sample.Body)) + "\r\n")
		}
		response.WriteString("\r\n")
		response.WriteString(sample.Body)
		if sample.responseRaw != "" {
			response.Reset()
			response.WriteString(sample.responseRaw)
		}
		// The offline parser accepts a request prefix to retain HEAD framing; this
		// file is never supplied to a network executor.
		if isHead {
			data := response.String()
			response.Reset()
			response.WriteString("HEAD / HTTP/1.1\r\nHost: offline.invalid\r\n\r\n")
			response.WriteString(data)
		}
		expectedResponse = response.String()
		file := filepath.Join(dir, "response.txt")
		if err = os.WriteFile(file, response.Bytes(), 0600); err != nil {
			return false, nil, err
		}
		args = append(args, "-target", file)
	}
	out, stderr, err := nativeCommand(ctx, dir, args...)
	if err != nil || bytes.Contains(stderr, []byte("[ERR]")) || bytes.Contains(stderr, []byte("[FTL]")) {
		return false, nil, errors.New("native compilation or matching failed")
	}
	proof := &NativeEvidence{rule.NativeTemplate.SHA256, nativeEngineVersion}
	var templateID struct {
		ID string `json:"id"`
	}
	if json.Unmarshal([]byte(rule.NativeTemplate.Raw), &templateID) != nil {
		return false, nil, errors.New("native identity invalid")
	}
	matched := false
	events := 0
	for _, line := range bytes.Split(bytes.TrimSpace(out), []byte("\n")) {
		if len(line) == 0 {
			continue
		}
		var event struct {
			Path          string `json:"path"`
			TemplateID    string `json:"template-id"`
			MatcherStatus *bool  `json:"matcher-status"`
		}
		// Nuclei can emit a false result after a parse error; only a response
		// event bound to the exact captured bytes proves evaluation happened.
		if json.Unmarshal(line, &event) != nil || event.TemplateID != templateID.ID || event.MatcherStatus == nil || event.Path != expectedResponse {
			return false, nil, errors.New("invalid native event")
		}
		events++
		matched = matched || *event.MatcherStatus
	}
	if sample != nil && events == 0 {
		return false, nil, errors.New("native engine did not evaluate response")
	}
	return matched, proof, nil
}
func CompileNativeRule(method string, rule HTTPRule) (NativeCompileProof, error) {
	if _, err := validateHTTPRule(rule, method); err != nil || rule.NativeTemplate == nil {
		return NativeCompileProof{}, errors.New("invalid native rule")
	}
	_, proof, err := nativeRun(context.Background(), rule, nil)
	if err != nil {
		return NativeCompileProof{}, err
	}
	return NativeCompileProof{true, "NATIVE_TEMPLATE_COMPILE", proof.EngineVersion, proof.TemplateSHA256, []string{}, "仅证明固定版本原生引擎成功编译；没有正反样本验证、没有请求目标，不证明实际漏洞命中。"}, nil
}

func nativePathAllowed(path string) bool {
	if strings.ContainsAny(path, ";|&$`") {
		return false
	}
	for _, part := range strings.Split(strings.ToLower(path), "/") {
		switch part {
		case "shutdown", "logout", "reboot", "reset":
			return false
		}
	}
	return true
}
