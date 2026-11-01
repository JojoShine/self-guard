package main

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"errors"
	"io"
	"mime"
	"mime/multipart"
	"net"
	"net/http"
	"net/textproto"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"unicode"
)

type secRequestBuilder struct {
	input                     map[string][]string
	count, size, argumentSize int
	err                       error
}

func (b *secRequestBuilder) add(name, value string) {
	if b.err != nil {
		return
	}
	b.count++
	b.size += len(name) + len(value)
	if b.count > 10000 || b.size > 4<<20 {
		b.err = errors.New("request variable budget exceeded")
		return
	}
	b.input[name] = append(b.input[name], value)
}
func (b *secRequestBuilder) argument(source, name, value string) {
	b.add("ARGS:"+name, value)
	b.add("ARGS_NAMES", name)
	b.add(source+":"+name, value)
	b.add(source+"_NAMES", name)
	b.argumentSize += len(name) + len(value)
}
func (b *secRequestBuilder) encodedArguments(source, value string) error {
	for _, field := range strings.Split(value, "&") {
		if field == "" {
			continue
		}
		name, value, _ := strings.Cut(field, "=")
		if _, err := url.QueryUnescape(name); err != nil {
			b.input["URLENCODED_ERROR"] = []string{"1"}
		}
		if _, err := url.QueryUnescape(value); err != nil {
			b.input["URLENCODED_ERROR"] = []string{"1"}
		}
		name = decodeSecURL(name, false)
		value = decodeSecURL(value, false)
		b.argument(source, name, value)
	}
	return b.err
}

// secRequestInput retains original request/body bytes alongside decoded values.
// Malformed or resource-limited parsing returns an error, never a clean result.
// Uploaded files stay in memory within the body budget; XML DTDs are rejected.
func secRequestInput(r *http.Request, body []byte) (map[string][]string, error) {
	return secRequestInputOptions(r, body, "", true)
}
func secRequestInputOptions(r *http.Request, body []byte, override string, bodyPhase bool) (map[string][]string, error) {
	if len(body) > 1<<20 || len(r.RequestURI) > 1<<20 {
		return nil, errors.New("request body or URI budget exceeded")
	}
	b := &secRequestBuilder{input: map[string][]string{}}
	identifier := make([]byte, 16)
	if _, err := rand.Read(identifier); err != nil {
		return nil, err
	}
	b.add("UNIQUE_ID", hex.EncodeToString(identifier))
	b.add("REQUEST_URI_RAW", r.RequestURI)
	b.add("REQUEST_URI", r.URL.RequestURI())
	b.add("REQUEST_FILENAME", r.URL.Path)
	path := r.URL.Path
	if last := strings.LastIndexByte(path, '/'); last >= 0 {
		path = path[last+1:]
	}
	b.add("REQUEST_BASENAME", path)
	b.add("REQUEST_METHOD", r.Method)
	b.add("REQUEST_PROTOCOL", r.Proto)
	b.add("REQUEST_LINE", r.Method+" "+r.RequestURI+" "+r.Proto)
	if bodyPhase {
		b.add("REQUEST_BODY", string(body))
		b.add("REQUEST_BODY_LENGTH", strconv.Itoa(len(body)))
	}
	b.add("QUERY_STRING", r.URL.RawQuery)
	address, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		address = r.RemoteAddr
	}
	b.add("REMOTE_ADDR", address)
	headers := r.Header.Clone()
	if r.Host != "" {
		headers.Set("Host", r.Host)
	}
	if len(r.TransferEncoding) > 0 && headers.Get("Transfer-Encoding") == "" {
		headers.Set("Transfer-Encoding", strings.Join(r.TransferEncoding, ", "))
	}
	names := make([]string, 0, len(headers))
	for name := range headers {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		for _, value := range headers[name] {
			b.add("REQUEST_HEADERS:"+name, value)
			b.add("REQUEST_HEADERS_NAMES", name)
		}
	}
	for _, line := range r.Header.Values("Cookie") {
		for _, cookie := range strings.Split(line, ";") {
			cookie = strings.TrimLeft(cookie, " \t")
			if cookie == "" {
				continue
			}
			name, value, _ := strings.Cut(cookie, "=")
			if strings.HasSuffix(name, " ") {
				return nil, errors.New("malformed cookie")
			}
			for _, character := range name {
				if character != ' ' && unicode.IsSpace(character) || unicode.IsControl(character) {
					return nil, errors.New("malformed cookie")
				}
			}
			for index := 0; index < len(value); index++ {
				if value[index] < 32 || value[index] == 127 {
					return nil, errors.New("malformed cookie")
				}
			}
			// CRS uses Netscape/v0 fields: semicolons delimit entries and quotes
			// remain evidence. Keep empty-name values instead of hiding payloads.
			// Internal ASCII spaces stay in names; never normalize attack bytes.
			b.add("REQUEST_COOKIES:"+name, value)
			b.add("REQUEST_COOKIES_NAMES", name)
		}
	}
	if err := b.encodedArguments("ARGS_GET", r.URL.RawQuery); err != nil {
		return nil, err
	}
	contentType := r.Header.Get("Content-Type")
	mediaType, params, err := mime.ParseMediaType(contentType)
	if err != nil && contentType != "" {
		// Keep the original header available to protocol rules. Guessing a
		// structured parser from an invalid media type can hide raw payloads.
		mediaType, params = "", nil
		if bodyPhase {
			b.add("REQBODY_ERROR", "1")
			b.add("REQBODY_PROCESSOR_ERROR", "1")
			b.add("REQBODY_ERROR_MSG", "malformed content type; raw inspection only")
			b.add("REQBODY_PROCESSOR_ERROR_MSG", "malformed content type; raw inspection only")
		}
	}
	if override != "" {
		switch override {
		case "URLENCODED":
			mediaType = "application/x-www-form-urlencoded"
		case "JSON":
			mediaType = "application/json"
		case "XML":
			mediaType = "application/xml"
		case "MULTIPART":
			mediaType = "multipart/form-data"
		default:
			return nil, errors.New("unsupported body processor")
		}
	}
	processor := ""
	switch {
	case mediaType == "application/x-www-form-urlencoded":
		processor = "URLENCODED"
	case mediaType == "application/json" || strings.HasSuffix(mediaType, "+json"):
		processor = "JSON"
	case mediaType == "multipart/form-data":
		processor = "MULTIPART"
	case mediaType == "application/xml" || mediaType == "text/xml" || strings.HasSuffix(mediaType, "+xml"):
		processor = "XML"
	}
	// A known-empty processor is a scalar value, not an absent collection.
	// CRS uses a negated match on it to enable unknown-content raw inspection.
	b.add("REQBODY_PROCESSOR", processor)
	if bodyPhase && len(body) > 0 {
		switch {
		case mediaType == "application/x-www-form-urlencoded":
			if err := b.encodedArguments("ARGS_POST", string(body)); err != nil {
				return nil, err
			}
		case mediaType == "application/json" || strings.HasSuffix(mediaType, "+json"):
			decoder := json.NewDecoder(bytes.NewReader(body))
			decoder.UseNumber()
			if err := b.jsonValue(decoder, "json", 0); err != nil {
				return nil, err
			}
			if _, err := decoder.Token(); err != io.EOF {
				return nil, errors.New("trailing JSON content")
			}
		case mediaType == "multipart/form-data":
			if err := b.multipartBody(body, params["boundary"]); err != nil {
				return nil, err
			}
		case mediaType == "application/xml" || mediaType == "text/xml" || strings.HasSuffix(mediaType, "+xml"):
			if err := b.xmlBody(body); err != nil {
				return nil, err
			}
		}
	}
	b.add("ARGS_COMBINED_SIZE", strconv.Itoa(b.argumentSize))
	if b.err != nil {
		return nil, b.err
	}
	return b.input, nil
}
func (b *secRequestBuilder) jsonValue(decoder *json.Decoder, name string, depth int) error {
	if depth > 64 {
		return errors.New("JSON nesting budget exceeded")
	}
	token, err := decoder.Token()
	if err != nil {
		return errors.New("malformed JSON body")
	}
	switch value := token.(type) {
	case json.Delim:
		switch value {
		case '{':
			for decoder.More() {
				key, err := decoder.Token()
				if err != nil {
					return err
				}
				field, ok := key.(string)
				if !ok {
					return errors.New("invalid JSON key")
				}
				if err := b.jsonValue(decoder, name+"."+field, depth+1); err != nil {
					return err
				}
			}
		case '[':
			for index := 0; decoder.More(); index++ {
				if err := b.jsonValue(decoder, name+"."+strconv.Itoa(index), depth+1); err != nil {
					return err
				}
			}
		default:
			return errors.New("unexpected JSON delimiter")
		}
		if _, err := decoder.Token(); err != nil {
			return errors.New("incomplete JSON body")
		}
	case string:
		b.argument("ARGS_POST", name, value)
	case json.Number:
		b.argument("ARGS_POST", name, string(value))
	case bool:
		b.argument("ARGS_POST", name, strconv.FormatBool(value))
	case nil:
		b.argument("ARGS_POST", name, "")
	default:
		return errors.New("unsupported JSON value")
	}
	return b.err
}

var errSecMultipartHeader = errors.New("Multipart parsing error: Multipart: Invalid part header (contains invalid character)")

func secMultipartHasInvalidHeader(err error) bool {
	var protocol textproto.ProtocolError
	if !errors.As(err, &protocol) {
		return false
	}
	message := string(protocol)
	if !strings.HasPrefix(message, "malformed MIME header") {
		return false
	}
	_, quoted, found := strings.Cut(message, ": ")
	if !found {
		return false
	}
	line, e := strconv.Unquote(quoted)
	if e != nil {
		return false
	}
	for _, b := range []byte(line) {
		if b < 32 && b != '\t' || b >= 127 {
			return true
		}
	}
	return false
}
func (b *secRequestBuilder) multipartBody(body []byte, boundary string) error {
	if boundary == "" || len(boundary) > 200 {
		return errors.New("multipart boundary missing or oversized")
	}
	reader := multipart.NewReader(bytes.NewReader(body), boundary)
	fileSize := 0
	for count := 0; ; count++ {
		part, err := reader.NextRawPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			if secMultipartHasInvalidHeader(err) {
				return errSecMultipartHeader
			}
			return errors.New("malformed multipart body")
		}
		if count >= 1000 {
			return errors.New("multipart part budget exceeded")
		}
		_, parameters, err := mime.ParseMediaType(part.Header.Get("Content-Disposition"))
		if err != nil || parameters["name"] == "" {
			return errors.New("multipart disposition/name invalid")
		}
		name := parameters["name"]
		content, err := io.ReadAll(io.LimitReader(part, 1<<20+1))
		part.Close()
		if err != nil || len(content) > 1<<20 {
			return errors.New("multipart content budget exceeded")
		}
		if filename, present := parameters["filename"]; present {
			b.add("FILES:"+name, filename)
			b.add("FILES_NAMES", name)
			fileSize += len(content)
		} else {
			b.argument("ARGS_POST", name, string(content))
		}
		for key, values := range part.Header {
			for _, value := range values {
				b.add("MULTIPART_PART_HEADERS:"+name, key+": "+value)
			}
		}
		if b.err != nil {
			return b.err
		}
	}
	b.add("FILES_COMBINED_SIZE", strconv.Itoa(fileSize))
	return b.err
}
func (b *secRequestBuilder) xmlBody(body []byte) error {
	decoder := xml.NewDecoder(bytes.NewReader(body))
	depth, roots := 0, 0
	var content strings.Builder
	for {
		token, err := decoder.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return errors.New("malformed XML body")
		}
		switch value := token.(type) {
		case xml.Directive:
			return errors.New("XML directives and DTDs are not permitted")
		case xml.StartElement:
			if depth == 0 {
				roots++
			}
			depth++
			if depth > 64 || roots > 1 {
				return errors.New("XML depth or root budget exceeded")
			}
			for _, attribute := range value.Attr {
				if attribute.Name.Space == "xmlns" || attribute.Name.Space == "" && attribute.Name.Local == "xmlns" {
					continue
				}
				b.add("XML://@*", attribute.Value)
			}
		case xml.EndElement:
			depth--
		case xml.CharData:
			if depth == 0 && strings.TrimSpace(string(value)) != "" {
				return errors.New("XML text outside root")
			}
			if depth > 0 && len(value) > 0 {
				content.Write(value)
			}
		}
		if b.err != nil {
			return b.err
		}
	}
	if roots != 1 || depth != 0 {
		return errors.New("incomplete XML document")
	}
	b.add("XML:/*", content.String())
	return b.err
}
