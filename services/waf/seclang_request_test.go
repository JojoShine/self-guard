package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"mime/multipart"
	"net/http/httptest"
	"net/textproto"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

func TestSecLangCLIReplaysRawHTTPRequestThroughOwnParser(t *testing.T) {
	body := `{"field":"safe","field":"attack"}`
	request := "POST / HTTP/1.1\r\nHost: fixture.test\r\nContent-Type: application/json\r\nContent-Length: " + strconv.Itoa(len(body)) + "\r\n\r\n" + body
	fixture := map[string]any{"files": []secLangFile{{Name: "fixture.conf", Source: `SecRule ARGS "@contains attack" "id:2501,phase:2,deny"`}}, "requestBase64": base64.StdEncoding.EncodeToString([]byte(request))}
	raw, _ := json.Marshal(fixture)
	var output bytes.Buffer
	if err := runSecLangCLI(bytes.NewReader(raw), &output, true); err != nil {
		t.Fatal(err)
	}
	var result secResult
	if err := json.Unmarshal(output.Bytes(), &result); err != nil || !result.Blocked {
		t.Fatalf("%+v %v", result, err)
	}
}

func TestSecRequestInputPreservesRepeatedQueryFormAndHeaderValues(t *testing.T) {
	r := httptest.NewRequest("POST", "https://example.test/a%2fb?q=one&q=two", strings.NewReader("q=three&name=a%2Bb"))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Add("X-Sample", "one")
	r.Header.Add("X-Sample", "two")
	input, err := secRequestInput(r, []byte("q=three&name=a%2Bb"))
	if err != nil {
		t.Fatal(err)
	}
	for key, want := range map[string][]string{"ARGS:q": {"one", "two", "three"}, "ARGS_GET:q": {"one", "two"}, "ARGS_POST:name": {"a+b"}, "REQUEST_HEADERS:X-Sample": {"one", "two"}, "REQUEST_FILENAME": {"/a/b"}, "REQUEST_URI_RAW": {"https://example.test/a%2fb?q=one&q=two"}} {
		if !reflect.DeepEqual(input[key], want) {
			t.Fatalf("%s: %q want %q", key, input[key], want)
		}
	}
}
func TestSecRequestJSONPreservesDuplicateKeysAndRejectsIncompleteBodies(t *testing.T) {
	r := httptest.NewRequest("POST", "https://example.test/", nil)
	r.Header.Set("Content-Type", "application/json")
	input, err := secRequestInput(r, []byte(`{"name":"safe","name":"attack","nested":{"id":123},"items":["a","b"]}`))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(input["ARGS:json.name"], []string{"safe", "attack"}) || !reflect.DeepEqual(input["ARGS:json.nested.id"], []string{"123"}) {
		t.Fatal(input)
	}
	for _, body := range []string{`{"x":`, `{"x":1}{"y":2}`, strings.Repeat("[", 70) + strings.Repeat("]", 70)} {
		if _, err := secRequestInput(r, []byte(body)); err == nil {
			t.Fatal("malformed or unbounded JSON accepted")
		}
	}
}
func TestSecRequestMultipartKeepsOriginalFilenameAndDoesNotWriteUploadedFiles(t *testing.T) {
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	part, err := writer.CreatePart(textproto.MIMEHeader{"Content-Disposition": {`form-data; name="upload"; filename="../../secret.txt"`}, "Content-Type": {"application/octet-stream"}})
	if err != nil {
		t.Fatal(err)
	}
	part.Write([]byte("file content"))
	writer.WriteField("note", "ordinary text")
	writer.Close()
	r := httptest.NewRequest("POST", "https://example.test/upload", nil)
	r.Header.Set("Content-Type", writer.FormDataContentType())
	input, err := secRequestInput(r, body.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(input["FILES:upload"], []string{"../../secret.txt"}) || !reflect.DeepEqual(input["FILES_NAMES"], []string{"upload"}) || !reflect.DeepEqual(input["ARGS:note"], []string{"ordinary text"}) || len(input["ARGS:upload"]) != 0 {
		t.Fatal(input)
	}
}
func TestSecRequestXMLRejectsDTDAndExternalEntities(t *testing.T) {
	r := httptest.NewRequest("POST", "https://example.test/", nil)
	r.Header.Set("Content-Type", "application/xml")
	input, err := secRequestInput(r, []byte(`<root attr="value"><item>attack</item></root>`))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(input["XML:/*"], []string{"attack"}) || !reflect.DeepEqual(input["XML://@*"], []string{"value"}) {
		t.Fatal(input)
	}
	if _, err := secRequestInput(r, []byte(`<!DOCTYPE root [<!ENTITY x SYSTEM "file:///etc/passwd">]><root>&x;</root>`)); err == nil {
		t.Fatal("DTD accepted")
	}
	if _, err := secRequestInput(r, bytes.Repeat([]byte("a"), 1<<20+1)); err == nil {
		t.Fatal("oversized body accepted")
	}
}

func TestSecRequestXMLRootContentJoinsDescendantsAndEntityChunks(t *testing.T) {
	r := httptest.NewRequest("POST", "https://example.test/", nil)
	r.Header.Set("Content-Type", "application/xml")
	input, err := secRequestInput(r, []byte(`<root xmlns="urn:normal" xmlns:x="urn:other" x:flag="attack"><item>sel</item>e<![CDATA[c]]>t</root>`))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(input["XML:/*"], []string{"select"}) || !reflect.DeepEqual(input["XML://@*"], []string{"attack"}) {
		t.Fatalf("XPath root/attribute content differs: %v", input)
	}
	for _, target := range []string{"XML:/*", "XML://@*"} {
		rules, err := parseSecLang("xml.conf", `SecRule `+target+` "@contains `+map[string]string{"XML:/*": "select", "XML://@*": "attack"}[target]+`" "id:2750,phase:2,deny"`)
		if err != nil {
			t.Fatal(err)
		}
		got, err := evaluateSecLang(rules, input, 5)
		if err != nil || !got.Blocked {
			t.Fatalf("%s: %+v %v", target, got, err)
		}
	}
	rules, err := parseSecLang("xpath.conf", `SecRule XML:/root/item "@contains attack" "id:2751,phase:2,deny"`)
	if err != nil {
		t.Fatal(err)
	}
	if secLangCompatibility(rules).Publishable {
		t.Fatal("arbitrary unsupported XPath accepted")
	}
}

func TestSecRequestMalformedPercentSequencesRemainInspectibleAndIncomplete(t *testing.T) {
	r := httptest.NewRequest("POST", "http://example.test/?a=%41%zz", nil)
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	input, err := secRequestInput(r, []byte("q=%53LEEP(1)%SystemDrive%&name%zz=value"))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(input["ARGS:a"], []string{"A%zz"}) || !reflect.DeepEqual(input["ARGS:q"], []string{"SLEEP(1)%SystemDrive%"}) || !reflect.DeepEqual(input["URLENCODED_ERROR"], []string{"1"}) {
		t.Fatalf("lost undecodable evidence: %v", input)
	}
	rules, err := parseSecLang("encoding.conf", `SecRule ARGS "@contains never" "id:2752,phase:2,deny"`)
	if err != nil {
		t.Fatal(err)
	}
	result, err := evaluateSecLang(rules, input, 5)
	if err != nil || result.Blocked || len(result.Incomplete) == 0 {
		t.Fatalf("malformed data reported clean: %+v %v", result, err)
	}
}
