package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode/utf16"
)

var errSkipped = errors.New("unsupported event")

type Event struct {
	EventID         string         `json:"eventId"`
	SourceSHA256    string         `json:"sourceSha256"`
	OccurredAt      string         `json:"occurredAt"`
	EventType       string         `json:"eventType"`
	FlowID          string         `json:"flowId,omitempty"`
	SourceIP        string         `json:"sourceIp,omitempty"`
	DestinationIP   string         `json:"destinationIp,omitempty"`
	SourcePort      *int           `json:"sourcePort,omitempty"`
	DestinationPort *int           `json:"destinationPort,omitempty"`
	Protocol        string         `json:"protocol,omitempty"`
	AppProtocol     string         `json:"appProtocol,omitempty"`
	Metadata        map[string]any `json:"metadata"`
}

func digest(b []byte) string   { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }
func obj(v any) map[string]any { m, _ := v.(map[string]any); return m }
func str(v any, n int) string {
	s, _ := v.(string)
	s = strings.Map(func(r rune) rune {
		if r < 32 || r == 127 {
			return -1
		}
		return r
	}, s)
	units := 0
	for i, r := range s {
		units += utf16.RuneLen(r)
		if units > n {
			s = s[:i]
			break
		}
	}
	return s
}
func numeric(v any, max uint64) (uint64, bool) {
	n, ok := v.(json.Number)
	if !ok {
		return 0, false
	}
	i, e := strconv.ParseUint(string(n), 10, 64)
	return i, e == nil && i <= max
}
func copyStr(out map[string]any, key string, in map[string]any, from string, n int) {
	if s := str(in[from], n); s != "" {
		out[key] = s
	}
}
func copyCounter(out map[string]any, key string, in map[string]any, from string) {
	if i, ok := numeric(in[from], ^uint64(0)); ok {
		out[key] = strconv.FormatUint(i, 10)
	}
}
func copyCount(out map[string]any, key string, in map[string]any, from string) {
	if i, ok := numeric(in[from], 9007199254740991); ok {
		out[key] = int64(i)
	}
}
func normalize(raw []byte, generation string, offset int64) (Event, error) {
	var root map[string]any
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	if e := d.Decode(&root); e != nil {
		return Event{}, errors.New("invalid EVE")
	}
	if d.Decode(new(any)) != io.EOF {
		return Event{}, errors.New("invalid trailing EVE")
	}
	typ := str(root["event_type"], 20)
	switch typ {
	case "alert", "http", "dns", "tls", "flow", "anomaly", "stats":
	default:
		return Event{}, errSkipped
	}
	ts := str(root["timestamp"], 64)
	var timestamp time.Time
	var err error
	for _, layout := range []string{time.RFC3339Nano, "2006-01-02T15:04:05.999999999-0700"} {
		timestamp, err = time.Parse(layout, ts)
		if err == nil {
			break
		}
	}
	if err != nil {
		return Event{}, errors.New("invalid timestamp")
	}
	if year := timestamp.UTC().Year(); year < 0 || year > 9999 {
		return Event{}, errors.New("timestamp outside wire range")
	}
	source := digest(raw)
	e := Event{EventID: digest([]byte(fmt.Sprintf("%s:%d:%s", generation, offset, source))), SourceSHA256: source, OccurredAt: timestamp.UTC().Format(time.RFC3339Nano), EventType: typ, Metadata: map[string]any{}}
	if n, ok := numeric(root["flow_id"], ^uint64(0)); ok {
		e.FlowID = strconv.FormatUint(n, 10)
	}
	for _, f := range []struct {
		key string
		dst *string
	}{{"src_ip", &e.SourceIP}, {"dest_ip", &e.DestinationIP}} {
		s := str(root[f.key], 45)
		if net.ParseIP(s) != nil {
			*f.dst = s
		}
	}
	for _, f := range []struct {
		key string
		dst **int
	}{{"src_port", &e.SourcePort}, {"dest_port", &e.DestinationPort}} {
		if n, ok := numeric(root[f.key], 65535); ok {
			v := int(n)
			*f.dst = &v
		}
	}
	e.Protocol = str(root["proto"], 16)
	e.AppProtocol = str(root["app_proto"], 48)
	in := obj(root[typ])
	out := map[string]any{}
	e.Metadata[typ] = out
	switch typ {
	case "alert":
		for _, f := range []struct {
			to, from string
			max      uint64
		}{{"signatureId", "signature_id", 4294967295}, {"gid", "gid", 4294967295}, {"rev", "rev", 4294967295}, {"severity", "severity", 255}} {
			n, ok := numeric(in[f.from], f.max)
			if !ok {
				return Event{}, errors.New("invalid alert")
			}
			out[f.to] = n
		}
		out["signature"] = str(in["signature"], 500)
		copyStr(out, "category", in, "category", 200)
		a := str(in["action"], 16)
		switch a {
		case "allowed", "blocked", "rejected":
		default:
			a = "unknown"
		}
		out["action"] = a
	case "http":
		copyStr(out, "hostname", in, "hostname", 253)
		copyStr(out, "method", in, "http_method", 32)
		if rawURL, ok := in["url"].(string); ok {
			if u, err := url.Parse(rawURL); err == nil {
				p := u.EscapedPath()
				if p == "" {
					p = "/"
				}
				if !strings.ContainsAny(p, "?#") {
					out["path"] = str(p, 1024)
				}
			}
		}
		if n, ok := numeric(in["status"], 599); ok && n >= 100 {
			out["status"] = n
		}
	case "dns":
		names := []string{}
		add := func(v any) {
			if s := str(v, 253); s != "" && len(names) < 16 {
				names = append(names, s)
			}
		}
		add(in["rrname"])
		if q, ok := in["queries"].([]any); ok {
			for _, v := range q {
				add(obj(v)["rrname"])
			}
		}
		out["names"] = names
		copyStr(out, "rrtype", in, "rrtype", 32)
		copyStr(out, "rcode", in, "rcode", 32)
	case "tls":
		for _, f := range []struct {
			key string
			n   int
		}{{"sni", 253}, {"version", 32}, {"subject", 512}, {"issuerdn", 512}, {"fingerprint", 128}} {
			to := f.key
			if to == "issuerdn" {
				to = "issuer"
			}
			copyStr(out, to, in, f.key, f.n)
		}
	case "flow":
		for _, f := range [][2]string{{"pktsToServer", "pkts_toserver"}, {"pktsToClient", "pkts_toclient"}, {"bytesToServer", "bytes_toserver"}, {"bytesToClient", "bytes_toclient"}} {
			copyCounter(out, f[0], in, f[1])
		}
		copyStr(out, "state", in, "state", 48)
		copyStr(out, "reason", in, "reason", 80)
		if v, ok := in["alerted"].(bool); ok {
			out["alerted"] = v
		}
	case "anomaly":
		copyStr(out, "type", in, "type", 80)
		copyStr(out, "event", in, "event", 200)
	case "stats":
		copyCount(out, "uptime", in, "uptime")
		for _, f := range []struct{ to, section, from string }{{"kernelPackets", "capture", "kernel_packets"}, {"kernelDrops", "capture", "kernel_drops"}, {"decoderPackets", "decoder", "pkts"}, {"decoderBytes", "decoder", "bytes"}, {"alertsSuppressed", "detect", "alerts_suppressed"}, {"alertQueueOverflow", "detect", "alert_queue_overflow"}} {
			copyCounter(out, f.to, obj(in[f.section]), f.from)
		}
		detect := obj(in["detect"])
		engines, _ := detect["engines"].([]any)
		for _, f := range [][2]string{{"rulesLoaded", "rules_loaded"}, {"rulesFailed", "rules_failed"}, {"rulesSkipped", "rules_skipped"}} {
			if len(engines) == 0 {
				copyCount(out, f[0], detect, f[1])
			} else {
				var sum uint64
				found := false
				for _, v := range engines {
					if n, ok := numeric(obj(v)[f[1]], 9007199254740991); ok {
						if n > 9007199254740991-sum {
							sum = 9007199254740992
							break
						}
						sum += n
						found = true
					}
				}
				if found && sum <= 9007199254740991 {
					out[f[0]] = int64(sum)
				}
			}
		}
	}
	return e, nil
}
