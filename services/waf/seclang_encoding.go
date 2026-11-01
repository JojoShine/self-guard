package main

import (
	"encoding/base64"
	"fmt"
	"strings"
	"unicode/utf8"
)

func secUTF8Unicode(value string) (string, error) {
	ascii := true
	for index := 0; index < len(value); index++ {
		if value[index] >= utf8.RuneSelf {
			ascii = false
			break
		}
	}
	if ascii {
		return value, nil
	}
	var output strings.Builder
	for offset := 0; offset < len(value); {
		code, size := utf8.DecodeRuneInString(value[offset:])
		if code == utf8.RuneError && size == 1 {
			// Preserve malformed bytes for explicit UTF-8 validation and byte
			// operators. Replacing or dropping them can hide the original input.
			output.WriteByte(value[offset])
			offset++
			continue
		}
		offset += size
		if code < 128 {
			output.WriteByte(byte(code))
		} else {
			fmt.Fprintf(&output, "%%u%04x", code)
		}
	}
	return output.String(), nil
}
func secBase64Decode(value string) string {
	// Only end-of-line/trailing spaces are allowed. Invalid data retains its
	// original bytes, rather than erasing an attack prefix with partial decoding.
	lines := strings.Split(value, "\n")
	for i, line := range lines {
		cr := ""
		if strings.HasSuffix(line, "\r") {
			cr = "\r"
			line = strings.TrimSuffix(line, "\r")
		}
		lines[i] = strings.TrimRight(line, " ") + cr
	}
	normalized := strings.Join(lines, "\n")
	decoded, err := base64.StdEncoding.DecodeString(normalized)
	if err != nil {
		return value
	}
	return string(decoded)
}
