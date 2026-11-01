package main

import (
	"strconv"
	"strings"
)

func secHexByte(value string) (byte, bool) {
	n, err := strconv.ParseUint(value, 16, 32)
	return byte(n), err == nil
}
func secBackslashDecode(value string, javascript bool) string {
	var output strings.Builder
	for i := 0; i < len(value); {
		if value[i] != '\\' || i+1 == len(value) {
			output.WriteByte(value[i])
			i++
			continue
		}
		next := value[i+1]
		if javascript && next == 'u' && i+6 <= len(value) {
			if number, err := strconv.ParseUint(value[i+2:i+6], 16, 16); err == nil {
				if number >= 0xff01 && number <= 0xff5e {
					number -= 0xfee0
				}
				output.WriteByte(byte(number))
				i += 6
				continue
			}
		}
		if (next == 'x' || !javascript && next == 'X') && i+4 <= len(value) {
			if decoded, ok := secHexByte(value[i+2 : i+4]); ok {
				output.WriteByte(decoded)
				i += 4
				continue
			}
		}
		if next >= '0' && next <= '7' {
			end := i + 1
			maximum := 3
			if javascript && next > '3' {
				maximum = 2
			}
			for end < len(value) && end < i+1+maximum && value[end] >= '0' && value[end] <= '7' {
				end++
			}
			number, _ := strconv.ParseUint(value[i+1:end], 8, 16)
			output.WriteByte(byte(number))
			i = end
			continue
		}
		switch next {
		case 'a':
			next = '\a'
		case 'b':
			next = '\b'
		case 'f':
			next = '\f'
		case 'n':
			next = '\n'
		case 'r':
			next = '\r'
		case 't':
			next = '\t'
		case 'v':
			next = '\v'
		}
		output.WriteByte(next)
		i += 2
	}
	return output.String()
}
func secCSSDecode(value string) string {
	var output strings.Builder
	for i := 0; i < len(value); {
		if value[i] != '\\' {
			output.WriteByte(value[i])
			i++
			continue
		}
		i++
		if i == len(value) {
			break
		}
		end := i
		for end < len(value) && end < i+6 {
			c := value[end]
			if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F') {
				break
			}
			end++
		}
		if end > i {
			number, _ := strconv.ParseUint(value[i:end], 16, 32)
			if number >= 0xff01 && number <= 0xff5e {
				number -= 0xfee0
			}
			output.WriteByte(byte(number))
			i = end
			if i < len(value) && (value[i] == ' ' || value[i] >= '\t' && value[i] <= '\r') {
				i++
			}
		} else if value[i] == '\n' {
			i++
		} else {
			output.WriteByte(value[i])
			i++
		}
	}
	return output.String()
}
