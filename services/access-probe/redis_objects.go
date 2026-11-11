package main

import "strings"

// Key positions are explicit; values and credentials must never become object names.
func redisObjects(e *Exchange, request respValue, database string) {
	stride, all := 1, false
	switch e.Operation {
	case "MGET", "DEL", "UNLINK", "EXISTS", "TOUCH":
		all = true
	case "MSET", "MSETNX":
		all = true
		stride = 2
	case "GET", "SET", "HGET", "HSET", "HGETALL", "LPUSH", "RPUSH", "LRANGE", "SADD", "SMEMBERS", "ZADD", "ZRANGE", "EXPIRE", "TTL":
	default:
		return
	}
	if all && request.argumentsTruncated {
		e.gap("RESOURCE_LIMIT")
	}
	seen := map[string]bool{}
	for i := 1; i < len(request.arguments); i += stride {
		if !all && i > 1 {
			break
		}
		key := request.arguments[i]
		colon := strings.IndexByte(key, ':')
		if colon >= 120 || (colon < 0 && i < len(request.argumentShortened) && request.argumentShortened[i]) {
			e.gap("RESOURCE_LIMIT")
			continue
		}
		if colon <= 0 {
			continue
		}
		namespace := key[:colon] + ":*"
		if seen[namespace] {
			continue
		}
		seen[namespace] = true
		if len(e.Objects) >= 32 {
			e.gap("RESOURCE_LIMIT")
			continue
		}
		e.Objects = append(e.Objects, Object{Database: database, Table: namespace, Columns: []string{}})
	}
}

// HELLO options consume their values; a client name may itself be AUTH.
func redisHelloAccount(request respValue) (string, bool, bool) {
	if request.argumentsTruncated {
		return "", false, false
	}
	account := ""
	auth := false
	for i := 2; i < len(request.arguments); {
		switch strings.ToUpper(request.arguments[i]) {
		case "AUTH":
			if i+2 >= len(request.arguments) || i+1 < len(request.argumentShortened) && request.argumentShortened[i+1] {
				return "", false, false
			}
			account = request.arguments[i+1]
			auth = true
			i += 3
		case "SETNAME":
			if i+1 >= len(request.arguments) {
				return "", false, false
			}
			i += 2
		default:
			return "", false, false
		}
	}
	return account, auth, true
}
