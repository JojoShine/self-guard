package main

import (
	"strconv"
	"strings"
)

// encoding/csv removes the CR in every CRLF, including inside quoted SQL.
// Doubling only quoted CRs lets its normal decoder preserve the original bytes.
func postgresSQLCSV(line string) string {
 var b strings.Builder
 quoted:=false
 for i:=0;i<len(line);i++ {
  if line[i]=='"' {quoted=!quoted}
  if quoted&&line[i]=='\r'&&i+1<len(line)&&line[i+1]=='\n' {b.WriteByte('\r')}
  b.WriteByte(line[i])
 }
 return b.String()
}

// Only core Execute/completion records prove execution; an application can RAISE LOG arbitrary text.
func postgresSQL(value map[string]any, fields []string) (map[string]any, bool, bool) {
	message, location := fields[13], fields[21]
	execution := map[string]any{"sqlState": fields[12]}
	sql := ""
	if fields[11] == "LOG" && (strings.HasPrefix(location, "exec_simple_query, postgres.c:") || strings.HasPrefix(location, "exec_execute_message, postgres.c:")) {
		// Dot does not match physical newlines. Match the fixed header independently of SQL.
		head, tail, found := strings.Cut(message, " ms  ")
		if !found {
			return nil, true, true
		}
		duration, err := strconv.ParseFloat(strings.TrimPrefix(head, "duration: "), 64)
		if err != nil || !strings.HasPrefix(head, "duration: ") || duration < 0 {
			return nil, false, false
		}
		if strings.HasPrefix(tail, "statement: ") {
			sql = strings.TrimPrefix(tail, "statement: ")
			execution["protocol"] = "SIMPLE"
		} else if strings.HasPrefix(tail, "execute ") {
			// A named portal may contain ': '. Retain that label verbatim rather than guessing its boundary.
			if strings.HasPrefix(tail, "execute <unnamed>: ") {
				sql = strings.TrimPrefix(tail, "execute <unnamed>: ")
			} else {
				sql = tail
				execution["portalLabelIncluded"] = true
			}
			execution["protocol"] = "EXTENDED"
		} else {
			return nil, true, true
		}
		execution["durationMs"] = duration
		value["succeeded"] = true
	} else if databaseIncludes([]string{"ERROR", "FATAL", "PANIC"}, fields[11]) && fields[19] != "" {
		sql = fields[19]
		execution["protocol"] = "ERROR"
		value["succeeded"] = false
	} else {
		return nil, true, true
	}
	if sql == "" || len(sql) > 32768 || fields[1] == "" || fields[5] == "" || fields[6] == "" {
		return nil, false, false
	}
	execution["sql"] = sql
	value["execution"] = execution
	value["operation"] = databaseCommand(fields[7])
	return value, true, false
}
